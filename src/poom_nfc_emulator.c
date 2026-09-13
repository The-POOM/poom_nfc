// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 THE POOM

#include "poom_nfc_emulator.h"

#include <stdio.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_heap_caps.h"

#include "poom_nfc_ats.h"
#include "poom_nfc_core.h"
#include "poom_nfc_emulator_mful.h"
#include "poom_nfc_emulator_t4t.h"
#include "poom_secrets_store.h"

#include "rfal_isoDep.h"
#include "rfal_nfca.h"
#include "rfal_rf.h"
#include "rfal_utils.h"

#ifndef ERR_NONE
#define ERR_NONE (0U)
#endif
#ifndef ERR_BUSY
#define ERR_BUSY (2U)
#endif
#ifndef ERR_TIMEOUT
#define ERR_TIMEOUT (4U)
#endif
#ifndef ERR_LINK_LOSS
#define ERR_LINK_LOSS (37U)
#endif
#ifndef ERR_SLEEP_REQ
#define ERR_SLEEP_REQ (32U)
#endif

#define POOM_NFC_EMU_DEFAULT_URI "https://poom.stellar-iot.com/"
#define POOM_NFC_EMU_KEY_URI "nfc_emul_uri"

enum
{
    POOM_NFC_EMU_TASK_STACK = 6144,
    POOM_NFC_EMU_TASK_PRIO = 18,
    POOM_NFC_EMU_LOOP_DELAY_MS = 1,
    POOM_NFC_EMU_RX_BUF_LEN = 300,
    POOM_NFC_EMU_TX_BUF_LEN = 300,
    POOM_NFC_EMU_UID_LEN_4 = 4,
    POOM_NFC_EMU_UID_LEN_7 = 7,
    POOM_NFC_EMU_UID_LEN_10 = 10,
    POOM_NFC_EMU_UID_DEF_LEN = 7,
    POOM_NFC_EMU_ATQA_4B_UID = 0x04,
    POOM_NFC_EMU_ATQA_7B_UID = 0x44,
    POOM_NFC_EMU_ATQA_LSB_DEFAULT = 0x00,
    POOM_NFC_EMU_SAK_DEFAULT_T4T = 0x20,
    POOM_NFC_EMU_ATS_DEFAULT_FSCI = 0x08,
    POOM_NFC_EMU_ATS_DEFAULT_FWI = 0x0A,
    POOM_NFC_EMU_ATS_DEFAULT_SFGI = 0x00,
    POOM_NFC_EMU_STOP_WAIT_LOOPS = 300,
    POOM_NFC_EMU_STOP_WAIT_DELAY_MS = 10,
};

typedef struct
{
    TaskHandle_t task_h;
    volatile bool running;
    volatile bool stop_req;

    poom_nfc_emu_cfg_t cfg;

    rfalLmConfPA conf_a;
    rfalIsoDepAtsParam ats;
    uint8_t ats_hb[16];

    uint8_t* rx_buf;
    uint8_t* tx_buf;
    uint16_t rx_bits;

    rfalTransceiveContext l3_ctx;
    bool l3_rx_ready;
    bool l3_txrx_busy;
    bool l3_restart_after_tx;

    rfalIsoDepBufFormat* iso_rx;
    rfalIsoDepBufFormat* iso_tx;
    bool iso_rx_chaining;
    bool iso_activated;
    rfalIsoDepTxRxParam iso_param;

    poom_nfc_emu_t4t_t* t4t;
    poom_nfc_emu_mful_t* mful;
} poom_nfc_emu_ctx_t;

static poom_nfc_emu_ctx_t s_emu;

/**
 * @brief Releases all buffers allocated for the active emulation session.
 *
 * RX/TX share in internal DMA-capable RAM while large tag payloads live in
 * PSRAM. Both allocations exist only while emulation is active.
 */
static void poom_nfc_emu_free_runtime_buffers_(void)
{
    if(s_emu.rx_buf != NULL)
    {
        heap_caps_free(s_emu.rx_buf);
        s_emu.rx_buf = NULL;
        s_emu.tx_buf = NULL;
    }
    if(s_emu.t4t != NULL)
    {
        poom_nfc_emu_t4t_free(s_emu.t4t);
        s_emu.t4t = NULL;
    }
    if(s_emu.mful != NULL)
    {
        poom_nfc_emu_mful_free(s_emu.mful);
        s_emu.mful = NULL;
    }
}

/**
 * @brief Allocates transport and protocol buffers for an emulation session.
 *
 * RX and TX share one internal allocation. The selected protocol gets at most
 * one additional payload allocation in PSRAM.
 *
 * @return true when all allocations succeed, false otherwise.
 */
static bool poom_nfc_emu_alloc_runtime_buffers_(void)
{
    poom_nfc_emu_free_runtime_buffers_();

    s_emu.rx_buf = heap_caps_calloc(1U,
                                    POOM_NFC_EMU_RX_BUF_LEN + POOM_NFC_EMU_TX_BUF_LEN,
                                    MALLOC_CAP_INTERNAL | MALLOC_CAP_DMA | MALLOC_CAP_8BIT);
    if(s_emu.rx_buf == NULL)
    {
        printf("  nfc-emul: failed to allocate RFAL buffers in internal RAM\r\n");
        return false;
    }
    s_emu.tx_buf = &s_emu.rx_buf[POOM_NFC_EMU_RX_BUF_LEN];

    if(s_emu.cfg.mode == POOM_NFC_EMU_MODE_T4T)
    {
        s_emu.t4t = poom_nfc_emu_t4t_alloc(
            s_emu.cfg.uri_set ? s_emu.cfg.uri : POOM_NFC_EMU_DEFAULT_URI);
        if(s_emu.t4t == NULL)
        {
            printf("  nfc-emul: failed to allocate Type 4 payload in PSRAM\r\n");
            poom_nfc_emu_free_runtime_buffers_();
            return false;
        }
        return true;
    }
    else if(s_emu.cfg.mode == POOM_NFC_EMU_MODE_MFUL)
    {
        s_emu.mful = poom_nfc_emu_mful_alloc(
            s_emu.cfg.image_path_set ? s_emu.cfg.image_path : NULL, &s_emu.cfg);
        if(s_emu.mful == NULL)
        {
            printf("  nfc-emul: failed to load MIFARE Ultralight image\r\n");
            poom_nfc_emu_free_runtime_buffers_();
            return false;
        }
        return true;
    }
    else
    {
        return true;
    }

    return true;
}

static const uint8_t s_uid_default[POOM_NFC_EMU_UID_DEF_LEN] = {
    0x02, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
};


/**
 * @brief Internal helper for `poom_nfc_emu_uid_enum_len`.
 *
 * @param[in] uid_len Parameter passed to the function.
 * @return uint8_t
 */
static uint8_t poom_nfc_emu_uid_enum_len(uint8_t uid_len)
{
    switch(uid_len)
    {
        case POOM_NFC_EMU_UID_LEN_4:
            return (uint8_t)RFAL_LM_NFCID_LEN_04;
        case POOM_NFC_EMU_UID_LEN_7:
            return (uint8_t)RFAL_LM_NFCID_LEN_07;
        case POOM_NFC_EMU_UID_LEN_10:
            return (uint8_t)RFAL_LM_NFCID_LEN_10;
        default:
            return 0;
    }
}

/**
 * @brief Internal helper for `poom_nfc_emu_rebuild_cc_file`.
 *
 * @return void
 */

/**
 * @brief Parses input data for this module.
 *
 * @param[in] ats Parameter passed to the function.
 * @param[in] ats_len Parameter passed to the function.
 * @param[in] out Parameter passed to the function.
 * @param[in] out_hb Parameter passed to the function.
 * @param[in] out_hb_max Parameter passed to the function.
 * @return bool
 */
static bool poom_nfc_emu_parse_ats(const uint8_t* ats,
                                   uint8_t ats_len,
                                   rfalIsoDepAtsParam* out,
                                   uint8_t* out_hb,
                                   uint8_t out_hb_max)
{
    poom_nfc_ats_info_t info;

    if(out == NULL || out_hb == NULL)
    {
        return false;
    }

    memset(out, 0, sizeof(*out));
    memset(out_hb, 0, out_hb_max);

    if(ats == NULL || ats_len == 0U)
    {
        out->fsci       = POOM_NFC_EMU_ATS_DEFAULT_FSCI;
        out->fwi        = POOM_NFC_EMU_ATS_DEFAULT_FWI;
        out->sfgi       = POOM_NFC_EMU_ATS_DEFAULT_SFGI;
        out->didSupport = false;
        out->ta         = 0x00;
        out_hb[0]       = 's';
        out_hb[1]       = 't';
        out->hb         = out_hb;
        out->hbLen      = 2;
        return true;
    }

    if(ats_len < 2U)
    {
        return false;
    }

    if(!poom_nfc_ats_parse(ats, ats_len, &info))
    {
        return false;
    }

    out->fsci       = info.fsci;
    out->fwi        = info.fwi;
    out->sfgi       = info.sfgi;
    out->didSupport = info.did_supported;
    out->ta         = info.ta_present ? info.ta : 0x00U;

    if(info.hb_len > out_hb_max)
    {
        info.hb_len = out_hb_max;
    }
    if(info.hb_len > 0U)
    {
        memcpy(out_hb, info.hb, info.hb_len);
    }

    out->hb    = out_hb;
    out->hbLen = info.hb_len;
    return true;
}

/**
 * @brief Internal helper for `poom_nfc_emu_config_to_listen_params`.
 *
 * @return bool
 */
static bool poom_nfc_emu_config_to_listen_params(void)
{
    uint8_t uid_enum_len;
    uint8_t atqa0;
    uint8_t atqa1;

    uid_enum_len = poom_nfc_emu_uid_enum_len(s_emu.cfg.uid_len);
    if(uid_enum_len == 0U)
    {
        printf("  nfc-emul: invalid UID length. Use %d or %d bytes.\r\n",
               POOM_NFC_EMU_UID_LEN_4, POOM_NFC_EMU_UID_LEN_7);
        return false;
    }

    if(!s_emu.cfg.sak_set)
    {
        printf("  nfc-emul: SAK not set.\r\n");
        return false;
    }

    atqa0 = s_emu.cfg.atqa_set ? s_emu.cfg.atqa[0]
                               : ((s_emu.cfg.uid_len == POOM_NFC_EMU_UID_LEN_7)
                                      ? POOM_NFC_EMU_ATQA_7B_UID
                                      : POOM_NFC_EMU_ATQA_4B_UID);
    atqa1 = s_emu.cfg.atqa_set ? s_emu.cfg.atqa[1] : POOM_NFC_EMU_ATQA_LSB_DEFAULT;

    memset(&s_emu.conf_a, 0, sizeof(s_emu.conf_a));
    s_emu.conf_a.nfcidLen = (rfalLmNfcidLen)uid_enum_len;
    memcpy(s_emu.conf_a.nfcid, s_emu.cfg.uid, s_emu.cfg.uid_len);
    s_emu.conf_a.SENS_RES[0] = atqa0;
    s_emu.conf_a.SENS_RES[1] = atqa1;
    s_emu.conf_a.SEL_RES     = s_emu.cfg.sak;

    if(!poom_nfc_emu_parse_ats(s_emu.cfg.ats, s_emu.cfg.ats_len, &s_emu.ats,
                               s_emu.ats_hb, sizeof(s_emu.ats_hb)))
    {
        printf("  nfc-emul: ATS invalid.\r\n");
        return false;
    }

    return true;
}

/**
 * @brief Internal helper for `poom_nfc_emu_reset_t4t_state`.
 *
 * @return void
 */
static void poom_nfc_emu_reset_t4t_state(void)
{
    poom_nfc_emu_t4t_reset(s_emu.t4t);
}

/**
 * @brief Internal helper for `poom_nfc_emu_put_sw`.
 *
 * @param[in] rsp Parameter passed to the function.
 * @param[in] rsp_max Parameter passed to the function.
 * @param[in] sw1 Parameter passed to the function.
 * @param[in] sw2 Parameter passed to the function.
 * @return uint16_t
 */

/**
 * @brief Starts the internal runtime for this module.
 *
 * @return bool
 */
static bool poom_nfc_emu_start_listen(void)
{
    ReturnCode rc;

    s_emu.rx_bits           = 0;
    s_emu.l3_rx_ready       = false;
    s_emu.l3_txrx_busy      = false;
    s_emu.l3_restart_after_tx = false;
    s_emu.iso_activated     = false;
    poom_nfc_emu_mful_reset(s_emu.mful);
    poom_nfc_emu_reset_t4t_state();

    memset(&s_emu.l3_ctx, 0, sizeof(s_emu.l3_ctx));
    s_emu.l3_ctx.txBuf     = s_emu.tx_buf;
    s_emu.l3_ctx.rxBuf     = s_emu.rx_buf;
    s_emu.l3_ctx.rxBufLen  = rfalConvBytesToBits(POOM_NFC_EMU_RX_BUF_LEN);
    s_emu.l3_ctx.rxRcvdLen = &s_emu.rx_bits;
    s_emu.l3_ctx.flags     = RFAL_TXRX_FLAGS_DEFAULT;
    s_emu.l3_ctx.fwt       = RFAL_FWT_NONE;

    s_emu.iso_rx = (rfalIsoDepBufFormat*)s_emu.rx_buf;
    s_emu.iso_tx = (rfalIsoDepBufFormat*)s_emu.tx_buf;
    memset(&s_emu.iso_param, 0, sizeof(s_emu.iso_param));
    s_emu.iso_param.rxBuf        = s_emu.iso_rx;
    s_emu.iso_param.rxLen        = &s_emu.rx_bits;
    s_emu.iso_param.txBuf        = s_emu.iso_tx;
    s_emu.iso_param.isRxChaining = &s_emu.iso_rx_chaining;
    s_emu.iso_param.isTxChaining = false;
    s_emu.iso_param.ourFSx       = RFAL_ISODEP_FSX_KEEP;
    s_emu.iso_param.FSx          = rfalIsoDepFSxI2FSx(s_emu.ats.fsci);
    s_emu.iso_param.DID          = RFAL_ISODEP_NO_DID;
    s_emu.iso_param.FWT          = RFAL_FWT_NONE;

    rfalFieldOff();
    rfalIsoDepInitialize();
    rfalListenStop();
    rfalSetFDTListen(RFAL_FDT_LISTEN_NFCA_LISTENER);

    rc = rfalListenStart(RFAL_LM_MASK_NFCA, &s_emu.conf_a, NULL, NULL,
                         s_emu.rx_buf, rfalConvBytesToBits(POOM_NFC_EMU_RX_BUF_LEN),
                         &s_emu.rx_bits);
    if(rc != ERR_NONE)
    {
        printf("  nfc-emul: listen start failed err=%d\r\n", rc);
        return false;
    }
    return true;
}

/**
 * @brief Starts the internal runtime for this module.
 *
 * @return void
 */
static void poom_nfc_emu_restart_listen(void)
{
    (void)poom_nfc_emu_start_listen();
}

/**
 * @brief Handles the current module action.
 *
 * @return void
 */
static void poom_nfc_emu_handle_iso_dep(void)
{
    ReturnCode rc;
    uint16_t tx_len;

    if(!s_emu.iso_activated)
    {
        rc = rfalIsoDepListenGetActivationStatus();
        if(rc == ERR_BUSY)
        {
            return;
        }
        if(rc == ERR_NONE)
        {
            s_emu.iso_activated = true;
            return;
        }
        poom_nfc_emu_restart_listen();
        return;
    }

    rc = rfalIsoDepGetTransceiveStatus();
    if(rc == ERR_BUSY)
    {
        return;
    }
    if(rc == ERR_NONE)
    {
        tx_len = poom_nfc_emu_t4t_process(s_emu.t4t,
                                          s_emu.iso_param.rxBuf->inf,
                                          *s_emu.iso_param.rxLen,
                                          s_emu.iso_param.txBuf->inf,
                                          (uint16_t)sizeof(s_emu.iso_param.txBuf->inf));
        s_emu.iso_param.txBufLen = tx_len;
        *s_emu.iso_param.rxLen   = 0;

        rc = rfalIsoDepStartTransceive(s_emu.iso_param);
        if(rc != ERR_NONE)
        {
            poom_nfc_emu_restart_listen();
        }
        return;
    }

    if(rc == ERR_LINK_LOSS || rc == ERR_SLEEP_REQ || rc == ERR_TIMEOUT)
    {
        poom_nfc_emu_restart_listen();
    }
}

/**
 * @brief Handles the current module action.
 *
 * @return void
 */
static void poom_nfc_emu_handle_l3(void)
{
    ReturnCode rc;
    uint16_t tx_bits = 0;
    bool card_reset  = false;

    if(s_emu.l3_txrx_busy)
    {
        rc = rfalGetTransceiveStatus();
        if(rc == ERR_BUSY)
        {
            return;
        }
        s_emu.l3_txrx_busy = false;

        if(rc == ERR_NONE)
        {
            s_emu.l3_rx_ready = true;
            if(s_emu.l3_restart_after_tx)
            {
                poom_nfc_emu_restart_listen();
            }
            s_emu.l3_restart_after_tx = false;
            return;
        }

        poom_nfc_emu_restart_listen();
        return;
    }

    if(!s_emu.l3_rx_ready)
    {
        return;
    }

    if(s_emu.cfg.mode == POOM_NFC_EMU_MODE_MFUL)
    {
        tx_bits = poom_nfc_emu_mful_process(s_emu.mful, s_emu.rx_buf,
                                            rfalConvBitsToBytes(s_emu.rx_bits),
                                            s_emu.tx_buf, POOM_NFC_EMU_TX_BUF_LEN,
                                            &card_reset);
    }
    else
    {
        /* MODE_3A only exposes the NFC-A identity. After a reader sends an
         * unsupported post-selection command (for example Classic AUTH),
         * restart listening so the identity remains discoverable. */
        tx_bits = 0;
        card_reset = true;
    }

    s_emu.l3_rx_ready = false;

    if(card_reset && tx_bits == 0U)
    {
        poom_nfc_emu_restart_listen();
        return;
    }
    if(tx_bits == 0U)
    {
        return;
    }

    s_emu.l3_ctx.txBuf    = s_emu.tx_buf;
    s_emu.l3_ctx.txBufLen = tx_bits;
    s_emu.l3_ctx.flags    = RFAL_TXRX_FLAGS_DEFAULT;

    rc = rfalStartTransceive(&s_emu.l3_ctx);
    if(rc != ERR_NONE)
    {
        poom_nfc_emu_restart_listen();
        return;
    }
    s_emu.l3_txrx_busy       = true;
    s_emu.l3_restart_after_tx = card_reset;
}

/**
 * @brief Internal helper for `poom_nfc_emu_state_machine`.
 *
 * @return void
 */
static void poom_nfc_emu_state_machine(void)
{
    bool data_flag = false;
    rfalLmState st;

    rfalWorker();
    st = rfalListenGetState(&data_flag, NULL);

    switch(st)
    {
        case RFAL_LM_STATE_ACTIVE_A:
        case RFAL_LM_STATE_ACTIVE_Ax:
            if(data_flag)
            {
                uint8_t rx_bytes = (uint8_t)rfalConvBitsToBytes(s_emu.rx_bits);
                if(rfalNfcaListenerIsSleepReq(s_emu.rx_buf, rx_bytes))
                {
                    (void)rfalListenSleepStart(RFAL_LM_STATE_SLEEP_A, s_emu.rx_buf,
                                               rfalConvBytesToBits(POOM_NFC_EMU_RX_BUF_LEN),
                                               &s_emu.rx_bits);
                    break;
                }

                if((s_emu.cfg.mode == POOM_NFC_EMU_MODE_T4T) &&
                   rfalIsoDepIsRats(s_emu.rx_buf, rx_bytes))
                {
                    rfalIsoDepListenActvParam rx_param;

                    rfalListenSetState(RFAL_LM_STATE_CARDEMU_4A);
                    rx_param.rxBuf        = s_emu.iso_rx;
                    rx_param.rxLen        = &s_emu.rx_bits;
                    rx_param.isoDepDev    = NULL;
                    rx_param.isRxChaining = &s_emu.iso_rx_chaining;
                    (void)rfalIsoDepListenStartActivation(&s_emu.ats, NULL, s_emu.rx_buf,
                                                          s_emu.rx_bits, rx_param);
                    break;
                }

                s_emu.l3_rx_ready = true;
            }
            poom_nfc_emu_handle_l3();
            break;

        case RFAL_LM_STATE_CARDEMU_4A:
            if(s_emu.cfg.mode == POOM_NFC_EMU_MODE_T4T)
            {
                poom_nfc_emu_handle_iso_dep();
            }
            else
            {
                poom_nfc_emu_restart_listen();
            }
            break;

        case RFAL_LM_STATE_SLEEP_A:
            break;

        default:
            break;
    }
}

/**
 * @brief Runs the internal task for this module.
 *
 * @param[in] arg Parameter passed to the function.
 * @return void
 */
static void poom_nfc_emu_task(void* arg)
{
    (void)arg;

    if(!poom_nfc_emu_start_listen())
    {
        poom_nfc_emu_free_runtime_buffers_();
        s_emu.running = false;
        s_emu.task_h  = NULL;
        vTaskDelete(NULL);
        return;
    }

    printf("  nfc-emul: started (%s)\r\n",
           poom_nfc_emulator_mode_to_str(s_emu.cfg.mode));
    while(!s_emu.stop_req)
    {
        poom_nfc_emu_state_machine();
        vTaskDelay(pdMS_TO_TICKS(POOM_NFC_EMU_LOOP_DELAY_MS));
    }

    rfalListenStop();
    rfalFieldOff();
    poom_nfc_emu_free_runtime_buffers_();
    s_emu.running = false;
    s_emu.task_h  = NULL;
    printf("  nfc-emul: stopped\r\n");
    vTaskDelete(NULL);
}

/**
 * @brief Internal helper for `poom_nfc_emu_cfg_defaults`.
 *
 * @return void
 */
static void poom_nfc_emu_cfg_defaults(void)
{
    memset(&s_emu.cfg, 0, sizeof(s_emu.cfg));

    s_emu.cfg.mode = POOM_NFC_EMU_MODE_T4T;

    s_emu.cfg.uid_len = POOM_NFC_EMU_UID_DEF_LEN;
    memcpy(s_emu.cfg.uid, s_uid_default, sizeof(s_uid_default));

    s_emu.cfg.sak     = POOM_NFC_EMU_SAK_DEFAULT_T4T;
    s_emu.cfg.sak_set = true;

    s_emu.cfg.atqa[0] = POOM_NFC_EMU_ATQA_7B_UID;
    s_emu.cfg.atqa[1] = POOM_NFC_EMU_ATQA_LSB_DEFAULT;
    s_emu.cfg.atqa_set = true;

    strcpy(s_emu.cfg.uri, POOM_NFC_EMU_DEFAULT_URI);
    s_emu.cfg.uri_set = true;

    s_emu.cfg.ats_len = 0; /* use defaults */
}

/**
 * @brief Loads internal data used by this module.
 *
 * @return void
 */
static void poom_nfc_emu_cfg_try_load_persisted_uri_(void)
{
    size_t n = sizeof(s_emu.cfg.uri);

    const esp_err_t init_err = poom_secrets_init();
    if(init_err != ESP_OK)
    {
        return;
    }

    const esp_err_t err = poom_secrets_get_str(POOM_NFC_EMU_KEY_URI, s_emu.cfg.uri, &n);
    if(err != ESP_OK)
    {
        return;
    }
    if(s_emu.cfg.uri[0] == '\0')
    {
        return;
    }

    s_emu.cfg.uri_set = true;
}

/**
 * @brief Saves internal data used by this module.
 *
 * @param[in] uri Parameter passed to the function.
 * @return bool
 */
static bool poom_nfc_emu_cfg_save_persisted_uri_(const char* uri)
{
    if(uri == NULL)
    {
        return false;
    }

    const esp_err_t init_err = poom_secrets_init();
    if(init_err != ESP_OK)
    {
        return false;
    }

    return (poom_secrets_set_str(POOM_NFC_EMU_KEY_URI, uri) == ESP_OK);
}

/**
 * @brief Clears the internal state used by this module.
 *
 * @return bool
 */
static bool poom_nfc_emu_cfg_clear_persisted_uri_(void)
{
    const esp_err_t init_err = poom_secrets_init();
    if(init_err != ESP_OK)
    {
        return false;
    }
    return (poom_secrets_erase_key(POOM_NFC_EMU_KEY_URI) == ESP_OK);
}

void poom_nfc_emulator_init(void)
{
    static bool s_done = false;
    if(s_done)
    {
        return;
    }

    memset(&s_emu, 0, sizeof(s_emu));
    poom_nfc_emu_cfg_defaults();
    poom_nfc_emu_cfg_try_load_persisted_uri_();
    s_done = true;
}

void poom_nfc_emulator_reset_config(void)
{
    poom_nfc_emulator_init();

    if(s_emu.running)
    {
        printf("  nfc-emul: stop first.\r\n");
        return;
    }
    poom_nfc_emu_free_runtime_buffers_();
    poom_nfc_emu_cfg_defaults();
    (void)poom_nfc_emu_cfg_clear_persisted_uri_();
}

bool poom_nfc_emulator_set_mode(poom_nfc_emu_mode_t mode)
{
    poom_nfc_emulator_init();

    if(s_emu.running)
        return false;
    if(mode > POOM_NFC_EMU_MODE_MFUL)
        return false;
    s_emu.cfg.mode = mode;

    if(mode == POOM_NFC_EMU_MODE_MFUL)
    {
        s_emu.cfg.sak     = 0x00U;
        s_emu.cfg.sak_set = true;

        s_emu.cfg.atqa[0] = (s_emu.cfg.uid_len == POOM_NFC_EMU_UID_LEN_7)
                                ? POOM_NFC_EMU_ATQA_7B_UID
                                : POOM_NFC_EMU_ATQA_4B_UID;
        s_emu.cfg.atqa[1] = POOM_NFC_EMU_ATQA_LSB_DEFAULT;
        s_emu.cfg.atqa_set = true;
    }
    else if(mode == POOM_NFC_EMU_MODE_T4T)
    {
        s_emu.cfg.sak     = POOM_NFC_EMU_SAK_DEFAULT_T4T;
        s_emu.cfg.sak_set = true;

        s_emu.cfg.atqa[0] = (s_emu.cfg.uid_len == POOM_NFC_EMU_UID_LEN_7)
                                ? POOM_NFC_EMU_ATQA_7B_UID
                                : POOM_NFC_EMU_ATQA_4B_UID;
        s_emu.cfg.atqa[1] = POOM_NFC_EMU_ATQA_LSB_DEFAULT;
        s_emu.cfg.atqa_set = true;
    }
    return true;
}

bool poom_nfc_emulator_set_uid(const uint8_t* uid, uint8_t uid_len)
{
    poom_nfc_emulator_init();

    if(s_emu.running || uid == NULL)
        return false;
    if(uid_len != POOM_NFC_EMU_UID_LEN_4 && uid_len != POOM_NFC_EMU_UID_LEN_7)
        return false;
    memset(s_emu.cfg.uid, 0, sizeof(s_emu.cfg.uid));
    memcpy(s_emu.cfg.uid, uid, uid_len);
    s_emu.cfg.uid_len = uid_len;
    if(!s_emu.cfg.atqa_set)
    {
        s_emu.cfg.atqa[0] = (uid_len == POOM_NFC_EMU_UID_LEN_7) ? POOM_NFC_EMU_ATQA_7B_UID
                                                                 : POOM_NFC_EMU_ATQA_4B_UID;
        s_emu.cfg.atqa[1] = POOM_NFC_EMU_ATQA_LSB_DEFAULT;
    }
    return true;
}

bool poom_nfc_emulator_set_sak(uint8_t sak)
{
    poom_nfc_emulator_init();

    if(s_emu.running)
        return false;
    s_emu.cfg.sak     = sak;
    s_emu.cfg.sak_set = true;
    return true;
}

bool poom_nfc_emulator_set_atqa(const uint8_t atqa[2])
{
    poom_nfc_emulator_init();

    if(s_emu.running || atqa == NULL)
        return false;
    s_emu.cfg.atqa[0] = atqa[0];
    s_emu.cfg.atqa[1] = atqa[1];
    s_emu.cfg.atqa_set = true;
    return true;
}

bool poom_nfc_emulator_set_ats(const uint8_t* ats, uint8_t ats_len)
{
    poom_nfc_emulator_init();

    if(s_emu.running)
        return false;
    if(ats == NULL || ats_len == 0U)
    {
        s_emu.cfg.ats_len = 0U;
        memset(s_emu.cfg.ats, 0, sizeof(s_emu.cfg.ats));
        return true;
    }
    if(ats_len > sizeof(s_emu.cfg.ats))
        return false;
    memcpy(s_emu.cfg.ats, ats, ats_len);
    s_emu.cfg.ats_len = ats_len;
    return true;
}

bool poom_nfc_emulator_set_uri(const char* uri)
{
    size_t n;

    poom_nfc_emulator_init();

    if(s_emu.running || uri == NULL)
        return false;

    n = strlen(uri);
    if(n >= sizeof(s_emu.cfg.uri))
        return false;

    memcpy(s_emu.cfg.uri, uri, n + 1U);
    s_emu.cfg.uri_set = true;
    if(!poom_nfc_emu_cfg_save_persisted_uri_(s_emu.cfg.uri))
    {
        return false;
    }
    return true;
}

bool poom_nfc_emulator_clear_uri(void)
{
    poom_nfc_emulator_init();

    if(s_emu.running)
    {
        return false;
    }

    strcpy(s_emu.cfg.uri, POOM_NFC_EMU_DEFAULT_URI);
    s_emu.cfg.uri_set = true;
    (void)poom_nfc_emu_cfg_clear_persisted_uri_();
    return true;
}

bool poom_nfc_emulator_set_mful_image_file(const char* path)
{
    size_t n;

    poom_nfc_emulator_init();

    if(s_emu.running || path == NULL)
        return false;

    n = strlen(path);
    if(n >= sizeof(s_emu.cfg.image_path))
        return false;
    memcpy(s_emu.cfg.image_path, path, n + 1U);
    s_emu.cfg.image_path_set = true;
    return true;
}

bool poom_nfc_emulator_start(void)
{
    BaseType_t ok;

    poom_nfc_emulator_init();

    if(s_emu.running)
    {
        printf("  nfc-emul: already running\r\n");
        return false;
    }

    if(!poom_nfc_emu_alloc_runtime_buffers_())
    {
        return false;
    }

    poom_nfc_emu_reset_t4t_state();
    if(!poom_nfc_emu_config_to_listen_params())
    {
        poom_nfc_emu_free_runtime_buffers_();
        return false;
    }

    s_emu.stop_req = false;
    s_emu.running  = true;

    ok = xTaskCreate(poom_nfc_emu_task, "poom_nfc_emu", POOM_NFC_EMU_TASK_STACK,
                     NULL, POOM_NFC_EMU_TASK_PRIO, &s_emu.task_h);
    if(ok != pdPASS)
    {
        s_emu.running = false;
        s_emu.task_h  = NULL;
        poom_nfc_emu_free_runtime_buffers_();
        printf("  nfc-emul: failed to create task\r\n");
        return false;
    }
    return true;
}

void poom_nfc_emulator_stop(void)
{
    uint32_t i;

    if(!s_emu.running)
    {
        return;
    }
    s_emu.stop_req = true;
    for(i = 0; i < POOM_NFC_EMU_STOP_WAIT_LOOPS; i++)
    {
        if(!s_emu.running)
        {
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(POOM_NFC_EMU_STOP_WAIT_DELAY_MS));
    }

    if(s_emu.running)
    {
        rfalListenStop();
        rfalFieldOff();
        printf("  nfc-emul: stop timeout; task cleanup still pending\r\n");
    }
}

bool poom_nfc_emulator_is_running(void)
{
    return s_emu.running;
}

void poom_nfc_emulator_get_config(poom_nfc_emu_cfg_t* out_cfg)
{
    poom_nfc_emulator_init();

    if(out_cfg == NULL)
        return;
    *out_cfg = s_emu.cfg;
}

const char* poom_nfc_emulator_mode_to_str(poom_nfc_emu_mode_t mode)
{
    switch(mode)
    {
        case POOM_NFC_EMU_MODE_3A:
            return "3a";
        case POOM_NFC_EMU_MODE_T4T:
            return "t4t";
        case POOM_NFC_EMU_MODE_MFUL:
            return "mful";
        default:
            return "unknown";
    }
}
