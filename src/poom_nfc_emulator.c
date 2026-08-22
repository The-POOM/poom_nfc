#include "poom_nfc_emulator.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_rom_sys.h"

#include "poom_nfc_ats.h"
#include "poom_secrets_store.h"

#include "rfal_isoDep.h"
#include "rfal_nfca.h"
#include "rfal_rf.h"
#include "sd_card.h"

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
    POOM_NFC_EMU_TASK_STACK       = 6144,
    POOM_NFC_EMU_TASK_PRIO        = 18,
    POOM_NFC_EMU_LOOP_DELAY_MS    = 1,
    POOM_NFC_EMU_RX_BUF_LEN       = 300,
    POOM_NFC_EMU_TX_BUF_LEN       = 300,
    POOM_NFC_EMU_NDEF_MAX         = 1024,
    POOM_NFC_EMU_MFUL_PAGE_SIZE   = 4,
    POOM_NFC_EMU_MFUL_PAGE_COUNT_213  = 45,  /* NTAG213: pages 0..44 */
    POOM_NFC_EMU_MFUL_PAGE_COUNT_215  = 135, /* NTAG215: pages 0..134 */
    POOM_NFC_EMU_MFUL_PAGE_COUNT_216  = 231, /* NTAG216: pages 0..230 */
    POOM_NFC_EMU_MFUL_DATA_LEN_213 =
        (POOM_NFC_EMU_MFUL_PAGE_COUNT_213 * POOM_NFC_EMU_MFUL_PAGE_SIZE), /* 180 bytes */
    POOM_NFC_EMU_MFUL_DATA_LEN_215 =
        (POOM_NFC_EMU_MFUL_PAGE_COUNT_215 * POOM_NFC_EMU_MFUL_PAGE_SIZE), /* 540 bytes */
    POOM_NFC_EMU_MFUL_DATA_LEN_216 =
        (POOM_NFC_EMU_MFUL_PAGE_COUNT_216 * POOM_NFC_EMU_MFUL_PAGE_SIZE), /* 924 bytes */
    POOM_NFC_EMU_MFUL_DATA_LEN_MAX = POOM_NFC_EMU_MFUL_DATA_LEN_216,
    POOM_NFC_EMU_MFUL_ROLLOVER    = (3 * POOM_NFC_EMU_MFUL_PAGE_SIZE), /* READ wraps 3 pages */
    POOM_NFC_EMU_MFUL_IMG_LEN     = (POOM_NFC_EMU_MFUL_DATA_LEN_MAX + POOM_NFC_EMU_MFUL_ROLLOVER),
    POOM_NFC_EMU_T4T_CLA_00       = 0x00,
    POOM_NFC_EMU_T4T_INS_SELECT   = 0xA4,
    POOM_NFC_EMU_T4T_INS_READ     = 0xB0,
    POOM_NFC_EMU_T4T_INS_UPDATE   = 0xD6,
    POOM_NFC_EMU_FID_CC_H         = 0xE1,
    POOM_NFC_EMU_FID_CC_L         = 0x03,
    POOM_NFC_EMU_FID_NDEF_H       = 0x00,
    POOM_NFC_EMU_FID_NDEF_L       = 0x01,
    POOM_NFC_EMU_CMD_UL_READ      = 0x30,
    POOM_NFC_EMU_CMD_UL_FAST_READ = 0x3A,
    POOM_NFC_EMU_CMD_UL_WRITE     = 0xA2,
    POOM_NFC_EMU_CMD_UL_CWRITE    = 0xA0,
    POOM_NFC_EMU_CMD_UL_PWD_AUTH  = 0x1B,
    POOM_NFC_EMU_CMD_UL_READ_CNT  = 0x39,
    POOM_NFC_EMU_CMD_UL_READ_SIG  = 0x3C,
    POOM_NFC_EMU_CMD_UL_GET_VERSION = 0x60,
    POOM_NFC_EMU_MIF_ACK          = 0x0A,
    POOM_NFC_EMU_MIF_NAK          = 0x00,
    POOM_NFC_EMU_UID_LEN_4        = 4,
    POOM_NFC_EMU_UID_LEN_7        = 7,
    POOM_NFC_EMU_UID_LEN_10       = 10,
    POOM_NFC_EMU_UID_DEF_LEN      = 7,
    POOM_NFC_EMU_ATQA_4B_UID      = 0x04,
    POOM_NFC_EMU_ATQA_7B_UID      = 0x44,
    POOM_NFC_EMU_ATQA_LSB_DEFAULT = 0x00,
    POOM_NFC_EMU_SAK_DEFAULT_T4T  = 0x20,
    POOM_NFC_EMU_FILE_COUNT       = 2,
    POOM_NFC_EMU_FILE_IDX_CC      = 0,
    POOM_NFC_EMU_FILE_IDX_NDEF    = 1,
    POOM_NFC_EMU_FILE_NONE        = -1,
    POOM_NFC_EMU_CC_FILE_LEN      = 15,
    POOM_NFC_EMU_CC_NDEF_MSB_IDX  = 11,
    POOM_NFC_EMU_CC_NDEF_LSB_IDX  = 12,
    POOM_NFC_EMU_URI_MAX_LEN      = 240,
    POOM_NFC_EMU_NDEF_HDR_LEN     = 2,
    POOM_NFC_EMU_NDEF_REC_MIN_LEN = 5,
    POOM_NFC_EMU_NDEF_URI_TYPE    = 0x55,
    POOM_NFC_EMU_NDEF_MB_ME_SR_TNF_WELLKNOWN = 0xD1,
    POOM_NFC_EMU_NDEF_TYPE_LEN_URI           = 0x01,
    POOM_NFC_EMU_NDEF_URI_PREFIX_NONE        = 0x00,
    POOM_NFC_EMU_ATS_DEFAULT_FSCI    = 0x08,
    POOM_NFC_EMU_ATS_DEFAULT_FWI     = 0x0A,
    POOM_NFC_EMU_ATS_DEFAULT_SFGI    = 0x00,
    POOM_NFC_EMU_APDU_MIN_LEN        = 5,
    POOM_NFC_EMU_APDU_SW_LEN         = 2,
    POOM_NFC_EMU_SW1_OK              = 0x90,
    POOM_NFC_EMU_SW2_OK              = 0x00,
    POOM_NFC_EMU_SW1_FUNC_NOT_SUPP   = 0x68,
    POOM_NFC_EMU_SW1_WRONG_LEN       = 0x67,
    POOM_NFC_EMU_SW1_NOT_FOUND       = 0x6A,
    POOM_NFC_EMU_SW2_NOT_FOUND       = 0x82,
    POOM_NFC_EMU_SW1_WARN            = 0x62,
    POOM_NFC_EMU_SW1_TECHNICAL       = 0x6F,
    POOM_NFC_EMU_CMD_FIND_LIMIT      = 20,
    POOM_NFC_EMU_MFUL_READ_CMD_LEN   = 2,
    POOM_NFC_EMU_MFUL_FAST_READ_CMD_LEN = 3,
    POOM_NFC_EMU_MFUL_WRITE_CMD_LEN  = 6,
    POOM_NFC_EMU_MFUL_CWRITE_CMD_LEN = 2,
    POOM_NFC_EMU_MFUL_CWRITE_PHASE2_LEN = 16,
    POOM_NFC_EMU_MFUL_PWD_AUTH_CMD_LEN = 5,
    POOM_NFC_EMU_MFUL_READ_CNT_CMD_LEN = 2,
    POOM_NFC_EMU_MFUL_READ_SIG_CMD_LEN = 2,
    POOM_NFC_EMU_MFUL_GET_VERSION_CMD_LEN = 1,
    POOM_NFC_EMU_MFUL_READ_RSP_LEN   = 16,
    POOM_NFC_EMU_MFUL_GET_VERSION_RSP_LEN = 8,
    POOM_NFC_EMU_MFUL_PWD_AUTH_RSP_LEN = 2,
    POOM_NFC_EMU_MFUL_READ_CNT_RSP_LEN = 3,
    POOM_NFC_EMU_MFUL_READ_SIG_RSP_LEN = 32,
    POOM_NFC_EMU_MFUL_ACK_BITS       = 4,
    POOM_NFC_EMU_MFUL_PAGE_LOCK      = 0x02, /* lock bytes are at page 2 bytes 2..3 */
    POOM_NFC_EMU_MFUL_PAGE_OTP       = 0x03,
    POOM_NFC_EMU_MFUL_PAGE_USER_FIRST = 0x04,
    POOM_NFC_EMU_MFUL_PAGE_USER_LAST_213  = 0x27,
    POOM_NFC_EMU_MFUL_PAGE_USER_LAST_215  = 0x81,
    POOM_NFC_EMU_MFUL_PAGE_USER_LAST_216  = 0xE1,
    POOM_NFC_EMU_MFUL_PAGE_LAST_213       = 0x2C,
    POOM_NFC_EMU_MFUL_PAGE_LAST_215       = 0x86,
    POOM_NFC_EMU_MFUL_PAGE_LAST_216       = 0xE6,
    POOM_NFC_EMU_MFUL_DYN_LOCK_PAGE_213   = 0x28,
    POOM_NFC_EMU_MFUL_DYN_LOCK_PAGE_215   = 0x82,
    POOM_NFC_EMU_MFUL_DYN_LOCK_PAGE_216   = 0xE2,
    POOM_NFC_EMU_MFUL_CFG0_PAGE_213       = 0x29,
    POOM_NFC_EMU_MFUL_CFG0_PAGE_215       = 0x83,
    POOM_NFC_EMU_MFUL_CFG0_PAGE_216       = 0xE3,
    POOM_NFC_EMU_MFUL_CFG1_PAGE_213       = 0x2A,
    POOM_NFC_EMU_MFUL_CFG1_PAGE_215       = 0x84,
    POOM_NFC_EMU_MFUL_CFG1_PAGE_216       = 0xE4,
    POOM_NFC_EMU_MFUL_PWD_PAGE_213        = 0x2B,
    POOM_NFC_EMU_MFUL_PWD_PAGE_215        = 0x85,
    POOM_NFC_EMU_MFUL_PWD_PAGE_216        = 0xE5,
    POOM_NFC_EMU_MFUL_PACK_PAGE_213       = 0x2C,
    POOM_NFC_EMU_MFUL_PACK_PAGE_215       = 0x86,
    POOM_NFC_EMU_MFUL_PACK_PAGE_216       = 0xE6,
    POOM_NFC_EMU_MFUL_LOCK_OFFSET     = ((2 * POOM_NFC_EMU_MFUL_PAGE_SIZE) + 2),
    POOM_NFC_EMU_MFUL_LOCK_BYTES      = 2,
    POOM_NFC_EMU_MFUL_RESET_DELAY_US  = 100,
    POOM_NFC_EMU_MFUL_HALT_CMD        = 0x50,
    POOM_NFC_EMU_MFUL_HALT_ARG        = 0x00,
    POOM_NFC_EMU_STOP_WAIT_LOOPS      = 300,
    POOM_NFC_EMU_STOP_WAIT_DELAY_MS   = 10,
};

typedef enum
{
    POOM_T4T_STATE_IDLE = 0,
    POOM_T4T_STATE_APP_SELECTED,
    POOM_T4T_STATE_CC_SELECTED,
    POOM_T4T_STATE_FID_SELECTED,
} poom_t4t_state_t;

typedef struct
{
    TaskHandle_t task_h;
    volatile bool running;
    volatile bool stop_req;

    poom_nfc_emu_cfg_t cfg;

    rfalLmConfPA conf_a;
    rfalIsoDepAtsParam ats;
    uint8_t ats_hb[16];

    uint8_t rx_buf[POOM_NFC_EMU_RX_BUF_LEN];
    uint8_t tx_buf[POOM_NFC_EMU_TX_BUF_LEN];
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

    poom_t4t_state_t t4t_state;
    int t4t_selected_idx;
    uint8_t cc_file[POOM_NFC_EMU_CC_FILE_LEN];
    uint32_t file_size[POOM_NFC_EMU_FILE_COUNT];
    uint8_t ndef_file[POOM_NFC_EMU_NDEF_MAX];

    uint8_t mful_image[POOM_NFC_EMU_MFUL_IMG_LEN];
    uint8_t mful_cwrite_page_set;
    uint16_t mful_data_len;
    uint8_t mful_page_last;
    uint8_t mful_page_user_last;
    uint8_t mful_dyn_lock_page;
    uint8_t mful_cfg0_page;
    uint8_t mful_cfg1_page;
    uint8_t mful_pwd_page;
    uint8_t mful_pack_page;
    uint8_t mful_version[POOM_NFC_EMU_MFUL_GET_VERSION_RSP_LEN];
    uint8_t mful_signature[POOM_NFC_EMU_MFUL_READ_SIG_RSP_LEN];
    bool mful_auth_ok;
} poom_nfc_emu_ctx_t;

static poom_nfc_emu_ctx_t s_emu;

static const uint8_t s_uid_default[POOM_NFC_EMU_UID_DEF_LEN] = {
    0x02, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
};

static const uint8_t s_cc_file_template[POOM_NFC_EMU_CC_FILE_LEN] = {
    0x00, 0x0F, 0x20, 0x00, 0x7F, 0x00, 0x7F, 0x04, 0x06, POOM_NFC_EMU_FID_NDEF_H,
    POOM_NFC_EMU_FID_NDEF_L, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t s_mful_factory[POOM_NFC_EMU_MFUL_IMG_LEN] = {
    /* Pages 0..3 (manufacturer + CC defaults), rest zeroed by static init. */
    0x04, 0x3B, 0x99, 0x2E, 0x0A, 0x9D, 0x32, 0x80, 0x25, 0x48, 0x0F, 0xE0, 0xF1,
    0x10, 0xFF, 0xEE,
};

static const uint8_t s_mful_version_ntag215[POOM_NFC_EMU_MFUL_GET_VERSION_RSP_LEN] = {
    0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x11, 0x03,
};

static const uint8_t s_mful_version_ntag213[POOM_NFC_EMU_MFUL_GET_VERSION_RSP_LEN] = {
    0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x0F, 0x03,
};

static const uint8_t s_mful_version_ntag216[POOM_NFC_EMU_MFUL_GET_VERSION_RSP_LEN] = {
    0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x13, 0x03,
};

static const uint8_t s_mful_signature_default[POOM_NFC_EMU_MFUL_READ_SIG_RSP_LEN] = {
    0x00,
};

/**
 * @brief Internal helper for `poom_nfc_emu_mful_apply_variant`.
 *
 * @param[in] pages_total Parameter passed to the function.
 * @return void
 */
static void poom_nfc_emu_mful_apply_variant_(uint16_t pages_total)
{
    if(pages_total == POOM_NFC_EMU_MFUL_PAGE_COUNT_213)
    {
        s_emu.mful_data_len      = POOM_NFC_EMU_MFUL_DATA_LEN_213;
        s_emu.mful_page_last     = POOM_NFC_EMU_MFUL_PAGE_LAST_213;
        s_emu.mful_page_user_last = POOM_NFC_EMU_MFUL_PAGE_USER_LAST_213;
        s_emu.mful_dyn_lock_page = POOM_NFC_EMU_MFUL_DYN_LOCK_PAGE_213;
        s_emu.mful_cfg0_page     = POOM_NFC_EMU_MFUL_CFG0_PAGE_213;
        s_emu.mful_cfg1_page     = POOM_NFC_EMU_MFUL_CFG1_PAGE_213;
        s_emu.mful_pwd_page      = POOM_NFC_EMU_MFUL_PWD_PAGE_213;
        s_emu.mful_pack_page     = POOM_NFC_EMU_MFUL_PACK_PAGE_213;
        memcpy(s_emu.mful_version, s_mful_version_ntag213, sizeof(s_emu.mful_version));
    }
    else if(pages_total == POOM_NFC_EMU_MFUL_PAGE_COUNT_216)
    {
        s_emu.mful_data_len      = POOM_NFC_EMU_MFUL_DATA_LEN_216;
        s_emu.mful_page_last     = POOM_NFC_EMU_MFUL_PAGE_LAST_216;
        s_emu.mful_page_user_last = POOM_NFC_EMU_MFUL_PAGE_USER_LAST_216;
        s_emu.mful_dyn_lock_page = POOM_NFC_EMU_MFUL_DYN_LOCK_PAGE_216;
        s_emu.mful_cfg0_page     = POOM_NFC_EMU_MFUL_CFG0_PAGE_216;
        s_emu.mful_cfg1_page     = POOM_NFC_EMU_MFUL_CFG1_PAGE_216;
        s_emu.mful_pwd_page      = POOM_NFC_EMU_MFUL_PWD_PAGE_216;
        s_emu.mful_pack_page     = POOM_NFC_EMU_MFUL_PACK_PAGE_216;
        memcpy(s_emu.mful_version, s_mful_version_ntag216, sizeof(s_emu.mful_version));
    }
    else /* default: NTAG215 */
    {
        s_emu.mful_data_len      = POOM_NFC_EMU_MFUL_DATA_LEN_215;
        s_emu.mful_page_last     = POOM_NFC_EMU_MFUL_PAGE_LAST_215;
        s_emu.mful_page_user_last = POOM_NFC_EMU_MFUL_PAGE_USER_LAST_215;
        s_emu.mful_dyn_lock_page = POOM_NFC_EMU_MFUL_DYN_LOCK_PAGE_215;
        s_emu.mful_cfg0_page     = POOM_NFC_EMU_MFUL_CFG0_PAGE_215;
        s_emu.mful_cfg1_page     = POOM_NFC_EMU_MFUL_CFG1_PAGE_215;
        s_emu.mful_pwd_page      = POOM_NFC_EMU_MFUL_PWD_PAGE_215;
        s_emu.mful_pack_page     = POOM_NFC_EMU_MFUL_PACK_PAGE_215;
        memcpy(s_emu.mful_version, s_mful_version_ntag215, sizeof(s_emu.mful_version));
    }

    memcpy(s_emu.mful_signature, s_mful_signature_default, sizeof(s_emu.mful_signature));
    s_emu.mful_auth_ok = false;
}

/**
 * @brief Internal helper for `poom_nfc_emu_mful_rebuild_rollover`.
 *
 * @return void
 */
static void poom_nfc_emu_mful_rebuild_rollover(void)
{
    memcpy(&s_emu.mful_image[s_emu.mful_data_len], s_emu.mful_image,
           POOM_NFC_EMU_MFUL_ROLLOVER);
}

/**
 * @brief Internal helper for `poom_nfc_emu_mful_is_zero4`.
 *
 * @param[in] p Parameter passed to the function.
 * @return bool
 */
static bool poom_nfc_emu_mful_is_zero4_(const uint8_t* p)
{
    return (p != NULL) && (p[0] == 0x00U) && (p[1] == 0x00U) && (p[2] == 0x00U) &&
           (p[3] == 0x00U);
}

/**
 * @brief Internal helper for `poom_nfc_emu_mful_pwd_from_uid7`.
 *
 * @param[in] uid Parameter passed to the function.
 * @param[in] out_pwd Parameter passed to the function.
 * @return void
 */
static void poom_nfc_emu_mful_pwd_from_uid7_(const uint8_t uid[7], uint8_t out_pwd[4])
{
    out_pwd[0] = (uint8_t)(0xAAU ^ uid[1] ^ uid[3]);
    out_pwd[1] = (uint8_t)(0x55U ^ uid[2] ^ uid[4]);
    out_pwd[2] = (uint8_t)(0xAAU ^ uid[3] ^ uid[5]);
    out_pwd[3] = (uint8_t)(0x55U ^ uid[4] ^ uid[6]);
}

/**
 * @brief Internal helper for `poom_nfc_emu_reset_mful_image`.
 *
 * @return void
 */
static void poom_nfc_emu_reset_mful_image(void)
{
    poom_nfc_emu_mful_apply_variant_(POOM_NFC_EMU_MFUL_PAGE_COUNT_215);
    memset(s_emu.mful_image, 0, sizeof(s_emu.mful_image));
    memcpy(s_emu.mful_image, s_mful_factory, sizeof(s_mful_factory));
    poom_nfc_emu_mful_rebuild_rollover();
    s_emu.mful_cwrite_page_set = 0;
    s_emu.mful_auth_ok = false;
}

/**
 * @brief Internal helper for `poom_nfc_emu_hex_nibble`.
 *
 * @param[in] c Parameter passed to the function.
 * @return int
 */
static int poom_nfc_emu_hex_nibble_(char c)
{
    if((c >= '0') && (c <= '9'))
    {
        return c - '0';
    }
    if((c >= 'a') && (c <= 'f'))
    {
        return 10 + (c - 'a');
    }
    if((c >= 'A') && (c <= 'F'))
    {
        return 10 + (c - 'A');
    }
    return -1;
}

/**
 * @brief Parses input data for this module.
 *
 * @param[in] s Parameter passed to the function.
 * @param[in] out Parameter passed to the function.
 * @param[in] out_max Parameter passed to the function.
 * @param[in] out_len Parameter passed to the function.
 * @return bool
 */
static bool poom_nfc_emu_parse_hex_bytes_(const char* s, uint8_t* out, size_t out_max, size_t* out_len)
{
    int hi = -1;
    size_t w = 0U;

    if((s == NULL) || (out == NULL) || (out_len == NULL))
    {
        return false;
    }

    for(const char* p = s; *p != '\0'; p++)
    {
        const int nib = poom_nfc_emu_hex_nibble_(*p);
        if(nib < 0)
        {
            continue;
        }

        if(hi < 0)
        {
            hi = nib;
        }
        else
        {
            if(w >= out_max)
            {
                return false;
            }
            out[w++] = (uint8_t)(((uint8_t)hi << 4) | (uint8_t)nib);
            hi = -1;
        }
    }

    if(hi >= 0)
    {
        return false;
    }

    *out_len = w;
    return true;
}

/**
 * @brief Internal helper for `poom_nfc_emu_skip_ws`.
 *
 * @param[in] s Parameter passed to the function.
 * @return const char*
 */
static const char* poom_nfc_emu_skip_ws_(const char* s)
{
    if(s == NULL)
    {
        return "";
    }

    while((*s == ' ') || (*s == '\t'))
    {
        s++;
    }
    return s;
}

/**
 * @brief Internal helper for `poom_nfc_emu_path_has_ext`.
 *
 * @param[in] path Parameter passed to the function.
 * @param[in] ext Parameter passed to the function.
 * @return bool
 */
static bool poom_nfc_emu_path_has_ext_(const char* path, const char* ext)
{
    size_t plen;
    size_t elen;

    if((path == NULL) || (ext == NULL))
    {
        return false;
    }

    plen = strlen(path);
    elen = strlen(ext);
    if((elen == 0U) || (plen < elen))
    {
        return false;
    }

    for(size_t i = 0U; i < elen; i++)
    {
        const char a = path[plen - elen + i];
        const char b = ext[i];
        if((char)tolower((unsigned char)a) != (char)tolower((unsigned char)b))
        {
            return false;
        }
    }
    return true;
}

/**
 * @brief Internal helper for `poom_nfc_emu_pages_from_version`.
 *
 * @param[in] version Parameter passed to the function.
 * @return uint16_t
 */
static uint16_t poom_nfc_emu_pages_from_version_(const uint8_t version[8])
{
    if(version == NULL)
    {
        return 0U;
    }

    if((version[0] != 0x00U) || (version[1] != 0x04U) || (version[2] != 0x04U) ||
       (version[3] != 0x02U) || (version[4] != 0x01U) || (version[5] != 0x00U))
    {
        return 0U;
    }

    if(version[6] == 0x0FU)
    {
        return POOM_NFC_EMU_MFUL_PAGE_COUNT_213;
    }
    if(version[6] == 0x11U)
    {
        return POOM_NFC_EMU_MFUL_PAGE_COUNT_215;
    }
    if(version[6] == 0x13U)
    {
        return POOM_NFC_EMU_MFUL_PAGE_COUNT_216;
    }
    return 0U;
}

/**
 * @brief Loads internal data used by this module.
 *
 * @param[in] f Parameter passed to the function.
 * @return bool
 */
static bool poom_nfc_emu_load_mful_flipper_nfc_(FILE* f)
{
    char line[384];
    uint8_t page_data[POOM_NFC_EMU_MFUL_DATA_LEN_MAX];
    bool page_seen[POOM_NFC_EMU_MFUL_PAGE_COUNT_216];
    bool has_any_page = false;
    uint16_t max_page_seen = 0U;

    uint8_t uid[10];
    size_t uid_len = 0U;
    bool uid_set = false;

    uint8_t atqa[2];
    bool atqa_set = false;
    uint8_t sak = 0U;
    bool sak_set = false;

    uint8_t signature[POOM_NFC_EMU_MFUL_READ_SIG_RSP_LEN];
    bool signature_set = false;

    uint8_t version[POOM_NFC_EMU_MFUL_GET_VERSION_RSP_LEN];
    bool version_set = false;

    uint16_t pages_total = 0U;
    bool pages_total_set = false;
    uint16_t pages_read = 0U;
    bool pages_read_set = false;
    uint16_t device_type_pages = 0U;
    uint16_t effective_pages = 0U;

    (void)memset(page_data, 0, sizeof(page_data));
    (void)memset(page_seen, 0, sizeof(page_seen));

    if(fseek(f, 0, SEEK_SET) != 0)
    {
        return false;
    }

    while(fgets(line, sizeof(line), f) != NULL)
    {
        const char* p = poom_nfc_emu_skip_ws_(line);

        if((*p == '\0') || (*p == '\r') || (*p == '\n') || (*p == '#'))
        {
            continue;
        }

        if(strncmp(p, "UID:", 4) == 0)
        {
            if(!poom_nfc_emu_parse_hex_bytes_(p + 4, uid, sizeof(uid), &uid_len))
            {
                return false;
            }
            uid_set = (uid_len == POOM_NFC_EMU_UID_LEN_4) || (uid_len == POOM_NFC_EMU_UID_LEN_7);
            continue;
        }

        if(strncmp(p, "Device type:", 12) == 0)
        {
            const char* v = poom_nfc_emu_skip_ws_(p + 12);
            if(strstr(v, "NTAG213") != NULL)
            {
                device_type_pages = POOM_NFC_EMU_MFUL_PAGE_COUNT_213;
            }
            else if(strstr(v, "NTAG215") != NULL)
            {
                device_type_pages = POOM_NFC_EMU_MFUL_PAGE_COUNT_215;
            }
            else if(strstr(v, "NTAG216") != NULL)
            {
                device_type_pages = POOM_NFC_EMU_MFUL_PAGE_COUNT_216;
            }
            continue;
        }

        if(strncmp(p, "NTAG/Ultralight type:", 21) == 0)
        {
            const char* v = poom_nfc_emu_skip_ws_(p + 21);
            if(strstr(v, "NTAG213") != NULL)
            {
                device_type_pages = POOM_NFC_EMU_MFUL_PAGE_COUNT_213;
            }
            else if(strstr(v, "NTAG215") != NULL)
            {
                device_type_pages = POOM_NFC_EMU_MFUL_PAGE_COUNT_215;
            }
            else if(strstr(v, "NTAG216") != NULL)
            {
                device_type_pages = POOM_NFC_EMU_MFUL_PAGE_COUNT_216;
            }
            continue;
        }

        if(strncmp(p, "ATQA:", 5) == 0)
        {
            size_t n = 0U;
            if(!poom_nfc_emu_parse_hex_bytes_(p + 5, atqa, sizeof(atqa), &n) || (n != 2U))
            {
                return false;
            }
            if(((atqa[1] == 0x44U) || (atqa[1] == 0x04U)) && (atqa[0] <= 0x03U))
            {
                const uint8_t t = atqa[0];
                atqa[0] = atqa[1];
                atqa[1] = t;
            }
            atqa_set = true;
            continue;
        }

        if(strncmp(p, "SAK:", 4) == 0)
        {
            uint8_t tmp[2];
            size_t n = 0U;
            if(!poom_nfc_emu_parse_hex_bytes_(p + 4, tmp, sizeof(tmp), &n) || (n != 1U))
            {
                return false;
            }
            sak = tmp[0];
            sak_set = true;
            continue;
        }

        if(strncmp(p, "Signature:", 10) == 0)
        {
            const char* sig = poom_nfc_emu_skip_ws_(p + 10);
            if((sig[0] == 'N' || sig[0] == 'n') &&
               (sig[1] == '/' || sig[1] == '\\') &&
               (sig[2] == 'A' || sig[2] == 'a'))
            {
                continue;
            }

            size_t n = 0U;
            if(!poom_nfc_emu_parse_hex_bytes_(sig, signature, sizeof(signature), &n) ||
               (n != sizeof(signature)))
            {
                return false;
            }
            signature_set = true;
            continue;
        }

        if(strncmp(p, "Mifare version:", 15) == 0)
        {
            size_t n = 0U;
            if(!poom_nfc_emu_parse_hex_bytes_(p + 15, version, sizeof(version), &n) ||
               (n != sizeof(version)))
            {
                return false;
            }
            version_set = true;
            continue;
        }

        if(strncmp(p, "Version bytes:", 14) == 0)
        {
            const char* vb = poom_nfc_emu_skip_ws_(p + 14);
            if((vb[0] == 'N' || vb[0] == 'n') &&
               (vb[1] == '/' || vb[1] == '\\') &&
               (vb[2] == 'A' || vb[2] == 'a'))
            {
                continue;
            }

            size_t n = 0U;
            if(!poom_nfc_emu_parse_hex_bytes_(vb, version, sizeof(version), &n) ||
               (n != sizeof(version)))
            {
                return false;
            }
            version_set = true;
            continue;
        }

        {
            unsigned int pages_u = 0U;
            if(sscanf(p, "Pages total: %u", &pages_u) == 1)
            {
                if(pages_u > 0xFFFFU)
                {
                    return false;
                }
                pages_total = (uint16_t)pages_u;
                pages_total_set = true;
                continue;
            }
        }

        {
            unsigned int pages_u = 0U;
            if(sscanf(p, "Pages read: %u", &pages_u) == 1)
            {
                if(pages_u > 0xFFFFU)
                {
                    return false;
                }
                pages_read = (uint16_t)pages_u;
                pages_read_set = true;
                continue;
            }
        }

        if(strncmp(p, "Page ", 5) == 0)
        {
            unsigned int page_u = 0U;
            const char* colon = strchr(p, ':');
            uint8_t bytes[16];
            size_t n = 0U;

            if((colon == NULL) || (sscanf(p, "Page %u", &page_u) != 1))
            {
                return false;
            }
            if(page_u > POOM_NFC_EMU_MFUL_PAGE_COUNT_216)
            {
                return false;
            }
            if(page_u == POOM_NFC_EMU_MFUL_PAGE_COUNT_216)
            {
                continue;
            }
            if(!poom_nfc_emu_parse_hex_bytes_(colon + 1, bytes, sizeof(bytes), &n) || (n < 4U))
            {
                return false;
            }

            (void)memcpy(&page_data[page_u * POOM_NFC_EMU_MFUL_PAGE_SIZE], bytes,
                         POOM_NFC_EMU_MFUL_PAGE_SIZE);
            page_seen[page_u] = true;
            has_any_page = true;
            if((uint16_t)page_u > max_page_seen)
            {
                max_page_seen = (uint16_t)page_u;
            }
        }
    }

    if(!has_any_page)
    {
        return false;
    }

    if(pages_total_set && ((pages_total == POOM_NFC_EMU_MFUL_PAGE_COUNT_213) ||
                           (pages_total == POOM_NFC_EMU_MFUL_PAGE_COUNT_215) ||
                           (pages_total == POOM_NFC_EMU_MFUL_PAGE_COUNT_216)))
    {
        effective_pages = pages_total;
    }
    if((effective_pages == 0U) && pages_total_set)
    {
        if(pages_total == (POOM_NFC_EMU_MFUL_PAGE_COUNT_213 + 1U))
        {
            effective_pages = POOM_NFC_EMU_MFUL_PAGE_COUNT_213;
        }
        else if(pages_total == (POOM_NFC_EMU_MFUL_PAGE_COUNT_215 + 1U))
        {
            effective_pages = POOM_NFC_EMU_MFUL_PAGE_COUNT_215;
        }
        else if(pages_total == (POOM_NFC_EMU_MFUL_PAGE_COUNT_216 + 1U))
        {
            effective_pages = POOM_NFC_EMU_MFUL_PAGE_COUNT_216;
        }
    }
    if((effective_pages == 0U) && pages_read_set &&
       ((pages_read == POOM_NFC_EMU_MFUL_PAGE_COUNT_213) ||
        (pages_read == POOM_NFC_EMU_MFUL_PAGE_COUNT_215) ||
        (pages_read == POOM_NFC_EMU_MFUL_PAGE_COUNT_216)))
    {
        effective_pages = pages_read;
    }
    if((effective_pages == 0U) && (device_type_pages != 0U))
    {
        effective_pages = device_type_pages;
    }
    if((effective_pages == 0U) && version_set)
    {
        effective_pages = poom_nfc_emu_pages_from_version_(version);
    }
    if(effective_pages == 0U)
    {
        if(max_page_seen < POOM_NFC_EMU_MFUL_PAGE_COUNT_213)
        {
            effective_pages = POOM_NFC_EMU_MFUL_PAGE_COUNT_213;
        }
        else if(max_page_seen < POOM_NFC_EMU_MFUL_PAGE_COUNT_215)
        {
            effective_pages = POOM_NFC_EMU_MFUL_PAGE_COUNT_215;
        }
        else
        {
            effective_pages = POOM_NFC_EMU_MFUL_PAGE_COUNT_216;
        }
    }
    if((effective_pages != POOM_NFC_EMU_MFUL_PAGE_COUNT_213) &&
       (effective_pages != POOM_NFC_EMU_MFUL_PAGE_COUNT_215) &&
       (effective_pages != POOM_NFC_EMU_MFUL_PAGE_COUNT_216))
    {
        return false;
    }
    if(max_page_seen >= effective_pages)
    {
        if(max_page_seen == effective_pages)
        {
            page_seen[max_page_seen] = false;
            while((max_page_seen > 0U) && !page_seen[max_page_seen])
            {
                max_page_seen--;
            }
        }
        else
        {
            return false;
        }
    }
    if(max_page_seen >= effective_pages)
    {
        return false;
    }

    poom_nfc_emu_mful_apply_variant_(effective_pages);
    (void)memset(s_emu.mful_image, 0, sizeof(s_emu.mful_image));

    for(uint16_t page = 0U; page < effective_pages; page++)
    {
        if(page_seen[page])
        {
            (void)memcpy(&s_emu.mful_image[page * POOM_NFC_EMU_MFUL_PAGE_SIZE],
                         &page_data[page * POOM_NFC_EMU_MFUL_PAGE_SIZE],
                         POOM_NFC_EMU_MFUL_PAGE_SIZE);
        }
    }

    if(signature_set)
    {
        (void)memcpy(s_emu.mful_signature, signature, sizeof(s_emu.mful_signature));
    }
    if(version_set)
    {
        (void)memcpy(s_emu.mful_version, version, sizeof(s_emu.mful_version));
    }

    if(uid_set)
    {
        (void)memset(s_emu.cfg.uid, 0, sizeof(s_emu.cfg.uid));
        (void)memcpy(s_emu.cfg.uid, uid, uid_len);
        s_emu.cfg.uid_len = (uint8_t)uid_len;
    }
    if(atqa_set)
    {
        s_emu.cfg.atqa[0] = atqa[0];
        s_emu.cfg.atqa[1] = atqa[1];
        s_emu.cfg.atqa_set = true;
    }
    if(sak_set)
    {
        s_emu.cfg.sak = sak;
        s_emu.cfg.sak_set = true;
    }

    poom_nfc_emu_mful_rebuild_rollover();
    s_emu.mful_cwrite_page_set = 0U;
    s_emu.mful_auth_ok = false;
    return true;
}

/**
 * @brief Loads internal data used by this module.
 *
 * @param[in] path Parameter passed to the function.
 * @return bool
 */
static bool poom_nfc_emu_load_mful_image_file(const char* path)
{
    FILE* f;
    long sz;
    size_t rd;
    bool ok = false;
    esp_err_t sd_err;

    if(path == NULL || path[0] == '\0')
    {
        return false;
    }

    if(sd_card_is_not_mounted())
    {
        sd_err = sd_card_mount();
        if(sd_err != ESP_OK)
        {
            printf("  nfc-emul: sd mount failed err=%d\r\n", (int)sd_err);
            return false;
        }
    }

    f = fopen(path, "rb");
    if(f == NULL)
    {
        printf("  nfc-emul: fopen failed (%s)\r\n", path);
        return false;
    }

    if(poom_nfc_emu_path_has_ext_(path, ".nfc"))
    {
        ok = poom_nfc_emu_load_mful_flipper_nfc_(f);
        (void)fclose(f);
        if(!ok)
        {
            printf("  nfc-emul: invalid Flipper .nfc MFUL image (%s)\r\n", path);
        }
        return ok;
    }

    if(fseek(f, 0, SEEK_END) != 0)
    {
        fclose(f);
        return false;
    }
    sz = ftell(f);
    if(sz < 0)
    {
        fclose(f);
        return false;
    }
    if(fseek(f, 0, SEEK_SET) != 0)
    {
        fclose(f);
        return false;
    }

    poom_nfc_emu_reset_mful_image();
    if(sz == 64L)
    {
        rd = fread(s_emu.mful_image, 1, 64U, f);
        ok = (rd == 64U);
    }
    else if(sz == (long)POOM_NFC_EMU_MFUL_DATA_LEN_213)
    {
        poom_nfc_emu_mful_apply_variant_(POOM_NFC_EMU_MFUL_PAGE_COUNT_213);
        rd = fread(s_emu.mful_image, 1, POOM_NFC_EMU_MFUL_DATA_LEN_213, f);
        ok = (rd == POOM_NFC_EMU_MFUL_DATA_LEN_213);
    }
    else if(sz == (long)(POOM_NFC_EMU_MFUL_DATA_LEN_213 + POOM_NFC_EMU_MFUL_PAGE_SIZE))
    {
        poom_nfc_emu_mful_apply_variant_(POOM_NFC_EMU_MFUL_PAGE_COUNT_213);
        rd = fread(s_emu.mful_image, 1, POOM_NFC_EMU_MFUL_DATA_LEN_213, f);
        ok = (rd == POOM_NFC_EMU_MFUL_DATA_LEN_213);
        if(ok)
        {
            printf("  nfc-emul: trimming trailing extra page from MFUL image (%ld -> %u).\r\n",
                   sz, (unsigned)POOM_NFC_EMU_MFUL_DATA_LEN_213);
        }
    }
    else if(sz == (long)(POOM_NFC_EMU_MFUL_DATA_LEN_213 + POOM_NFC_EMU_MFUL_READ_SIG_RSP_LEN))
    {
        poom_nfc_emu_mful_apply_variant_(POOM_NFC_EMU_MFUL_PAGE_COUNT_213);
        rd = fread(s_emu.mful_image, 1, POOM_NFC_EMU_MFUL_DATA_LEN_213, f);
        if(rd == POOM_NFC_EMU_MFUL_DATA_LEN_213)
        {
            rd = fread(s_emu.mful_signature, 1, POOM_NFC_EMU_MFUL_READ_SIG_RSP_LEN, f);
            ok = (rd == POOM_NFC_EMU_MFUL_READ_SIG_RSP_LEN);
        }
    }
    else if(sz == (long)(POOM_NFC_EMU_MFUL_DATA_LEN_213 + POOM_NFC_EMU_MFUL_READ_SIG_RSP_LEN +
                         POOM_NFC_EMU_MFUL_PAGE_SIZE))
    {
        poom_nfc_emu_mful_apply_variant_(POOM_NFC_EMU_MFUL_PAGE_COUNT_213);
        rd = fread(s_emu.mful_image, 1, POOM_NFC_EMU_MFUL_DATA_LEN_213, f);
        if(rd == POOM_NFC_EMU_MFUL_DATA_LEN_213)
        {
            (void)fseek(f, (long)POOM_NFC_EMU_MFUL_PAGE_SIZE, SEEK_CUR);
            rd = fread(s_emu.mful_signature, 1, POOM_NFC_EMU_MFUL_READ_SIG_RSP_LEN, f);
            ok = (rd == POOM_NFC_EMU_MFUL_READ_SIG_RSP_LEN);
        }
        if(ok)
        {
            printf("  nfc-emul: trimming trailing extra page from MFUL image (%ld -> %u+sig).\r\n",
                   sz, (unsigned)POOM_NFC_EMU_MFUL_DATA_LEN_213);
        }
    }
    else if(sz == (long)POOM_NFC_EMU_MFUL_DATA_LEN_215)
    {
        poom_nfc_emu_mful_apply_variant_(POOM_NFC_EMU_MFUL_PAGE_COUNT_215);
        rd = fread(s_emu.mful_image, 1, POOM_NFC_EMU_MFUL_DATA_LEN_215, f);
        ok = (rd == POOM_NFC_EMU_MFUL_DATA_LEN_215);
    }
    else if(sz == (long)(POOM_NFC_EMU_MFUL_DATA_LEN_215 + POOM_NFC_EMU_MFUL_PAGE_SIZE))
    {
        poom_nfc_emu_mful_apply_variant_(POOM_NFC_EMU_MFUL_PAGE_COUNT_215);
        rd = fread(s_emu.mful_image, 1, POOM_NFC_EMU_MFUL_DATA_LEN_215, f);
        ok = (rd == POOM_NFC_EMU_MFUL_DATA_LEN_215);
        if(ok)
        {
            printf("  nfc-emul: trimming trailing extra page from MFUL image (%ld -> %u).\r\n",
                   sz, (unsigned)POOM_NFC_EMU_MFUL_DATA_LEN_215);
        }
    }
    else if(sz == (long)(POOM_NFC_EMU_MFUL_DATA_LEN_215 + POOM_NFC_EMU_MFUL_READ_SIG_RSP_LEN))
    {
        poom_nfc_emu_mful_apply_variant_(POOM_NFC_EMU_MFUL_PAGE_COUNT_215);
        rd = fread(s_emu.mful_image, 1, POOM_NFC_EMU_MFUL_DATA_LEN_215, f);
        if(rd == POOM_NFC_EMU_MFUL_DATA_LEN_215)
        {
            rd = fread(s_emu.mful_signature, 1, POOM_NFC_EMU_MFUL_READ_SIG_RSP_LEN, f);
            ok = (rd == POOM_NFC_EMU_MFUL_READ_SIG_RSP_LEN);
        }
    }
    else if(sz == (long)(POOM_NFC_EMU_MFUL_DATA_LEN_215 + POOM_NFC_EMU_MFUL_READ_SIG_RSP_LEN +
                         POOM_NFC_EMU_MFUL_PAGE_SIZE))
    {
        poom_nfc_emu_mful_apply_variant_(POOM_NFC_EMU_MFUL_PAGE_COUNT_215);
        rd = fread(s_emu.mful_image, 1, POOM_NFC_EMU_MFUL_DATA_LEN_215, f);
        if(rd == POOM_NFC_EMU_MFUL_DATA_LEN_215)
        {
            (void)fseek(f, (long)POOM_NFC_EMU_MFUL_PAGE_SIZE, SEEK_CUR);
            rd = fread(s_emu.mful_signature, 1, POOM_NFC_EMU_MFUL_READ_SIG_RSP_LEN, f);
            ok = (rd == POOM_NFC_EMU_MFUL_READ_SIG_RSP_LEN);
        }
        if(ok)
        {
            printf("  nfc-emul: trimming trailing extra page from MFUL image (%ld -> %u+sig).\r\n",
                   sz, (unsigned)POOM_NFC_EMU_MFUL_DATA_LEN_215);
        }
    }
    else if(sz == (long)POOM_NFC_EMU_MFUL_DATA_LEN_216)
    {
        poom_nfc_emu_mful_apply_variant_(POOM_NFC_EMU_MFUL_PAGE_COUNT_216);
        rd = fread(s_emu.mful_image, 1, POOM_NFC_EMU_MFUL_DATA_LEN_216, f);
        ok = (rd == POOM_NFC_EMU_MFUL_DATA_LEN_216);
    }
    else if(sz == (long)(POOM_NFC_EMU_MFUL_DATA_LEN_216 + POOM_NFC_EMU_MFUL_PAGE_SIZE))
    {
        poom_nfc_emu_mful_apply_variant_(POOM_NFC_EMU_MFUL_PAGE_COUNT_216);
        rd = fread(s_emu.mful_image, 1, POOM_NFC_EMU_MFUL_DATA_LEN_216, f);
        ok = (rd == POOM_NFC_EMU_MFUL_DATA_LEN_216);
        if(ok)
        {
            printf("  nfc-emul: trimming trailing extra page from MFUL image (%ld -> %u).\r\n",
                   sz, (unsigned)POOM_NFC_EMU_MFUL_DATA_LEN_216);
        }
    }
    else if(sz == (long)(POOM_NFC_EMU_MFUL_DATA_LEN_216 + POOM_NFC_EMU_MFUL_READ_SIG_RSP_LEN))
    {
        poom_nfc_emu_mful_apply_variant_(POOM_NFC_EMU_MFUL_PAGE_COUNT_216);
        rd = fread(s_emu.mful_image, 1, POOM_NFC_EMU_MFUL_DATA_LEN_216, f);
        if(rd == POOM_NFC_EMU_MFUL_DATA_LEN_216)
        {
            rd = fread(s_emu.mful_signature, 1, POOM_NFC_EMU_MFUL_READ_SIG_RSP_LEN, f);
            ok = (rd == POOM_NFC_EMU_MFUL_READ_SIG_RSP_LEN);
        }
    }
    else if(sz == (long)(POOM_NFC_EMU_MFUL_DATA_LEN_216 + POOM_NFC_EMU_MFUL_READ_SIG_RSP_LEN +
                         POOM_NFC_EMU_MFUL_PAGE_SIZE))
    {
        poom_nfc_emu_mful_apply_variant_(POOM_NFC_EMU_MFUL_PAGE_COUNT_216);
        rd = fread(s_emu.mful_image, 1, POOM_NFC_EMU_MFUL_DATA_LEN_216, f);
        if(rd == POOM_NFC_EMU_MFUL_DATA_LEN_216)
        {
            (void)fseek(f, (long)POOM_NFC_EMU_MFUL_PAGE_SIZE, SEEK_CUR);
            rd = fread(s_emu.mful_signature, 1, POOM_NFC_EMU_MFUL_READ_SIG_RSP_LEN, f);
            ok = (rd == POOM_NFC_EMU_MFUL_READ_SIG_RSP_LEN);
        }
        if(ok)
        {
            printf("  nfc-emul: trimming trailing extra page from MFUL image (%ld -> %u+sig).\r\n",
                   sz, (unsigned)POOM_NFC_EMU_MFUL_DATA_LEN_216);
        }
    }
    else
    {
        printf("  nfc-emul: invalid image size (%ld). Expected 64, %u, %u, %u, %u, %u, %u, %u, %u, %u, %u, %u or %u bytes.\r\n",
               sz,
               (unsigned)POOM_NFC_EMU_MFUL_DATA_LEN_213,
               (unsigned)(POOM_NFC_EMU_MFUL_DATA_LEN_213 + POOM_NFC_EMU_MFUL_PAGE_SIZE),
               (unsigned)(POOM_NFC_EMU_MFUL_DATA_LEN_213 + POOM_NFC_EMU_MFUL_READ_SIG_RSP_LEN),
               (unsigned)(POOM_NFC_EMU_MFUL_DATA_LEN_213 + POOM_NFC_EMU_MFUL_READ_SIG_RSP_LEN +
                          POOM_NFC_EMU_MFUL_PAGE_SIZE),
               (unsigned)POOM_NFC_EMU_MFUL_DATA_LEN_215,
               (unsigned)(POOM_NFC_EMU_MFUL_DATA_LEN_215 + POOM_NFC_EMU_MFUL_PAGE_SIZE),
               (unsigned)(POOM_NFC_EMU_MFUL_DATA_LEN_215 + POOM_NFC_EMU_MFUL_READ_SIG_RSP_LEN),
               (unsigned)(POOM_NFC_EMU_MFUL_DATA_LEN_215 + POOM_NFC_EMU_MFUL_READ_SIG_RSP_LEN +
                          POOM_NFC_EMU_MFUL_PAGE_SIZE),
               (unsigned)POOM_NFC_EMU_MFUL_DATA_LEN_216,
               (unsigned)(POOM_NFC_EMU_MFUL_DATA_LEN_216 + POOM_NFC_EMU_MFUL_PAGE_SIZE),
               (unsigned)(POOM_NFC_EMU_MFUL_DATA_LEN_216 + POOM_NFC_EMU_MFUL_READ_SIG_RSP_LEN),
               (unsigned)(POOM_NFC_EMU_MFUL_DATA_LEN_216 + POOM_NFC_EMU_MFUL_READ_SIG_RSP_LEN +
                          POOM_NFC_EMU_MFUL_PAGE_SIZE));
        ok = false;
    }

    fclose(f);
    if(!ok)
    {
        return false;
    }

    poom_nfc_emu_mful_rebuild_rollover();
    s_emu.mful_cwrite_page_set = 0;
    return true;
}

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
static void poom_nfc_emu_rebuild_cc_file(void)
{
    const uint16_t ndef_size =
        (s_emu.file_size[POOM_NFC_EMU_FILE_IDX_NDEF] > 0xFFFFU) ? 0xFFFFU
                                                                 : (uint16_t)s_emu.file_size[POOM_NFC_EMU_FILE_IDX_NDEF];

    memcpy(s_emu.cc_file, s_cc_file_template, sizeof(s_emu.cc_file));
    s_emu.cc_file[POOM_NFC_EMU_CC_NDEF_MSB_IDX] = (uint8_t)(ndef_size >> 8);
    s_emu.cc_file[POOM_NFC_EMU_CC_NDEF_LSB_IDX] = (uint8_t)(ndef_size & 0xFFU);
}

/**
 * @brief Builds the default configuration used by this module.
 *
 * @return void
 */
static void poom_nfc_emu_build_default_ndef(void)
{
    const char* uri = s_emu.cfg.uri_set ? s_emu.cfg.uri : POOM_NFC_EMU_DEFAULT_URI;
    size_t uri_len  = strlen(uri);
    size_t payload_len;
    size_t rec_len;
    uint8_t* p;

    if(uri_len > POOM_NFC_EMU_URI_MAX_LEN)
    {
        uri_len = POOM_NFC_EMU_URI_MAX_LEN;
    }

    payload_len = 1U + uri_len;                              /* URI identifier + URI text */
    rec_len     = POOM_NFC_EMU_NDEF_REC_MIN_LEN + uri_len; /* D1 01 PL 55 00 + text */
    if((POOM_NFC_EMU_NDEF_HDR_LEN + rec_len) > sizeof(s_emu.ndef_file))
    {
        rec_len = sizeof(s_emu.ndef_file) - POOM_NFC_EMU_NDEF_HDR_LEN;
        if(rec_len < POOM_NFC_EMU_NDEF_REC_MIN_LEN)
        {
            rec_len = POOM_NFC_EMU_NDEF_REC_MIN_LEN;
        }
        uri_len     = rec_len - POOM_NFC_EMU_NDEF_REC_MIN_LEN;
        payload_len = 1U + uri_len;
    }

    p    = s_emu.ndef_file;
    p[0] = (uint8_t)(rec_len >> 8);
    p[1] = (uint8_t)(rec_len & 0xFFU);
    p[2] = POOM_NFC_EMU_NDEF_MB_ME_SR_TNF_WELLKNOWN;
    p[3] = POOM_NFC_EMU_NDEF_TYPE_LEN_URI;
    p[4] = (uint8_t)payload_len;
    p[5] = POOM_NFC_EMU_NDEF_URI_TYPE;
    p[6] = POOM_NFC_EMU_NDEF_URI_PREFIX_NONE; /* URI prefix: none */
    memcpy(&p[7], uri, uri_len);

    s_emu.file_size[POOM_NFC_EMU_FILE_IDX_CC]   = sizeof(s_emu.cc_file);
    s_emu.file_size[POOM_NFC_EMU_FILE_IDX_NDEF] = (uint32_t)(POOM_NFC_EMU_NDEF_HDR_LEN + rec_len);
    poom_nfc_emu_rebuild_cc_file();
}

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
    s_emu.t4t_state        = POOM_T4T_STATE_IDLE;
    s_emu.t4t_selected_idx = POOM_NFC_EMU_FILE_NONE;
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
static uint16_t poom_nfc_emu_put_sw(uint8_t* rsp, uint16_t rsp_max, uint8_t sw1, uint8_t sw2)
{
    if(rsp == NULL || rsp_max < POOM_NFC_EMU_APDU_SW_LEN)
    {
        return 0;
    }
    rsp[0] = sw1;
    rsp[1] = sw2;
    return POOM_NFC_EMU_APDU_SW_LEN;
}

/**
 * @brief Internal helper for `poom_nfc_emu_mful_is_user_page`.
 *
 * @param[in] page Parameter passed to the function.
 * @return bool
 */
static bool poom_nfc_emu_mful_is_user_page(uint8_t page)
{
    return (page >= POOM_NFC_EMU_MFUL_PAGE_USER_FIRST && page <= s_emu.mful_page_user_last);
}

/**
 * @brief Internal helper for `poom_nfc_emu_mful_or_lock_bytes`.
 *
 * @param[in] src Parameter passed to the function.
 * @param[in] src_offset Parameter passed to the function.
 * @return void
 */
static void poom_nfc_emu_mful_or_lock_bytes(const uint8_t* src, uint8_t src_offset)
{
    uint8_t i;

    for(i = 0; i < POOM_NFC_EMU_MFUL_LOCK_BYTES; i++)
    {
        s_emu.mful_image[POOM_NFC_EMU_MFUL_LOCK_OFFSET + i] |= src[src_offset + i];
    }
}

/**
 * @brief Internal helper for `poom_nfc_emu_mful_or_otp_page`.
 *
 * @param[in] src Parameter passed to the function.
 * @param[in] src_offset Parameter passed to the function.
 * @return void
 */
static void poom_nfc_emu_mful_or_otp_page(const uint8_t* src, uint8_t src_offset)
{
    uint8_t i;
    const uint16_t base = (uint16_t)POOM_NFC_EMU_MFUL_PAGE_OTP * POOM_NFC_EMU_MFUL_PAGE_SIZE;
    for(i = 0; i < POOM_NFC_EMU_MFUL_PAGE_SIZE; i++)
    {
        s_emu.mful_image[base + i] |= src[src_offset + i];
    }
}

/**
 * @brief Internal helper for `poom_nfc_emu_mful_auth_required_for_page`.
 *
 * @param[in] page Parameter passed to the function.
 * @param[in] for_write Parameter passed to the function.
 * @return bool
 */
static bool poom_nfc_emu_mful_auth_required_for_page(uint8_t page, bool for_write)
{
    const uint16_t cfg0_base = (uint16_t)s_emu.mful_cfg0_page * POOM_NFC_EMU_MFUL_PAGE_SIZE;
    const uint16_t cfg1_base = (uint16_t)s_emu.mful_cfg1_page * POOM_NFC_EMU_MFUL_PAGE_SIZE;
    const uint8_t auth0 = s_emu.mful_image[cfg0_base + 3U];
    const uint8_t access = s_emu.mful_image[cfg1_base + 0U];
    const bool prot_rw = (access & 0x80U) != 0U;

    if(auth0 > s_emu.mful_page_last)
    {
        return false;
    }
    if(page < auth0)
    {
        return false;
    }
    if(for_write)
    {
        return true;
    }
    return prot_rw;
}

/**
 * @brief Internal helper for `poom_nfc_emu_mful_read_protected_active`.
 *
 * @param[in] out_auth0 Parameter passed to the function.
 * @return bool
 */
static bool poom_nfc_emu_mful_read_protected_active_(uint8_t* out_auth0)
{
    const uint16_t cfg0_base = (uint16_t)s_emu.mful_cfg0_page * POOM_NFC_EMU_MFUL_PAGE_SIZE;
    const uint16_t cfg1_base = (uint16_t)s_emu.mful_cfg1_page * POOM_NFC_EMU_MFUL_PAGE_SIZE;
    const uint8_t auth0 = s_emu.mful_image[cfg0_base + 3U];
    const uint8_t access = s_emu.mful_image[cfg1_base + 0U];
    const bool prot_rw = (access & 0x80U) != 0U;

    if(out_auth0 != NULL)
    {
        *out_auth0 = auth0;
    }

    if(!prot_rw)
    {
        return false;
    }
    if(auth0 > s_emu.mful_page_last)
    {
        return false;
    }
    return true;
}

/**
 * @brief Internal helper for `poom_nfc_emu_mful_writeable_cfg_page`.
 *
 * @param[in] page Parameter passed to the function.
 * @return bool
 */
static bool poom_nfc_emu_mful_writeable_cfg_page(uint8_t page)
{
    return (page == s_emu.mful_dyn_lock_page) || (page == s_emu.mful_cfg0_page) ||
           (page == s_emu.mful_cfg1_page) || (page == s_emu.mful_pwd_page) ||
           (page == s_emu.mful_pack_page);
}

/**
 * @brief Internal helper for `poom_nfc_emu_mful_mask_secret_pages`.
 *
 * @param[in] start_page Parameter passed to the function.
 * @param[in] dst Parameter passed to the function.
 * @param[in] len Parameter passed to the function.
 * @return void
 */
static void poom_nfc_emu_mful_mask_secret_pages(uint8_t start_page, uint8_t* dst, uint16_t len)
{
    uint16_t i;

    if((dst == NULL) || (len == 0U))
    {
        return;
    }

    for(i = 0U; i < len; i++)
    {
        const uint8_t page = (uint8_t)(start_page + (uint8_t)(i / POOM_NFC_EMU_MFUL_PAGE_SIZE));
        if((page == s_emu.mful_pwd_page) || (page == s_emu.mful_pack_page))
        {
            dst[i] = 0x00U;
        }
    }
}

/**
 * @brief Internal helper for `poom_nfc_emu_cmd_find`.
 *
 * @param[in] cmd Parameter passed to the function.
 * @param[in] cmd_len Parameter passed to the function.
 * @param[in] needle Parameter passed to the function.
 * @param[in] needle_len Parameter passed to the function.
 * @return bool
 */
static bool poom_nfc_emu_cmd_find(const uint8_t* cmd,
                                  uint16_t cmd_len,
                                  const uint8_t* needle,
                                  uint16_t needle_len)
{
    uint16_t lim;
    uint16_t i;

    if(cmd == NULL || needle == NULL || cmd_len == 0 || needle_len == 0)
    {
        return false;
    }

    if(needle_len > cmd_len)
    {
        return false;
    }

    lim = (cmd_len > POOM_NFC_EMU_CMD_FIND_LIMIT) ? POOM_NFC_EMU_CMD_FIND_LIMIT : cmd_len;
    if(needle_len > lim)
    {
        return false;
    }

    for(i = 0; (uint16_t)(i + needle_len) <= lim; i++)
    {
        if(memcmp(&cmd[i], needle, needle_len) == 0)
        {
            return true;
        }
    }
    return false;
}

/**
 * @brief Internal helper for `poom_nfc_emu_t4_select`.
 *
 * @param[in] cmd Parameter passed to the function.
 * @param[in] cmd_len Parameter passed to the function.
 * @param[in] rsp Parameter passed to the function.
 * @param[in] rsp_max Parameter passed to the function.
 * @return uint16_t
 */
static uint16_t poom_nfc_emu_t4_select(const uint8_t* cmd,
                                       uint16_t cmd_len,
                                       uint8_t* rsp,
                                       uint16_t rsp_max)
{
    static const uint8_t aid[] = {0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01};
    const uint8_t fid_cc[] = {POOM_NFC_EMU_FID_CC_H, POOM_NFC_EMU_FID_CC_L};
    const uint8_t fid_ndef[] = {POOM_NFC_EMU_FID_NDEF_H, POOM_NFC_EMU_FID_NDEF_L};
    static const uint8_t select_file_id[] = {0xA4, 0x00, 0x0C, 0x02, 0x00, 0x01};
    bool ok = false;

    (void)cmd_len;
    if(rsp_max < POOM_NFC_EMU_APDU_SW_LEN)
        return 0;

    if(poom_nfc_emu_cmd_find(cmd, cmd_len, aid, sizeof(aid)))
    {
        s_emu.t4t_state = POOM_T4T_STATE_APP_SELECTED;
        ok              = true;
    }
    else if((s_emu.t4t_state >= POOM_T4T_STATE_APP_SELECTED) &&
            poom_nfc_emu_cmd_find(cmd, cmd_len, fid_cc, sizeof(fid_cc)))
    {
        s_emu.t4t_state        = POOM_T4T_STATE_CC_SELECTED;
        s_emu.t4t_selected_idx = POOM_NFC_EMU_FILE_IDX_CC;
        ok                     = true;
    }
    else if((s_emu.t4t_state >= POOM_T4T_STATE_APP_SELECTED) &&
            (poom_nfc_emu_cmd_find(cmd, cmd_len, fid_ndef, sizeof(fid_ndef)) ||
             poom_nfc_emu_cmd_find(cmd, cmd_len, select_file_id,
                                   sizeof(select_file_id))))
    {
        s_emu.t4t_state        = POOM_T4T_STATE_FID_SELECTED;
        s_emu.t4t_selected_idx = POOM_NFC_EMU_FILE_IDX_NDEF;
        ok                     = true;
    }
    else
    {
        s_emu.t4t_state        = POOM_T4T_STATE_IDLE;
        s_emu.t4t_selected_idx = POOM_NFC_EMU_FILE_NONE;
    }

    return ok ? poom_nfc_emu_put_sw(rsp, rsp_max, POOM_NFC_EMU_SW1_OK, POOM_NFC_EMU_SW2_OK)
              : poom_nfc_emu_put_sw(rsp, rsp_max, POOM_NFC_EMU_SW1_NOT_FOUND,
                                    POOM_NFC_EMU_SW2_NOT_FOUND);
}

/**
 * @brief Internal helper for `poom_nfc_emu_t4_read`.
 *
 * @param[in] cmd Parameter passed to the function.
 * @param[in] cmd_len Parameter passed to the function.
 * @param[in] rsp Parameter passed to the function.
 * @param[in] rsp_max Parameter passed to the function.
 * @return uint16_t
 */
static uint16_t poom_nfc_emu_t4_read(const uint8_t* cmd,
                                     uint16_t cmd_len,
                                     uint8_t* rsp,
                                     uint16_t rsp_max)
{
    uint16_t offset;
    uint16_t to_read;
    const uint8_t* src;
    uint32_t file_len;

    if(cmd_len < POOM_NFC_EMU_APDU_MIN_LEN || rsp_max < POOM_NFC_EMU_APDU_SW_LEN)
    {
        return 0;
    }
    if(s_emu.t4t_selected_idx < 0 || s_emu.t4t_selected_idx >= POOM_NFC_EMU_FILE_COUNT)
    {
        return poom_nfc_emu_put_sw(rsp, rsp_max, POOM_NFC_EMU_SW1_NOT_FOUND,
                                   POOM_NFC_EMU_SW2_NOT_FOUND);
    }

    offset = (uint16_t)(((uint16_t)cmd[2] << 8) | cmd[3]);
    to_read = cmd[4];

    file_len = s_emu.file_size[s_emu.t4t_selected_idx];
    if(offset >= file_len)
    {
        to_read = 0;
    }
    else if(((uint32_t)offset + (uint32_t)to_read) > file_len)
    {
        to_read = (uint16_t)(file_len - offset);
    }

    if(((uint32_t)to_read + POOM_NFC_EMU_APDU_SW_LEN) > rsp_max)
    {
        return poom_nfc_emu_put_sw(rsp, rsp_max, POOM_NFC_EMU_SW1_TECHNICAL,
                                   POOM_NFC_EMU_SW2_OK);
    }

    src = (s_emu.t4t_selected_idx == POOM_NFC_EMU_FILE_IDX_CC) ? s_emu.cc_file : s_emu.ndef_file;
    if(to_read > 0U)
    {
        memcpy(rsp, &src[offset], to_read);
    }
    rsp[to_read]     = POOM_NFC_EMU_SW1_OK;
    rsp[to_read + 1] = POOM_NFC_EMU_SW2_OK;
    return (uint16_t)(to_read + POOM_NFC_EMU_APDU_SW_LEN);
}

/**
 * @brief Internal helper for `poom_nfc_emu_t4_update`.
 *
 * @param[in] cmd Parameter passed to the function.
 * @param[in] cmd_len Parameter passed to the function.
 * @param[in] rsp Parameter passed to the function.
 * @param[in] rsp_max Parameter passed to the function.
 * @return uint16_t
 */
static uint16_t poom_nfc_emu_t4_update(const uint8_t* cmd,
                                       uint16_t cmd_len,
                                       uint8_t* rsp,
                                       uint16_t rsp_max)
{
    uint16_t offset;
    uint16_t length;

    if(cmd_len < POOM_NFC_EMU_APDU_MIN_LEN || rsp_max < POOM_NFC_EMU_APDU_SW_LEN)
    {
        return 0;
    }
    if(s_emu.t4t_selected_idx != POOM_NFC_EMU_FILE_IDX_NDEF)
    {
        return poom_nfc_emu_put_sw(rsp, rsp_max, POOM_NFC_EMU_SW1_NOT_FOUND,
                                   POOM_NFC_EMU_SW2_NOT_FOUND);
    }

    offset = (uint16_t)(((uint16_t)cmd[2] << 8) | cmd[3]);
    length = cmd[4];

    if((uint16_t)(POOM_NFC_EMU_APDU_MIN_LEN + length) > cmd_len)
    {
        return poom_nfc_emu_put_sw(rsp, rsp_max, POOM_NFC_EMU_SW1_WRONG_LEN,
                                   POOM_NFC_EMU_SW2_OK);
    }
    if(((uint32_t)offset + (uint32_t)length) > s_emu.file_size[POOM_NFC_EMU_FILE_IDX_NDEF])
    {
        return poom_nfc_emu_put_sw(rsp, rsp_max, POOM_NFC_EMU_SW1_WARN,
                                   POOM_NFC_EMU_SW2_NOT_FOUND);
    }

    memcpy(&s_emu.ndef_file[offset], &cmd[5], length);
    return poom_nfc_emu_put_sw(rsp, rsp_max, POOM_NFC_EMU_SW1_OK, POOM_NFC_EMU_SW2_OK);
}

/**
 * @brief Internal helper for `poom_nfc_emu_process_t4t`.
 *
 * @param[in] cmd Parameter passed to the function.
 * @param[in] cmd_len Parameter passed to the function.
 * @param[in] rsp Parameter passed to the function.
 * @param[in] rsp_max Parameter passed to the function.
 * @return uint16_t
 */
static uint16_t poom_nfc_emu_process_t4t(const uint8_t* cmd,
                                         uint16_t cmd_len,
                                         uint8_t* rsp,
                                         uint16_t rsp_max)
{
    if(cmd == NULL || rsp == NULL || cmd_len < POOM_NFC_EMU_APDU_SW_LEN ||
       rsp_max < POOM_NFC_EMU_APDU_SW_LEN)
    {
        return 0;
    }

    if(cmd[0] == POOM_NFC_EMU_T4T_CLA_00)
    {
        switch(cmd[1])
        {
            case POOM_NFC_EMU_T4T_INS_SELECT:
                return poom_nfc_emu_t4_select(cmd, cmd_len, rsp, rsp_max);
            case POOM_NFC_EMU_T4T_INS_READ:
                return poom_nfc_emu_t4_read(cmd, cmd_len, rsp, rsp_max);
            case POOM_NFC_EMU_T4T_INS_UPDATE:
                return poom_nfc_emu_t4_update(cmd, cmd_len, rsp, rsp_max);
            default:
                break;
        }
    }

    return poom_nfc_emu_put_sw(rsp, rsp_max, POOM_NFC_EMU_SW1_FUNC_NOT_SUPP,
                               POOM_NFC_EMU_SW2_OK);
}

/**
 * @brief Internal helper for `poom_nfc_emu_process_mful`.
 *
 * @param[in] cmd Parameter passed to the function.
 * @param[in] cmd_len Parameter passed to the function.
 * @param[in] rsp Parameter passed to the function.
 * @param[in] rsp_max Parameter passed to the function.
 * @param[in] card_reset Parameter passed to the function.
 * @return uint16_t
 */
static uint16_t poom_nfc_emu_process_mful(const uint8_t* cmd,
                                          uint16_t cmd_len,
                                          uint8_t* rsp,
                                          uint16_t rsp_max,
                                          bool* card_reset)
{
    uint8_t ul_addr = 0;
    uint8_t ul_end = 0;
    uint8_t page_count = 0;
    uint16_t rsp_len = 0;
    uint16_t i;
    uint32_t ctr;
    uint16_t pwd_base;
    uint16_t pack_base;
    bool cwrite_phase2 = false;

    if(card_reset != NULL)
    {
        *card_reset = false;
    }

    if(rsp == NULL || rsp_max == 0U || cmd == NULL || cmd_len == 0U)
    {
        return 0;
    }

    if(s_emu.mful_cwrite_page_set != 0U)
    {
        ul_addr = (uint8_t)(s_emu.mful_cwrite_page_set - 1U);
        s_emu.mful_cwrite_page_set = 0U;
        cwrite_phase2              = true;
    }

    esp_rom_delay_us(POOM_NFC_EMU_MFUL_RESET_DELAY_US);

    if(cmd_len == POOM_NFC_EMU_MFUL_READ_CMD_LEN && cmd[0] == POOM_NFC_EMU_MFUL_HALT_CMD &&
       cmd[1] == POOM_NFC_EMU_MFUL_HALT_ARG)
    {
        s_emu.mful_auth_ok = false;
        if(card_reset != NULL)
            *card_reset = true;
        return 0;
    }

    if(cmd[0] == POOM_NFC_EMU_CMD_UL_PWD_AUTH)
    {
        bool pwd_ok = false;
        const uint8_t* stored_pwd;

        if((cmd_len != POOM_NFC_EMU_MFUL_PWD_AUTH_CMD_LEN) ||
           (rsp_max < POOM_NFC_EMU_MFUL_PWD_AUTH_RSP_LEN))
        {
            rsp[0] = POOM_NFC_EMU_MIF_NAK;
            if(card_reset != NULL)
                *card_reset = true;
            return POOM_NFC_EMU_MFUL_ACK_BITS;
        }

        pwd_base = (uint16_t)s_emu.mful_pwd_page * POOM_NFC_EMU_MFUL_PAGE_SIZE;
        stored_pwd = &s_emu.mful_image[pwd_base];
        if(memcmp(&cmd[1], stored_pwd, POOM_NFC_EMU_MFUL_PAGE_SIZE) == 0)
        {
            pwd_ok = true;
        }
        else if((s_emu.cfg.uid_len == POOM_NFC_EMU_UID_LEN_7) &&
                poom_nfc_emu_mful_is_zero4_(stored_pwd))
        {
            uint8_t derived_pwd[4];
            poom_nfc_emu_mful_pwd_from_uid7_(s_emu.cfg.uid, derived_pwd);
            if(memcmp(&cmd[1], derived_pwd, sizeof(derived_pwd)) == 0)
            {
                pwd_ok = true;
            }
        }

        if(pwd_ok)
        {
            pack_base = (uint16_t)s_emu.mful_pack_page * POOM_NFC_EMU_MFUL_PAGE_SIZE;
            s_emu.mful_auth_ok = true;
            rsp[0] = s_emu.mful_image[pack_base + 0U];
            rsp[1] = s_emu.mful_image[pack_base + 1U];
            if((rsp[0] == 0x00U) && (rsp[1] == 0x00U))
            {
                rsp[0] = 0x80U;
                rsp[1] = 0x80U;
            }
            return rfalConvBytesToBits(POOM_NFC_EMU_MFUL_PWD_AUTH_RSP_LEN);
        }

        s_emu.mful_auth_ok = false;
        rsp[0] = POOM_NFC_EMU_MIF_NAK;
        return POOM_NFC_EMU_MFUL_ACK_BITS;
    }

    if(cwrite_phase2)
    {
        if(rsp_max < 1U)
            return 0;
        if(cmd_len != POOM_NFC_EMU_MFUL_CWRITE_PHASE2_LEN)
        {
            rsp[0] = POOM_NFC_EMU_MIF_NAK;
            if(card_reset != NULL)
                *card_reset = true;
            return POOM_NFC_EMU_MFUL_ACK_BITS;
        }
        if(poom_nfc_emu_mful_auth_required_for_page(ul_addr, true) && !s_emu.mful_auth_ok)
        {
            rsp[0] = POOM_NFC_EMU_MIF_NAK;
            return POOM_NFC_EMU_MFUL_ACK_BITS;
        }
        if(poom_nfc_emu_mful_is_user_page(ul_addr))
        {
            memcpy(&s_emu.mful_image[ul_addr * POOM_NFC_EMU_MFUL_PAGE_SIZE], cmd,
                   POOM_NFC_EMU_MFUL_PAGE_SIZE);
            poom_nfc_emu_mful_rebuild_rollover();
            rsp[0] = POOM_NFC_EMU_MIF_ACK;
            return POOM_NFC_EMU_MFUL_ACK_BITS;
        }
        if(ul_addr == POOM_NFC_EMU_MFUL_PAGE_LOCK)
        {
            poom_nfc_emu_mful_or_lock_bytes(cmd, 0U);
            poom_nfc_emu_mful_rebuild_rollover();
            rsp[0] = POOM_NFC_EMU_MIF_ACK;
            return POOM_NFC_EMU_MFUL_ACK_BITS;
        }
        if(ul_addr == POOM_NFC_EMU_MFUL_PAGE_OTP)
        {
            poom_nfc_emu_mful_or_otp_page(cmd, 0U);
            poom_nfc_emu_mful_rebuild_rollover();
            rsp[0] = POOM_NFC_EMU_MIF_ACK;
            return POOM_NFC_EMU_MFUL_ACK_BITS;
        }
        if(poom_nfc_emu_mful_writeable_cfg_page(ul_addr))
        {
            memcpy(&s_emu.mful_image[ul_addr * POOM_NFC_EMU_MFUL_PAGE_SIZE], cmd,
                   POOM_NFC_EMU_MFUL_PAGE_SIZE);
            poom_nfc_emu_mful_rebuild_rollover();
            rsp[0] = POOM_NFC_EMU_MIF_ACK;
            return POOM_NFC_EMU_MFUL_ACK_BITS;
        }

        rsp[0] = POOM_NFC_EMU_MIF_NAK;
        if(card_reset != NULL)
            *card_reset = true;
        return POOM_NFC_EMU_MFUL_ACK_BITS;
    }

    if(cmd[0] == POOM_NFC_EMU_CMD_UL_READ)
    {
        uint8_t auth0 = 0U;
        bool read_prot_active = false;

        if(cmd_len != POOM_NFC_EMU_MFUL_READ_CMD_LEN || rsp_max < POOM_NFC_EMU_MFUL_READ_RSP_LEN)
        {
            rsp[0] = POOM_NFC_EMU_MIF_NAK;
            if(card_reset != NULL)
                *card_reset = true;
            return POOM_NFC_EMU_MFUL_ACK_BITS;
        }
        ul_addr = cmd[1];
        if(ul_addr <= s_emu.mful_page_last)
        {
            read_prot_active = poom_nfc_emu_mful_read_protected_active_(&auth0);
            if(read_prot_active && !s_emu.mful_auth_ok)
            {
                if(ul_addr >= auth0)
                {
                    rsp[0] = POOM_NFC_EMU_MIF_NAK;
                    return POOM_NFC_EMU_MFUL_ACK_BITS;
                }

                for(i = 0U; i < POOM_NFC_EMU_MFUL_READ_RSP_LEN; i++)
                {
                    const uint8_t src_page = (uint8_t)((ul_addr + (uint8_t)(i / POOM_NFC_EMU_MFUL_PAGE_SIZE)) % auth0);
                    const uint8_t src_off = (uint8_t)(src_page * POOM_NFC_EMU_MFUL_PAGE_SIZE + (i % POOM_NFC_EMU_MFUL_PAGE_SIZE));
                    rsp[i] = s_emu.mful_image[src_off];
                }
                poom_nfc_emu_mful_mask_secret_pages(ul_addr, rsp, POOM_NFC_EMU_MFUL_READ_RSP_LEN);
                return rfalConvBytesToBits(POOM_NFC_EMU_MFUL_READ_RSP_LEN);
            }

            memcpy(rsp, &s_emu.mful_image[ul_addr * POOM_NFC_EMU_MFUL_PAGE_SIZE],
                   POOM_NFC_EMU_MFUL_READ_RSP_LEN);
            poom_nfc_emu_mful_mask_secret_pages(ul_addr, rsp, POOM_NFC_EMU_MFUL_READ_RSP_LEN);
            return rfalConvBytesToBits(POOM_NFC_EMU_MFUL_READ_RSP_LEN);
        }
        rsp[0] = POOM_NFC_EMU_MIF_NAK;
        if(card_reset != NULL)
            *card_reset = true;
        return POOM_NFC_EMU_MFUL_ACK_BITS;
    }

    if(cmd[0] == POOM_NFC_EMU_CMD_UL_FAST_READ)
    {
        uint8_t auth0 = 0U;
        bool read_prot_active = false;

        if(cmd_len != POOM_NFC_EMU_MFUL_FAST_READ_CMD_LEN)
        {
            rsp[0] = POOM_NFC_EMU_MIF_NAK;
            if(card_reset != NULL)
                *card_reset = true;
            return POOM_NFC_EMU_MFUL_ACK_BITS;
        }
        ul_addr = cmd[1];
        ul_end = cmd[2];
        if(ul_addr > s_emu.mful_page_last || ul_end > s_emu.mful_page_last ||
           ul_end < ul_addr)
        {
            rsp[0] = POOM_NFC_EMU_MIF_NAK;
            if(card_reset != NULL)
                *card_reset = true;
            return POOM_NFC_EMU_MFUL_ACK_BITS;
        }
        read_prot_active = poom_nfc_emu_mful_read_protected_active_(&auth0);
        if(read_prot_active && !s_emu.mful_auth_ok)
        {
            if(ul_end >= auth0)
            {
                rsp[0] = POOM_NFC_EMU_MIF_NAK;
                return POOM_NFC_EMU_MFUL_ACK_BITS;
            }
        }
        page_count = (uint8_t)(ul_end - ul_addr + 1U);
        rsp_len = (uint16_t)page_count * POOM_NFC_EMU_MFUL_PAGE_SIZE;
        if(rsp_len > rsp_max)
        {
            rsp[0] = POOM_NFC_EMU_MIF_NAK;
            if(card_reset != NULL)
                *card_reset = true;
            return POOM_NFC_EMU_MFUL_ACK_BITS;
        }
        memcpy(rsp, &s_emu.mful_image[ul_addr * POOM_NFC_EMU_MFUL_PAGE_SIZE], rsp_len);
        poom_nfc_emu_mful_mask_secret_pages(ul_addr, rsp, rsp_len);
        return rfalConvBytesToBits(rsp_len);
    }

    if(cmd[0] == POOM_NFC_EMU_CMD_UL_WRITE)
    {
        if(cmd_len != POOM_NFC_EMU_MFUL_WRITE_CMD_LEN || rsp_max < 1U)
        {
            rsp[0] = POOM_NFC_EMU_MIF_NAK;
            if(card_reset != NULL)
                *card_reset = true;
            return POOM_NFC_EMU_MFUL_ACK_BITS;
        }
        ul_addr = cmd[1];
        if(ul_addr > s_emu.mful_page_last)
        {
            rsp[0] = POOM_NFC_EMU_MIF_NAK;
            if(card_reset != NULL)
                *card_reset = true;
            return POOM_NFC_EMU_MFUL_ACK_BITS;
        }
        if(poom_nfc_emu_mful_auth_required_for_page(ul_addr, true) && !s_emu.mful_auth_ok)
        {
            rsp[0] = POOM_NFC_EMU_MIF_NAK;
            return POOM_NFC_EMU_MFUL_ACK_BITS;
        }
        if(poom_nfc_emu_mful_is_user_page(ul_addr))
        {
            memcpy(&s_emu.mful_image[ul_addr * POOM_NFC_EMU_MFUL_PAGE_SIZE], &cmd[2],
                   POOM_NFC_EMU_MFUL_PAGE_SIZE);
            poom_nfc_emu_mful_rebuild_rollover();
            rsp[0] = POOM_NFC_EMU_MIF_ACK;
            return POOM_NFC_EMU_MFUL_ACK_BITS;
        }
        if(ul_addr == POOM_NFC_EMU_MFUL_PAGE_LOCK)
        {
            poom_nfc_emu_mful_or_lock_bytes(cmd, 2U);
            poom_nfc_emu_mful_rebuild_rollover();
            rsp[0] = POOM_NFC_EMU_MIF_ACK;
            return POOM_NFC_EMU_MFUL_ACK_BITS;
        }
        if(ul_addr == POOM_NFC_EMU_MFUL_PAGE_OTP)
        {
            poom_nfc_emu_mful_or_otp_page(cmd, 2U);
            poom_nfc_emu_mful_rebuild_rollover();
            rsp[0] = POOM_NFC_EMU_MIF_ACK;
            return POOM_NFC_EMU_MFUL_ACK_BITS;
        }
        if(poom_nfc_emu_mful_writeable_cfg_page(ul_addr))
        {
            memcpy(&s_emu.mful_image[ul_addr * POOM_NFC_EMU_MFUL_PAGE_SIZE], &cmd[2],
                   POOM_NFC_EMU_MFUL_PAGE_SIZE);
            poom_nfc_emu_mful_rebuild_rollover();
            rsp[0] = POOM_NFC_EMU_MIF_ACK;
            return POOM_NFC_EMU_MFUL_ACK_BITS;
        }
        rsp[0] = POOM_NFC_EMU_MIF_NAK;
        if(card_reset != NULL)
            *card_reset = true;
        return POOM_NFC_EMU_MFUL_ACK_BITS;
    }

    if(cmd[0] == POOM_NFC_EMU_CMD_UL_CWRITE)
    {
        if(cmd_len != POOM_NFC_EMU_MFUL_CWRITE_CMD_LEN || rsp_max < 1U)
        {
            rsp[0] = POOM_NFC_EMU_MIF_NAK;
            if(card_reset != NULL)
                *card_reset = true;
            return POOM_NFC_EMU_MFUL_ACK_BITS;
        }
        if(cmd[1] >= POOM_NFC_EMU_MFUL_PAGE_OTP && cmd[1] <= s_emu.mful_page_last)
        {
            if(poom_nfc_emu_mful_auth_required_for_page(cmd[1], true) && !s_emu.mful_auth_ok)
            {
                rsp[0] = POOM_NFC_EMU_MIF_NAK;
                return POOM_NFC_EMU_MFUL_ACK_BITS;
            }
            s_emu.mful_cwrite_page_set = (uint8_t)(cmd[1] + 1U);
            rsp[0]                     = POOM_NFC_EMU_MIF_ACK;
            return POOM_NFC_EMU_MFUL_ACK_BITS;
        }
        rsp[0] = POOM_NFC_EMU_MIF_NAK;
        if(card_reset != NULL)
            *card_reset = true;
        return POOM_NFC_EMU_MFUL_ACK_BITS;
    }

    if(cmd[0] == POOM_NFC_EMU_CMD_UL_GET_VERSION)
    {
        if(cmd_len != POOM_NFC_EMU_MFUL_GET_VERSION_CMD_LEN ||
           rsp_max < POOM_NFC_EMU_MFUL_GET_VERSION_RSP_LEN)
        {
            rsp[0] = POOM_NFC_EMU_MIF_NAK;
            if(card_reset != NULL)
                *card_reset = true;
            return POOM_NFC_EMU_MFUL_ACK_BITS;
        }
        memcpy(rsp, s_emu.mful_version, POOM_NFC_EMU_MFUL_GET_VERSION_RSP_LEN);
        return rfalConvBytesToBits(POOM_NFC_EMU_MFUL_GET_VERSION_RSP_LEN);
    }

    if(cmd[0] == POOM_NFC_EMU_CMD_UL_READ_CNT)
    {
        if(cmd_len != POOM_NFC_EMU_MFUL_READ_CNT_CMD_LEN || rsp_max < POOM_NFC_EMU_MFUL_READ_CNT_RSP_LEN ||
           cmd[1] > 0x02U)
        {
            rsp[0] = POOM_NFC_EMU_MIF_NAK;
            if(card_reset != NULL)
                *card_reset = true;
            return POOM_NFC_EMU_MFUL_ACK_BITS;
        }
        ctr = 0U;
        rsp[0] = (uint8_t)(ctr & 0xFFU);
        rsp[1] = (uint8_t)((ctr >> 8) & 0xFFU);
        rsp[2] = (uint8_t)((ctr >> 16) & 0xFFU);
        return rfalConvBytesToBits(POOM_NFC_EMU_MFUL_READ_CNT_RSP_LEN);
    }

    if(cmd[0] == POOM_NFC_EMU_CMD_UL_READ_SIG)
    {
        if(cmd_len != POOM_NFC_EMU_MFUL_READ_SIG_CMD_LEN || cmd[1] != 0x00U ||
           rsp_max < POOM_NFC_EMU_MFUL_READ_SIG_RSP_LEN)
        {
            rsp[0] = POOM_NFC_EMU_MIF_NAK;
            if(card_reset != NULL)
                *card_reset = true;
            return POOM_NFC_EMU_MFUL_ACK_BITS;
        }
        for(i = 0; i < POOM_NFC_EMU_MFUL_READ_SIG_RSP_LEN; i++)
        {
            rsp[i] = s_emu.mful_signature[i];
        }
        return rfalConvBytesToBits(POOM_NFC_EMU_MFUL_READ_SIG_RSP_LEN);
    }

    if(card_reset != NULL)
    {
        *card_reset = true;
    }
    return 0;
}

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
    s_emu.mful_auth_ok      = false;
    poom_nfc_emu_reset_t4t_state();

    memset(&s_emu.l3_ctx, 0, sizeof(s_emu.l3_ctx));
    s_emu.l3_ctx.txBuf     = s_emu.tx_buf;
    s_emu.l3_ctx.rxBuf     = s_emu.rx_buf;
    s_emu.l3_ctx.rxBufLen  = rfalConvBytesToBits(sizeof(s_emu.rx_buf));
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

    rc = rfalListenStart(RFAL_LM_MASK_NFCA, &s_emu.conf_a, NULL, NULL,
                         s_emu.rx_buf, rfalConvBytesToBits(sizeof(s_emu.rx_buf)),
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
        tx_len = poom_nfc_emu_process_t4t(s_emu.iso_param.rxBuf->inf, *s_emu.iso_param.rxLen,
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
        tx_bits = poom_nfc_emu_process_mful(s_emu.rx_buf, rfalConvBitsToBytes(s_emu.rx_bits),
                                            s_emu.tx_buf, sizeof(s_emu.tx_buf),
                                            &card_reset);
    }
    else
    {
        tx_bits = 0;
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
                                               rfalConvBytesToBits(sizeof(s_emu.rx_buf)),
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
    poom_nfc_emu_build_default_ndef();
    poom_nfc_emu_reset_mful_image();
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
    poom_nfc_emu_cfg_defaults();
    (void)poom_nfc_emu_cfg_clear_persisted_uri_();
    poom_nfc_emu_build_default_ndef();
    poom_nfc_emu_reset_mful_image();
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
    poom_nfc_emu_build_default_ndef();
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
    poom_nfc_emu_build_default_ndef();
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

    poom_nfc_emu_reset_t4t_state();
    poom_nfc_emu_build_default_ndef();

    if(s_emu.cfg.mode == POOM_NFC_EMU_MODE_MFUL)
    {
        if(s_emu.cfg.image_path_set)
        {
            if(!poom_nfc_emu_load_mful_image_file(s_emu.cfg.image_path))
            {
                printf("  nfc-emul: image load failed (%s), using factory image.\r\n",
                       s_emu.cfg.image_path);
                poom_nfc_emu_reset_mful_image();
            }
        }
        else
        {
            poom_nfc_emu_reset_mful_image();
        }
    }

    if(!poom_nfc_emu_config_to_listen_params())
    {
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
        s_emu.running = false;
        s_emu.task_h  = NULL;
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
