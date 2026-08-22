#include "poom_nfc_debug.h"

#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "poom_nfc_controller.h"
#include "poom_nfc_iso14443_4.h"

#include "rfal_nfca.h"
#include "rfal_nfc.h"

void poom_nfc_debug_reader_set_verbose(bool enable)
{
    poom_reader_set_verbose(enable);
}

bool poom_nfc_debug_reader_set_iso_dep_chunk_len(uint8_t value_1_to_250)
{
    return poom_reader_set_iso_dep_chunk_len(value_1_to_250);
}

bool poom_nfc_debug_rf_on(void)
{
    if(!poom_nfc_controller_start())
    {
        return false;
    }

    rfalFieldOnAndStartGT();
    return true;
}

bool poom_nfc_debug_rf_off(void)
{
    if(!poom_nfc_controller_start())
    {
        return false;
    }

    rfalFieldOff();
    return true;
}

bool poom_nfc_debug_mode_get(poom_nfc_debug_mode_info_t* out_info)
{
    if(out_info == NULL)
    {
        return false;
    }

    if(!poom_nfc_controller_start())
    {
        return false;
    }

    (void)memset(out_info, 0, sizeof(*out_info));
    out_info->mode = rfalGetMode();
    out_info->tx_br = RFAL_BR_KEEP;
    out_info->rx_br = RFAL_BR_KEEP;
    out_info->bitrate_rc = rfalGetBitRate(&out_info->tx_br, &out_info->rx_br);
    return true;
}

ReturnCode poom_nfc_debug_mode_set(rfalMode mode, rfalBitRate tx_br, rfalBitRate rx_br)
{
    if(!poom_nfc_controller_start())
    {
        return RFAL_ERR_WRONG_STATE;
    }

    return rfalSetMode(mode, tx_br, rx_br);
}

bool poom_nfc_debug_obsv_get(poom_nfc_debug_obsv_info_t* out_info)
{
    if(out_info == NULL)
    {
        return false;
    }

    if(!poom_nfc_controller_start())
    {
        return false;
    }

    rfalGetObsvMode(&out_info->tx, &out_info->rx);
    return true;
}

bool poom_nfc_debug_obsv_set_enabled(bool enable, uint8_t tx, uint8_t rx)
{
    if(!poom_nfc_controller_start())
    {
        return false;
    }

    if(!enable)
    {
        rfalDisableObsvMode();
        return true;
    }

    rfalSetObsvMode(tx, rx);
    return true;
}

const char* poom_nfc_debug_return_code_to_str(ReturnCode rc)
{
    switch(rc)
    {
        case RFAL_ERR_NONE: return "NONE";
        case RFAL_ERR_NOMEM: return "NOMEM";
        case RFAL_ERR_BUSY: return "BUSY";
        case RFAL_ERR_IO: return "IO";
        case RFAL_ERR_TIMEOUT: return "TIMEOUT";
        case RFAL_ERR_REQUEST: return "REQUEST";
        case RFAL_ERR_NOMSG: return "NOMSG";
        case RFAL_ERR_PARAM: return "PARAM";
        case RFAL_ERR_SYSTEM: return "SYSTEM";
        case RFAL_ERR_FRAMING: return "FRAMING";
        case RFAL_ERR_OVERRUN: return "OVERRUN";
        case RFAL_ERR_PROTO: return "PROTO";
        case RFAL_ERR_INTERNAL: return "INTERNAL";
        case RFAL_ERR_AGAIN: return "AGAIN";
        case RFAL_ERR_CRC: return "CRC";
        case RFAL_ERR_NOTFOUND: return "NOTFOUND";
        case RFAL_ERR_NOTUNIQUE: return "NOTUNIQUE";
        case RFAL_ERR_NOTSUPP: return "NOTSUPP";
        case RFAL_ERR_FIFO: return "FIFO";
        case RFAL_ERR_PAR: return "PAR";
        case RFAL_ERR_RF_COLLISION: return "RF_COLLISION";
        case RFAL_ERR_SLEEP_REQ: return "SLEEP_REQ";
        case RFAL_ERR_WRONG_STATE: return "WRONG_STATE";
        case RFAL_ERR_DISABLED: return "DISABLED";
        case RFAL_ERR_HW_MISMATCH: return "HW_MISMATCH";
        case RFAL_ERR_LINK_LOSS: return "LINK_LOSS";
        case RFAL_ERR_INVALID_HANDLE: return "INVALID_HANDLE";
        case RFAL_ERR_INCOMPLETE_BYTE: return "INCOMPLETE_BYTE";
        default: return "UNKNOWN";
    }
}

/**
 * @brief Internal helper for `poom_nfc_debug_prepare_nfca_shortframe`.
 *
 * @return ReturnCode
 */
static ReturnCode poom_nfc_debug_prepare_nfca_shortframe_(void)
{
    ReturnCode rc;

    if(!poom_nfc_controller_start())
    {
        return RFAL_ERR_WRONG_STATE;
    }

    if(rfalNfcGetState() != RFAL_NFC_STATE_IDLE)
    {
        rc = rfalNfcDeactivate(RFAL_NFC_DEACTIVATE_IDLE);
        if(rc != RFAL_ERR_NONE)
        {
            return rc;
        }
    }

    rc = rfalNfcaPollerInitialize();
    if(rc != RFAL_ERR_NONE)
    {
        return rc;
    }

    rc = rfalFieldOnAndStartGT();
    if(rc != RFAL_ERR_NONE)
    {
        return rc;
    }

    return RFAL_ERR_NONE;
}

/**
 * @brief Internal helper for `poom_nfc_debug_shortframe`.
 *
 * @param[in] cmd Parameter passed to the function.
 * @param[in] out_atqa Parameter passed to the function.
 * @return ReturnCode
 */
static ReturnCode poom_nfc_debug_shortframe_(uint8_t cmd, poom_nfc_debug_atqa_t* out_atqa)
{
    ReturnCode rc;

    if(out_atqa == NULL)
    {
        return RFAL_ERR_PARAM;
    }

    rc = poom_nfc_debug_prepare_nfca_shortframe_();
    if(rc != RFAL_ERR_NONE)
    {
        return rc;
    }

    rfalNfcaSensRes sens;
    rc = rfalNfcaPollerCheckPresence(cmd, &sens);
    if(rc != RFAL_ERR_NONE)
    {
        return rc;
    }

    out_atqa->atqa[0] = sens.anticollisionInfo;
    out_atqa->atqa[1] = sens.platformInfo;
    return RFAL_ERR_NONE;
}

ReturnCode poom_nfc_debug_req_a(poom_nfc_debug_atqa_t* out_atqa)
{
    return poom_nfc_debug_shortframe_(RFAL_14443A_SHORTFRAME_CMD_REQA, out_atqa);
}

ReturnCode poom_nfc_debug_wup_a(poom_nfc_debug_atqa_t* out_atqa)
{
    return poom_nfc_debug_shortframe_(RFAL_14443A_SHORTFRAME_CMD_WUPA, out_atqa);
}

ReturnCode poom_nfc_debug_raw_txrx(const uint8_t* tx,
                                  size_t tx_len,
                                  bool crc_auto,
                                  uint8_t* rx,
                                  size_t rx_max,
                                  size_t* out_rx_len)
{
    uint16_t rx_len_u16 = 0;
    uint32_t flags;
    ReturnCode rc;

    if(out_rx_len != NULL)
    {
        *out_rx_len = 0U;
    }

    if((tx == NULL) || (tx_len == 0U) || (rx == NULL) || (rx_max == 0U) || (out_rx_len == NULL))
    {
        return RFAL_ERR_PARAM;
    }

    if(tx_len > 0xFFFFU || rx_max > 0xFFFFU)
    {
        return RFAL_ERR_PARAM;
    }

    if(!poom_nfc_controller_start())
    {
        return RFAL_ERR_WRONG_STATE;
    }

    flags = crc_auto ? (uint32_t)RFAL_TXRX_FLAGS_DEFAULT
                     : ((uint32_t)RFAL_TXRX_FLAGS_CRC_TX_MANUAL |
                        (uint32_t)RFAL_TXRX_FLAGS_CRC_RX_KEEP);

    rc = rfalTransceiveBlockingTxRx((uint8_t*)tx,
                                   (uint16_t)tx_len,
                                   rx,
                                   (uint16_t)rx_max,
                                   &rx_len_u16,
                                   flags,
                                   RFAL_FWT_NONE);

    *out_rx_len = (size_t)rx_len_u16;
    return rc;
}

ReturnCode poom_nfc_debug_regdump(t_st25r3916Regs* out_dump)
{
    if(out_dump == NULL)
    {
        return RFAL_ERR_PARAM;
    }

    if(!poom_nfc_controller_start())
    {
        return RFAL_ERR_WRONG_STATE;
    }

    return st25r3916GetRegsDump(out_dump);
}

const uint8_t* poom_nfc_debug_st25_space_b_addr_map(size_t* out_len)
{
    static const uint8_t k_map[16] = {
        0x05U,
        0x06U,
        0x0BU,
        0x0CU,
        0x0DU,
        0x0FU,
        0x15U,
        0x28U,
        0x29U,
        0x2AU,
        0x2BU,
        0x2CU,
        0x30U,
        0x31U,
        0x32U,
        0x33U,
    };

    if(out_len != NULL)
    {
        *out_len = sizeof(k_map);
    }
    return k_map;
}

bool poom_nfc_debug_scan_loop(uint32_t period_ms, uint32_t timeout_ms, uint32_t count)
{
    if((period_ms == 0U) || (count == 0U))
    {
        return false;
    }

    for(uint32_t i = 0; i < count; i++)
    {
        (void)poom_nfc_controller_scan_once(timeout_ms);
        vTaskDelay(pdMS_TO_TICKS(period_ms));
    }
    return true;
}
