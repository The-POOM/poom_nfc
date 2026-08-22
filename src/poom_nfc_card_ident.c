#include "poom_nfc_card_ident.h"
#include <string.h>
#include "rfal_nfc.h"
#include "rfal_t2t.h"

const char* nfc_ident_nfca_manufacturer(uint8_t uid0)
{
    switch(uid0)
    {
        case 0x01: return "Motorola";
        case 0x02: return "STMicroelectronics";
        case 0x03: return "Hitachi Ltd";
        case 0x04: return "NXP Semiconductors";
        case 0x05: return "Infineon Technologies";
        case 0x06: return "Cylink";
        case 0x07: return "Texas Instruments";
        case 0x08: return "Fujitsu Limited";
        case 0x09: return "Matsushita Electronics";
        case 0x0A: return "NEC";
        case 0x0B: return "Oki Electric Industry Co Ltd";
        case 0x0C: return "Toshiba Corp";
        case 0x0D: return "Mitsubishi Electric Corp";
        case 0x0E: return "Samsung Electronics Co Ltd";
        case 0x0F: return "Hynix";
        case 0x10: return "LG-Semiconductors Co Ltd";
        case 0x11: return "Emosyn-EM Microelectronics";
        case 0x12: return "INSIDE Technology";
        case 0x13: return "ORGA Kartensysteme GmbH";
        case 0x14: return "Sharp Corporation";
        case 0x15: return "ATMEL";
        case 0x16: return "EM Microelectronic-Marin";
        case 0x17: return "SMARTRAC TECHNOLOGY GmbH";
        case 0x18: return "ZMD AG";
        case 0x19: return "XICOR Inc";
        case 0x1A: return "Sony Corporation";
        case 0x1B: return "Malaysia Microelectronic Solutions Sdn Bhd";
        case 0x1C: return "Emosyn";
        case 0x1D: return "Shanghai Fudan Microelectronics Co Ltd";
        case 0x1E: return "Magellan Technology Pty Limited";
        case 0x1F: return "Melexis NV BO";
        case 0x20: return "Renesas Technology Corp";
        case 0x21: return "TAGSYS";
        case 0x22: return "Transcore";
        case 0x23: return "Shanghai Belling Corp Ltd";
        case 0x24: return "Masktech Germany GmbH";
        case 0x25: return "Innovision Research and Technology Plc";
        case 0x26: return "Hitachi ULSI Systems Co Ltd";
        case 0x27: return "Yubico AB";
        case 0x28: return "Ricoh";
        case 0x29: return "ASK";
        case 0x2A: return "Unicore Microsystems LLC";
        case 0x2B: return "Dallas semiconductor/Maxim";
        case 0x2C: return "Impinj Inc";
        case 0x2D: return "RightPlug Alliance";
        case 0x2E: return "Broadcom Corporation";
        case 0x2F: return "MStar Semiconductor Inc";
        case 0x30: return "BeeDar Technology Inc";
        case 0x31: return "RFIDsec";
        case 0x32: return "Schweizer Electronic AG";
        case 0x33: return "AMIC Technology Corp";
        case 0x34: return "Mikron JSC";
        case 0x35: return "Fraunhofer Institute for Photonic Microsystems";
        case 0x36: return "IDS Microship AG";
        case 0x37: return "Kovio";
        case 0x38: return "HMT Microelectronic Ltd";
        case 0x39: return "Silicon Craft Technology";
        case 0x3A: return "Advanced Film Device Inc.";
        case 0x3B: return "Nitecrest Ltd";
        case 0x3C: return "Verayo Inc.";
        case 0x3D: return "HID Global";
        case 0x3E: return "Productivity Engineering Gmbh";
        case 0x3F: return "Austriamicrosystems AG";
        case 0x40: return "Gemalto SA";
        case 0x41: return "Renesas Electronics Corporation";
        case 0x42: return "3Alogics Inc";
        case 0x43: return "Top TroniQ Asia Limited";
        case 0x44: return "Gentag Inc";
        case 0x45: return "Invengo Information Technology Co.Ltd";
        case 0x46: return "Guangzhou Sysur Microelectronics, Inc";
        case 0x47: return "CEITEC S.A.";
        case 0x48: return "Shanghai Quanray Electronics Co. Ltd.";
        case 0x49: return "MediaTek Inc";
        case 0x4A: return "Angstrem PJSC";
        case 0x4B: return "Celisic Semiconductor";
        case 0x4C: return "LEGIC Identsystems AG";
        case 0x4D: return "Balluff GmbH";
        case 0x4E: return "Oberthur Technologies";
        case 0x4F: return "Silterra Malaysia Sdn. Bhd.";
        case 0x50: return "DELTA Danish Electronics, Light & Acoustics";
        case 0x51: return "Giesecke & Devrient GmbH";
        case 0x52: return "Shenzhen China Vision Microelectronics Co., Ltd.";
        case 0x53: return "Shanghai Feiju Microelectronics Co. Ltd.";
        case 0x54: return "Intel Corporation";
        case 0x55: return "Microsensys GmbH";
        case 0x56: return "Sonix Technology Co., Ltd.";
        case 0x57: return "Qualcomm Technologies Inc";
        case 0x58: return "Realtek Semiconductor Corp";
        case 0x59: return "Freevision Technologies Co. Ltd";
        case 0x5A: return "Giantec Semiconductor Inc.";
        case 0x5B: return "JSC Angstrem-T";
        case 0x5C: return "STARCHIP France";
        case 0x5D: return "SPIRTECH";
        case 0x5E: return "GANTNER Electronic GmbH";
        case 0x5F: return "Nordic Semiconductor";
        case 0x60: return "Verisiti Inc";
        case 0x61: return "Wearlinks Technology Inc.";
        case 0x62: return "Userstar Information Systems Co., Ltd";
        case 0x63: return "Pragmatic Printing Ltd.";
        case 0x64: return "LSI-TEC (Brazil)";
        case 0x65: return "Tendyron Corporation";
        case 0x66: return "MUTO Smart Co., Ltd.";
        case 0x67: return "ON Semiconductor";
        case 0x68: return "TUBITAK BILGEM";
        case 0x69: return "Huada Semiconductor Co., Ltd";
        case 0x6A: return "SEVENEY";
        case 0x6B: return "ISSM";
        case 0x6C: return "Wisesec Ltd";
        case 0x7E: return "Holtek";
        case 0xC1: return "T2T Ultralight/NTAG ";
        default:   return "Unknown";
    }
}

nfc_card_type_t nfc_ident_detect_nfca(uint16_t atqa, uint8_t sak)
{
    switch((nfc_nfca_sak_t)sak)
    {
        case NFC_SAK_ULTRALIGHT_CL2:
            if(atqa == NFC_ATQA_ULTRALIGHT)
                return NFC_CARD_ULTRALIGHT_OR_NTAG;
            return NFC_CARD_UNKNOWN;

        case NFC_SAK_TNP3XXX:
            return NFC_CARD_OTHER;

        case NFC_SAK_MIFARE_CL1_NO_DF:
            return NFC_CARD_OTHER;

        case NFC_SAK_MIFARE_CLASSIC_1K:
            return NFC_CARD_MIFARE_CLASSIC_1K;

        case NFC_SAK_MIFARE_MINI:
            return NFC_CARD_MIFARE_MINI;

        case NFC_SAK_MIFARE_PLUS_2K:
        case NFC_SAK_MIFARE_PLUS_4K:
            return NFC_CARD_MIFARE_PLUS;

        case NFC_SAK_MIFARE_4K:
            if(atqa == NFC_ATQA_CLASSIC_4K)
                return NFC_CARD_MIFARE_CLASSIC_4K;
            if(atqa == NFC_ATQA_PLUS_4K_CL2)
                return NFC_CARD_MIFARE_PLUS;
            return NFC_CARD_MIFARE_CLASSIC_4K;

        case NFC_SAK_MIFARE_PLUS_OR_DF:
            if(atqa == NFC_ATQA_NTAG424DNA_RID)
                return NFC_CARD_NTAG424DNA;
            if(atqa == NFC_ATQA_DESFIRE_EV1)
                return NFC_CARD_MIFARE_DESFIRE;
            return NFC_CARD_MIFARE_PLUS;

        case NFC_SAK_DESFIRE_CL1:
            return NFC_CARD_MIFARE_DESFIRE;

        case NFC_SAK_DESFIRE_OR_JCOP:
            if(atqa == NFC_ATQA_JCOP)
                return NFC_CARD_JCOP;
            return NFC_CARD_MIFARE_DESFIRE;

        case NFC_SAK_NOKIA_CLASSIC_4K:
            return NFC_CARD_MIFARE_CLASSIC_4K;

        case NFC_SAK_INFINEON_CLASSIC:
            return NFC_CARD_MIFARE_CLASSIC_1K;

        case NFC_SAK_GEMPLUS_MPCOS:
            return NFC_CARD_OTHER;

        default:
            if(atqa == NFC_ATQA_JEWEL)
                return NFC_CARD_JEWEL;
            return NFC_CARD_UNKNOWN;
    }
}

const char* nfc_ident_card_type_to_str(nfc_card_type_t t)
{
    switch(t) {
        case NFC_CARD_ULTRALIGHT_OR_NTAG:  return "Ultralight/NTAG (T2T)";
        case NFC_CARD_MIFARE_MINI:         return "MIFARE Mini";
        case NFC_CARD_MIFARE_CLASSIC_1K:   return "MIFARE Classic 1K";
        case NFC_CARD_MIFARE_CLASSIC_4K:   return "MIFARE Classic 4K";
        case NFC_CARD_MIFARE_PLUS:         return "MIFARE Plus";
        case NFC_CARD_MIFARE_DESFIRE:      return "MIFARE DESFire (ISO-DEP)";
        case NFC_CARD_NTAG424DNA:          return "NTAG424DNA";
        case NFC_CARD_JCOP:                return "JCOP";
        case NFC_CARD_JEWEL:               return "Jewel";
        case NFC_CARD_OTHER:               return "Other";
        default:                           return "Unknown";
    }
}

/* GET_VERSION constants. */

typedef enum {
    NFC_CMD_GET_VERSION_T2T  = 0x60, /* Ultralight EV1 / NTAG / etc.: 1-byte command */
} nfc_t2t_cmd_t;

typedef enum {
    /* Common DESFire ISO7816-4 APDUs */
    NFC_DF_CLA = 0x90,
    NFC_DF_INS_GET_VERSION = 0x60,
    NFC_DF_INS_ADDITIONAL_FRAME = 0xAF,
    NFC_DF_P1 = 0x00,
    NFC_DF_P2 = 0x00,
    NFC_DF_LE = 0x00,
} nfc_desfire_apdu_const_t;

/* Typical DESFire status words:
 * 0x91AF => Additional Frame
 * 0x9100 => OK
 */

/**
 * @brief Internal helper for `df_is_sw_additional`.
 *
 * @param[in] sw1 Parameter passed to the function.
 * @param[in] sw2 Parameter passed to the function.
 * @return bool
 */
static bool df_is_sw_additional(uint8_t sw1, uint8_t sw2) { return (sw1 == 0x91 && sw2 == 0xAF); }

/**
 * @brief Internal helper for `df_is_sw_ok`.
 *
 * @param[in] sw1 Parameter passed to the function.
 * @param[in] sw2 Parameter passed to the function.
 * @return bool
 */
static bool df_is_sw_ok(uint8_t sw1, uint8_t sw2)         { return (sw1 == 0x91 && sw2 == 0x00); }

/* T2T GET_VERSION parsing. */

/**
 * @brief Parses input data for this module.
 *
 * @param[in] rx Parameter passed to the function.
 * @param[in] rx_len Parameter passed to the function.
 * @param[in] out Parameter passed to the function.
 * @return bool
 */
static bool t2t_parse_get_version(const uint8_t *rx, size_t rx_len, nfc_t2t_get_version_t *out)
{
    if(!rx || !out) return false;
    if(rx_len < 8) return false;

    memset(out, 0, sizeof(*out));
    memcpy(out->raw, rx, 8);

    out->vendor_id       = rx[0];
    out->product_type    = rx[1];
    out->product_subtype = rx[2];
    out->major_version   = rx[3];
    out->minor_version   = rx[4];
    out->storage_size    = rx[5];
    out->protocol_type   = rx[6];

    out->valid = true;
    return true;
}

/* DESFire GET_VERSION helpers. */

/**
 * @brief Internal helper for `df_send_apdu`.
 *
 * @param[in] cb Parameter passed to the function.
 * @param[in] ctx Parameter passed to the function.
 * @param[in] apdu Parameter passed to the function.
 * @param[in] apdu_len Parameter passed to the function.
 * @param[in] rx Parameter passed to the function.
 * @param[in] rx_max Parameter passed to the function.
 * @param[in] rx_len_out Parameter passed to the function.
 * @return bool
 */
static bool df_send_apdu(
    nfc_isodep_transceive_cb cb,
    void *ctx,
    const uint8_t *apdu, size_t apdu_len,
    uint8_t *rx, size_t rx_max, size_t *rx_len_out)
{
    if(!cb || !apdu || !rx || !rx_len_out) return false;
    *rx_len_out = 0;
    return cb(apdu, apdu_len, rx, rx_max, rx_len_out, ctx);
}

/**
 * @brief Parses input data for this module.
 *
 * @param[in] rx Parameter passed to the function.
 * @param[in] rx_len Parameter passed to the function.
 * @param[in] sw1 Parameter passed to the function.
 * @param[in] sw2 Parameter passed to the function.
 * @return bool
 */
static bool df_parse_sw(const uint8_t *rx, size_t rx_len, uint8_t *sw1, uint8_t *sw2)
{
    if(!rx || rx_len < 2 || !sw1 || !sw2) return false;
    *sw1 = rx[rx_len - 2];
    *sw2 = rx[rx_len - 1];
    return true;
}

/**
 * @brief Internal helper for `df_get_version_chained`.
 *
 * @param[in] cb Parameter passed to the function.
 * @param[in] ctx Parameter passed to the function.
 * @param[in] out Parameter passed to the function.
 * @return bool
 */
static bool df_get_version_chained(
    nfc_isodep_transceive_cb cb,
    void *ctx,
    nfc_desfire_get_version_t *out)
{
    if(!cb || !out) return false;

    uint8_t rx[64];
    size_t rx_len = 0;

    uint8_t apdu_get_ver[] = { (uint8_t)NFC_DF_CLA, (uint8_t)NFC_DF_INS_GET_VERSION, (uint8_t)NFC_DF_P1, (uint8_t)NFC_DF_P2, (uint8_t)NFC_DF_LE };
    uint8_t apdu_more[]    = { (uint8_t)NFC_DF_CLA, (uint8_t)NFC_DF_INS_ADDITIONAL_FRAME, (uint8_t)NFC_DF_P1, (uint8_t)NFC_DF_P2, (uint8_t)NFC_DF_LE };

    memset(out, 0, sizeof(*out));

    if(!df_send_apdu(cb, ctx, apdu_get_ver, sizeof(apdu_get_ver), rx, sizeof(rx), &rx_len)) return false;
    if(rx_len < 2) return false;

    {
        size_t data_len = rx_len - 2;
        if(data_len > sizeof(out->raw)) data_len = sizeof(out->raw);
        memcpy(out->raw, rx, data_len);
        out->raw_len = data_len;
    }

    uint8_t sw1 = 0, sw2 = 0;
    if(!df_parse_sw(rx, rx_len, &sw1, &sw2)) return false;

    while(df_is_sw_additional(sw1, sw2))
    {
        if(!df_send_apdu(cb, ctx, apdu_more, sizeof(apdu_more), rx, sizeof(rx), &rx_len)) return false;
        if(rx_len < 2) return false;

        size_t data_len = rx_len - 2;
        size_t space = (out->raw_len < sizeof(out->raw)) ? (sizeof(out->raw) - out->raw_len) : 0;
        if(space == 0) break;

        if(data_len > space) data_len = space;
        memcpy(&out->raw[out->raw_len], rx, data_len);
        out->raw_len += data_len;

        if(!df_parse_sw(rx, rx_len, &sw1, &sw2)) return false;
    }

    out->sw1 = sw1;
    out->sw2 = sw2;
    out->valid = df_is_sw_ok(sw1, sw2);

    return out->valid;
}

bool nfc_ident_try_get_version(
    nfc_card_type_t detected_type,
    nfc_t2t_transceive_cb t2t_cb,
    nfc_isodep_transceive_cb isodep_cb,
    void *user_ctx,
    nfc_get_version_info_t *out_info)
{
    if(!out_info) return false;
    memset(out_info, 0, sizeof(*out_info));

    if(detected_type == NFC_CARD_ULTRALIGHT_OR_NTAG ||
       detected_type == NFC_CARD_NTAG424DNA)
    {
        if(!t2t_cb) return false;

        uint8_t tx[] = { (uint8_t)NFC_CMD_GET_VERSION_T2T };
        uint8_t rx[16];
        size_t rx_len = 0;

        if(!t2t_cb(tx, sizeof(tx), rx, sizeof(rx), &rx_len, user_ctx))
            return false;

        out_info->kind = NFC_GV_T2T_UL_NTAG;
        if(!t2t_parse_get_version(rx, rx_len, &out_info->u.t2t))
            return false;

        return out_info->u.t2t.valid;
    }

    if(detected_type == NFC_CARD_MIFARE_DESFIRE)
    {
        if(!isodep_cb) return false;

        out_info->kind = NFC_GV_DESFIRE_APDU;
        return df_get_version_chained(isodep_cb, user_ctx, &out_info->u.df);
    }

    return false;
}
