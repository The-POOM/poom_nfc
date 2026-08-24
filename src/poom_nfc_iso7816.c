// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 THE POOM

#include "poom_nfc_iso7816.h"

#include <string.h>

enum
{
    POOM_ISO7816_SW_LEN = 2U,
    POOM_ISO7816_SELECT_DF_NAME_OVERHEAD = 6U,
    POOM_ISO7816_SHORT_LC_MAX = 0xFFU,
    POOM_ISO7816_CLA_INTERINDUSTRY = 0x00U,
    POOM_ISO7816_INS_SELECT = 0xA4U,
    POOM_ISO7816_P1_DF_NAME = 0x04U,
    POOM_ISO7816_P2_FIRST_ONLY = 0x00U,
    POOM_ISO7816_LE_SELECT = 0x00U,
    POOM_ISO7816_SW1_OK = 0x90U,
    POOM_ISO7816_SW2_OK = 0x00U,
    POOM_ISO7816_SW1_MORE_DATA = 0x61U,
    POOM_ISO7816_SW1_WARN_NV_UNCHANGED = 0x62U,
    POOM_ISO7816_SW1_WARN_NV_CHANGED = 0x63U,
    POOM_ISO7816_SW1_WRONG_LENGTH = 0x67U,
    POOM_ISO7816_SW1_FUNC_NOT_SUPPORTED = 0x68U,
    POOM_ISO7816_SW1_COMMAND_NOT_ALLOWED = 0x69U,
    POOM_ISO7816_SW2_CONDITIONS_NOT_SATISFIED = 0x85U,
    POOM_ISO7816_SW1_WRONG_PARAMS = 0x6AU,
    POOM_ISO7816_SW2_FILE_NOT_FOUND = 0x82U,
    POOM_ISO7816_SW2_INCORRECT_P1_P2 = 0x86U,
    POOM_ISO7816_SW1_WRONG_P1_P2 = 0x6BU,
    POOM_ISO7816_SW1_WRONG_LE = 0x6CU,
    POOM_ISO7816_SW1_INS_NOT_SUPPORTED = 0x6DU,
    POOM_ISO7816_SW1_CLA_NOT_SUPPORTED = 0x6EU,
    POOM_ISO7816_SW1_NO_DIAGNOSIS = 0x6FU,
};

bool poom_iso7816_parse_rapdu(const uint8_t* rapdu,
                              size_t rapdu_len,
                              poom_iso7816_rapdu_view_t* out_view)
{
    if(rapdu == NULL || out_view == NULL || rapdu_len < POOM_ISO7816_SW_LEN)
    {
        return false;
    }

    out_view->data = rapdu;
    out_view->data_len = rapdu_len - POOM_ISO7816_SW_LEN;
    out_view->sw1 = rapdu[rapdu_len - 2U];
    out_view->sw2 = rapdu[rapdu_len - 1U];
    return true;
}

/**
 * @brief Build a short SELECT FILE by DF Name C-APDU.
 *
 * @param[in] df_name Parameter passed to the function.
 * @param[in] df_name_len Parameter passed to the function.
 * @param[out] out_apdu Parameter passed to the function.
 * @param[in] out_apdu_max Parameter passed to the function.
 * @return size_t
 */
size_t poom_iso7816_build_select_df_name(const uint8_t* df_name,
                                         size_t df_name_len,
                                         uint8_t* out_apdu,
                                         size_t out_apdu_max)
{
    if(df_name == NULL || out_apdu == NULL || df_name_len == 0U || df_name_len > POOM_ISO7816_SHORT_LC_MAX)
    {
        return 0U;
    }

    if((df_name_len + POOM_ISO7816_SELECT_DF_NAME_OVERHEAD) > out_apdu_max)
    {
        return 0U;
    }

    out_apdu[0] = POOM_ISO7816_CLA_INTERINDUSTRY;
    out_apdu[1] = POOM_ISO7816_INS_SELECT;
    out_apdu[2] = POOM_ISO7816_P1_DF_NAME;
    out_apdu[3] = POOM_ISO7816_P2_FIRST_ONLY;
    out_apdu[4] = (uint8_t)df_name_len;
    memcpy(&out_apdu[5], df_name, df_name_len);
    out_apdu[5U + df_name_len] = POOM_ISO7816_LE_SELECT;
    return 6U + df_name_len;
}

/**
 * @brief Check whether an ISO/IEC 7816-4 status word is `90 00`.
 *
 * @param[in] sw1 Parameter passed to the function.
 * @param[in] sw2 Parameter passed to the function.
 * @return bool
 */
bool poom_iso7816_status_is_ok(uint8_t sw1, uint8_t sw2)
{
    return (sw1 == POOM_ISO7816_SW1_OK) && (sw2 == POOM_ISO7816_SW2_OK);
}

/**
 * @brief Return a short readable description for a status word.
 *
 * @param[in] sw1 Parameter passed to the function.
 * @param[in] sw2 Parameter passed to the function.
 * @return const char*
 */
const char* poom_iso7816_status_desc(uint8_t sw1, uint8_t sw2)
{
    if(sw1 == POOM_ISO7816_SW1_OK && sw2 == POOM_ISO7816_SW2_OK) return "Success";
    if(sw1 == POOM_ISO7816_SW1_MORE_DATA) return "More response bytes available";
    if(sw1 == POOM_ISO7816_SW1_WARN_NV_UNCHANGED) return "State of non-volatile memory unchanged";
    if(sw1 == POOM_ISO7816_SW1_WARN_NV_CHANGED) return "State of non-volatile memory changed";
    if(sw1 == POOM_ISO7816_SW1_WRONG_LENGTH && sw2 == POOM_ISO7816_SW2_OK) return "Wrong length";
    if(sw1 == POOM_ISO7816_SW1_FUNC_NOT_SUPPORTED) return "Function in CLA not supported";
    if(sw1 == POOM_ISO7816_SW1_COMMAND_NOT_ALLOWED && sw2 == POOM_ISO7816_SW2_CONDITIONS_NOT_SATISFIED) {
        return "Conditions of use not satisfied";
    }
    if(sw1 == POOM_ISO7816_SW1_COMMAND_NOT_ALLOWED) return "Command not allowed";
    if(sw1 == POOM_ISO7816_SW1_WRONG_PARAMS && sw2 == POOM_ISO7816_SW2_FILE_NOT_FOUND) return "File not found";
    if(sw1 == POOM_ISO7816_SW1_WRONG_PARAMS && sw2 == POOM_ISO7816_SW2_INCORRECT_P1_P2) {
        return "Incorrect parameters P1-P2";
    }
    if(sw1 == POOM_ISO7816_SW1_WRONG_PARAMS) return "Wrong parameters";
    if(sw1 == POOM_ISO7816_SW1_WRONG_P1_P2 && sw2 == POOM_ISO7816_SW2_OK) return "Wrong parameters P1-P2";
    if(sw1 == POOM_ISO7816_SW1_WRONG_LE) return "Wrong Le field";
    if(sw1 == POOM_ISO7816_SW1_INS_NOT_SUPPORTED && sw2 == POOM_ISO7816_SW2_OK) return "Instruction code not supported";
    if(sw1 == POOM_ISO7816_SW1_CLA_NOT_SUPPORTED && sw2 == POOM_ISO7816_SW2_OK) return "Class not supported";
    if(sw1 == POOM_ISO7816_SW1_NO_DIAGNOSIS && sw2 == POOM_ISO7816_SW2_OK) return "No precise diagnosis";
    return "Unknown status";
}
