// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 THE POOM

#include "poom_nfc_emv.h"

#include <ctype.h>
#include <string.h>

#include "poom_nfc_iso14443_4.h"
#include "poom_nfc_iso7816.h"
#include "poom_nfc_profile.h"
#include "poom_nfc_tlv.h"

static const uint8_t k_poom_emv_ppse_name[] = {
    0x32U, 0x50U, 0x41U, 0x59U, 0x2EU, 0x53U, 0x59U, 0x53U,
    0x2EU, 0x44U, 0x44U, 0x46U, 0x30U, 0x31U,
};

enum
{
    /* ISO/IEC 7816-4 / EMV FCI and directory tags used in v0.1. */
    POOM_EMV_TAG_FCI_TEMPLATE = 0x6FU,
    POOM_EMV_TAG_DF_NAME = 0x84U,
    POOM_EMV_TAG_FCI_PROPRIETARY_TEMPLATE = 0xA5U,
    POOM_EMV_TAG_FCI_ISSUER_DISCRETIONARY_DATA = 0xBF0CU,
    POOM_EMV_TAG_DIRECTORY_ENTRY = 0x61U,
    POOM_EMV_TAG_AID = 0x4FU,
    POOM_EMV_TAG_APPLICATION_LABEL = 0x50U,
    POOM_EMV_TAG_APPLICATION_PRIORITY = 0x87U,

    /* Short APDUs and short R-APDUs in this firmware stay within 256 + SW1/SW2. */
    POOM_EMV_SELECT_APDU_MAX = 261U,
};

static bool poom_nfc_emv_link_ready_(void)
{
    poom_nfc_profile_t profile;

    if(!poom_reader_get_last_profile(&profile))
    {
        return false;
    }

    return profile.ats_len > 0U;
}

/**
 * @brief Internal helper for `poom_nfc_emv_send_select_`.
 *
 * Builds a SELECT by DF Name C-APDU and sends it over the active ISO-DEP link.
 *
 * @param[in] name Parameter passed to the function.
 * @param[in] name_len Parameter passed to the function.
 * @param[out] out_rapdu Parameter passed to the function.
 * @param[in] out_max Parameter passed to the function.
 * @param[out] out_rapdu_len Parameter passed to the function.
 * @return bool
 */
static bool poom_nfc_emv_send_select_(const uint8_t* name,
                                      size_t name_len,
                                      uint8_t* out_rapdu,
                                      size_t out_max,
                                      size_t* out_rapdu_len)
{
    uint8_t apdu[POOM_EMV_SELECT_APDU_MAX];
    size_t apdu_len;

    if(out_rapdu_len == NULL)
    {
        return false;
    }

    *out_rapdu_len = 0U;

    if(!poom_nfc_emv_link_ready_())
    {
        return false;
    }

    apdu_len = poom_iso7816_build_select_df_name(name, name_len, apdu, sizeof(apdu));
    if(apdu_len == 0U)
    {
        return false;
    }

    return poom_reader_isodep_transceive_apdu(apdu, apdu_len, out_rapdu, out_max, out_rapdu_len);
}

/**
 * @brief Parse one EMV Directory Entry (`61`) payload into a small app view.
 *
 * @param[in] buf Parameter passed to the function.
 * @param[in] buf_len Parameter passed to the function.
 * @param[out] out_app Parameter passed to the function.
 * @return bool
 */
static bool poom_nfc_emv_parse_entry_(const uint8_t* buf,
                                      size_t buf_len,
                                      poom_nfc_emv_app_t* out_app)
{
    size_t off = 0U;
    poom_tlv_view_t tlv;

    if(buf == NULL || out_app == NULL)
    {
        return false;
    }

    (void)memset(out_app, 0, sizeof(*out_app));

    while(poom_tlv_next(buf, buf_len, &off, &tlv))
    {
        if(tlv.tag == POOM_EMV_TAG_AID)
        {
            out_app->aid = tlv.value;
            out_app->aid_len = tlv.value_len;
        }
        else if(tlv.tag == POOM_EMV_TAG_APPLICATION_LABEL)
        {
            out_app->label = tlv.value;
            out_app->label_len = tlv.value_len;
            out_app->label_printable = poom_nfc_emv_label_is_printable(tlv.value, tlv.value_len);
        }
        else if(tlv.tag == POOM_EMV_TAG_APPLICATION_PRIORITY && tlv.value_len >= 1U)
        {
            out_app->has_priority = true;
            out_app->priority = tlv.value[0];
        }
    }

    return out_app->aid != NULL && out_app->aid_len > 0U;
}

/**
 * @brief Recursively walk PPSE TLV containers and emit discovered apps.
 *
 * @param[in] buf Parameter passed to the function.
 * @param[in] buf_len Parameter passed to the function.
 * @param[in] cb Parameter passed to the function.
 * @param[in] user_ctx Parameter passed to the function.
 * @param[in,out] io_count Parameter passed to the function.
 * @return bool
 */
static bool poom_nfc_emv_walk_ppse_(const uint8_t* buf,
                                    size_t buf_len,
                                    poom_nfc_emv_app_cb_t cb,
                                    void* user_ctx,
                                    size_t* io_count)
{
    size_t off = 0U;
    poom_tlv_view_t tlv;

    while(poom_tlv_next(buf, buf_len, &off, &tlv))
    {
        if(tlv.tag == POOM_EMV_TAG_DIRECTORY_ENTRY)
        {
            poom_nfc_emv_app_t app;
            if(poom_nfc_emv_parse_entry_(tlv.value, tlv.value_len, &app))
            {
                if(io_count != NULL)
                {
                    (*io_count)++;
                }

                if(cb != NULL && !cb(&app, user_ctx))
                {
                    return false;
                }
            }
        }

        if(tlv.constructed && tlv.value_len > 0U)
        {
            if(!poom_nfc_emv_walk_ppse_(tlv.value, tlv.value_len, cb, user_ctx, io_count))
            {
                return false;
            }
        }
    }

    return true;
}

/**
 * @brief Return the static EMV PPSE name (`2PAY.SYS.DDF01`).
 *
 * @param[out] out_len Parameter passed to the function.
 * @return const uint8_t*
 */
const uint8_t* poom_nfc_emv_ppse_name(size_t* out_len)
{
    if(out_len != NULL)
    {
        *out_len = sizeof(k_poom_emv_ppse_name);
    }
    return k_poom_emv_ppse_name;
}

/**
 * @brief Select the PPSE over the active ISO-DEP session.
 *
 * @param[out] out_rapdu Parameter passed to the function.
 * @param[in] out_max Parameter passed to the function.
 * @param[out] out_rapdu_len Parameter passed to the function.
 * @return bool
 */
bool poom_nfc_emv_select_ppse(uint8_t* out_rapdu, size_t out_max, size_t* out_rapdu_len)
{
    return poom_nfc_emv_send_select_(
        k_poom_emv_ppse_name, sizeof(k_poom_emv_ppse_name), out_rapdu, out_max, out_rapdu_len);
}

/**
 * @brief Select one EMV application by AID over the active ISO-DEP session.
 *
 * @param[in] aid Parameter passed to the function.
 * @param[in] aid_len Parameter passed to the function.
 * @param[out] out_rapdu Parameter passed to the function.
 * @param[in] out_max Parameter passed to the function.
 * @param[out] out_rapdu_len Parameter passed to the function.
 * @return bool
 */
bool poom_nfc_emv_select_aid(const uint8_t* aid,
                             size_t aid_len,
                             uint8_t* out_rapdu,
                             size_t out_max,
                             size_t* out_rapdu_len)
{
    return poom_nfc_emv_send_select_(aid, aid_len, out_rapdu, out_max, out_rapdu_len);
}

/**
 * @brief Parse PPSE R-APDU contents and enumerate discovered applications.
 *
 * @param[in] rapdu Parameter passed to the function.
 * @param[in] rapdu_len Parameter passed to the function.
 * @param[in] cb Parameter passed to the function.
 * @param[in] user_ctx Parameter passed to the function.
 * @param[out] out_count Parameter passed to the function.
 * @return bool
 */
bool poom_nfc_emv_parse_ppse_apps(const uint8_t* rapdu,
                                  size_t rapdu_len,
                                  poom_nfc_emv_app_cb_t cb,
                                  void* user_ctx,
                                  size_t* out_count)
{
    poom_iso7816_rapdu_view_t view;
    size_t count = 0U;

    if(out_count != NULL)
    {
        *out_count = 0U;
    }

    if(!poom_iso7816_parse_rapdu(rapdu, rapdu_len, &view))
    {
        return false;
    }

    if(!poom_nfc_emv_walk_ppse_(view.data, view.data_len, cb, user_ctx, &count))
    {
        return false;
    }

    if(out_count != NULL)
    {
        *out_count = count;
    }
    return true;
}

/**
 * @brief Check whether a label is printable ASCII.
 *
 * @param[in] s Parameter passed to the function.
 * @param[in] len Parameter passed to the function.
 * @return bool
 */
bool poom_nfc_emv_label_is_printable(const uint8_t* s, size_t len)
{
    if(s == NULL)
    {
        return false;
    }

    for(size_t i = 0U; i < len; i++)
    {
        if(!isprint((int)s[i]))
        {
            return false;
        }
    }

    return true;
}
