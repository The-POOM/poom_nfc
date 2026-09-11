// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 THE POOM

#include "poom_nfc_emv.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "esp_random.h"
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

    POOM_EMV_TAG_AIP = 0x82U,
    POOM_EMV_TAG_PDOL = 0x9F38U,
    POOM_EMV_TAG_AFL = 0x94U,
    POOM_EMV_TAG_GPO_FORMAT_1 = 0x80U,
    POOM_EMV_TAG_GPO_FORMAT_2 = 0x77U,
    POOM_EMV_TAG_READ_RECORD_TEMPLATE = 0x70U,
    POOM_EMV_TAG_PREFERRED_NAME = 0x9F12U,
    POOM_EMV_TAG_PAN = 0x5AU,
    POOM_EMV_TAG_TRACK_1_DATA = 0x56U,
    POOM_EMV_TAG_TRACK_2_EQUIVALENT = 0x57U,
    POOM_EMV_TAG_TRACK_2_DATA = 0x9F6BU,
    POOM_EMV_TAG_CARDHOLDER_NAME = 0x5F20U,
    POOM_EMV_TAG_CARDHOLDER_NAME_EXTENDED = 0x9F0BU,
    POOM_EMV_TAG_EXPIRATION_DATE = 0x5F24U,
    POOM_EMV_TAG_EFFECTIVE_DATE = 0x5F25U,
    POOM_EMV_TAG_COUNTRY_CODE = 0x5F28U,
    POOM_EMV_TAG_CURRENCY_CODE = 0x9F42U,
    POOM_EMV_TAG_ATC = 0x9F36U,
    POOM_EMV_TAG_PIN_TRY_COUNTER = 0x9F17U,
    POOM_EMV_TAG_LAST_ONLINE_ATC = 0x9F13U,
    POOM_EMV_TAG_LOG_ENTRY = 0x9F4DU,
    POOM_EMV_TAG_LOG_FORMAT = 0x9F4FU,
    POOM_EMV_TAG_AMOUNT_AUTHORISED = 0x9F02U,
    POOM_EMV_TAG_TERMINAL_COUNTRY = 0x9F1AU,
    POOM_EMV_TAG_TRANSACTION_CURRENCY = 0x5F2AU,
    POOM_EMV_TAG_TRANSACTION_DATE = 0x9AU,
    POOM_EMV_TAG_TRANSACTION_TIME = 0x9F21U,
    POOM_EMV_TAG_LANGUAGE_PREFERENCE = 0x5F2DU,
    POOM_EMV_TAG_APPLICATION_USAGE_CONTROL = 0x9F07U,
    POOM_EMV_TAG_APPLICATION_VERSION_NUMBER = 0x9F08U,
    POOM_EMV_TAG_CVM_LIST = 0x8EU,
    POOM_EMV_TAG_CDOL1 = 0x8CU,
    POOM_EMV_TAG_CDOL2 = 0x8DU,
    POOM_EMV_TAG_IAC_DEFAULT = 0x9F0DU,
    POOM_EMV_TAG_IAC_DENIAL = 0x9F0EU,
    POOM_EMV_TAG_IAC_ONLINE = 0x9F0FU,
    POOM_EMV_TAG_SDA_TAG_LIST = 0x9F4AU,
    POOM_EMV_TAG_CA_PUBLIC_KEY_INDEX = 0x8FU,
    POOM_EMV_TAG_ISSUER_PUBLIC_KEY_CERTIFICATE = 0x90U,
    POOM_EMV_TAG_ISSUER_PUBLIC_KEY_REMAINDER = 0x92U,
    POOM_EMV_TAG_ISSUER_PUBLIC_KEY_EXPONENT = 0x9F32U,
    POOM_EMV_TAG_ICC_PUBLIC_KEY_CERTIFICATE = 0x9F46U,
    POOM_EMV_TAG_ICC_PUBLIC_KEY_EXPONENT = 0x9F47U,
    POOM_EMV_TAG_ICC_PUBLIC_KEY_REMAINDER = 0x9F48U,
    POOM_EMV_TAG_DDOL = 0x9F49U,
    POOM_EMV_TAG_CUSTOMER_EXCLUSIVE_DATA = 0x9F7CU,
    POOM_EMV_TAG_PAN_SEQUENCE_NUMBER = 0x5F34U,
    POOM_EMV_TAG_ISSUER_CODE_TABLE_INDEX = 0x9F11U,
    POOM_EMV_TAG_ISSUER_APPLICATION_DATA = 0x9F10U,
    POOM_EMV_TAG_APPLICATION_CRYPTOGRAM = 0x9F26U,
    POOM_EMV_TAG_CRYPTOGRAM_INFORMATION_DATA = 0x9F27U,
    POOM_EMV_TAG_APPLICATION_PROGRAM_IDENTIFIER = 0x9F5AU,
    /* Scheme-specific meanings: never interpret these in the common decoder. */
    POOM_EMV_TAG_SCHEME_9F5D = 0x9F5DU,
    POOM_EMV_TAG_SCHEME_9F6C = 0x9F6CU,
    POOM_EMV_TAG_SCHEME_9F6E = 0x9F6EU,

    /* Short APDUs and short R-APDUs in this firmware stay within 256 + SW1/SW2. */
    POOM_EMV_SELECT_APDU_MAX = 261U,
    POOM_EMV_RESPONSE_MAX = 512U,
    POOM_EMV_PDOL_MAX = 240U,
    POOM_EMV_AFL_MAX = 128U,
    POOM_EMV_LOG_FORMAT_MAX = 96U,
    POOM_EMV_GET_RESPONSE_MAX = 4U,
    POOM_EMV_CARD_GONE_THRESHOLD = 1U,
    POOM_EMV_CAPTURE_DATA_MAX = 2048U,
    POOM_EMV_CAPTURE_DATA_INITIAL = 256U,
};

typedef enum
{
    POOM_EMV_EXCHANGE_ERROR_NONE = 0,
    POOM_EMV_EXCHANGE_ERROR_TRANSPORT,
    POOM_EMV_EXCHANGE_ERROR_RESPONSE,
    POOM_EMV_EXCHANGE_ERROR_STATUS,
} poom_nfc_emv_exchange_error_t;

typedef struct
{
    uint8_t command[POOM_EMV_SELECT_APDU_MAX];
    uint8_t rapdu[POOM_EMV_RESPONSE_MAX + 2U];
    uint8_t response[POOM_EMV_RESPONSE_MAX];
    uint8_t pdol_data[POOM_EMV_PDOL_MAX];
    uint8_t gpo_data[POOM_EMV_PDOL_MAX + 3U];
    uint8_t apdu[POOM_EMV_SELECT_APDU_MAX];
    uint8_t afl[POOM_EMV_AFL_MAX];
    uint8_t log_format[POOM_EMV_LOG_FORMAT_MAX];
    poom_nfc_emv_capture_t* capture;
    size_t capture_capacity;
    poom_nfc_emv_exchange_error_t last_exchange_error;
} poom_nfc_emv_workspace_t;

static unsigned s_poom_nfc_emv_transport_failures;

poom_nfc_emv_scheme_t poom_nfc_emv_scheme_from_aid(const uint8_t* aid, size_t aid_len)
{
    static const uint8_t visa_rid[5] = {0xA0U, 0x00U, 0x00U, 0x00U, 0x03U};
    static const uint8_t mastercard_rid[5] = {0xA0U, 0x00U, 0x00U, 0x00U, 0x04U};

    if(aid == NULL || aid_len < sizeof(visa_rid))
    {
        return POOM_NFC_EMV_SCHEME_UNKNOWN;
    }
    if(memcmp(aid, visa_rid, sizeof(visa_rid)) == 0)
    {
        return POOM_NFC_EMV_SCHEME_VISA;
    }
    if(memcmp(aid, mastercard_rid, sizeof(mastercard_rid)) == 0)
    {
        return POOM_NFC_EMV_SCHEME_MASTERCARD;
    }
    return POOM_NFC_EMV_SCHEME_UNKNOWN;
}

const char* poom_nfc_emv_scheme_str(poom_nfc_emv_scheme_t scheme)
{
    switch(scheme)
    {
        case POOM_NFC_EMV_SCHEME_VISA: return "Visa";
        case POOM_NFC_EMV_SCHEME_MASTERCARD: return "Mastercard";
        default: return "Unknown";
    }
}

const char* poom_nfc_emv_kernel_hint_str(poom_nfc_emv_scheme_t scheme)
{
    switch(scheme)
    {
        case POOM_NFC_EMV_SCHEME_VISA: return "Kernel 3 family (expected)";
        case POOM_NFC_EMV_SCHEME_MASTERCARD: return "Kernel 2 family (expected)";
        default: return "Not inferred";
    }
}

static poom_nfc_emv_details_t* poom_nfc_emv_details_get_(poom_nfc_emv_card_t* card)
{
    if(card == NULL)
    {
        return NULL;
    }
    if(card->details == NULL)
    {
        card->details = (poom_nfc_emv_details_t*)calloc(1U, sizeof(*card->details));
    }
    return card->details;
}

static void poom_nfc_emv_capture_exchange_(poom_nfc_emv_workspace_t* workspace,
                                           const uint8_t* command,
                                           size_t command_len,
                                           const uint8_t* response,
                                           size_t response_len,
                                           bool transport_ok)
{
    if(workspace == NULL || command == NULL || command_len > UINT16_MAX ||
       response_len > UINT16_MAX)
    {
        return;
    }

    size_t current_len = (workspace->capture != NULL) ? workspace->capture->data_len : 0U;
    size_t current_count =
        (workspace->capture != NULL) ? workspace->capture->exchange_count : 0U;
    const size_t required = current_len + command_len + response_len;
    if(current_count >= POOM_NFC_EMV_CAPTURE_EXCHANGE_MAX ||
       required > POOM_EMV_CAPTURE_DATA_MAX)
    {
        if(workspace->capture != NULL)
        {
            workspace->capture->truncated = true;
        }
        return;
    }

    if(workspace->capture == NULL || required > workspace->capture_capacity)
    {
        size_t new_capacity = (workspace->capture_capacity > 0U) ?
                                  workspace->capture_capacity : POOM_EMV_CAPTURE_DATA_INITIAL;
        while(new_capacity < required && new_capacity < POOM_EMV_CAPTURE_DATA_MAX)
        {
            new_capacity *= 2U;
        }
        if(new_capacity > POOM_EMV_CAPTURE_DATA_MAX)
        {
            new_capacity = POOM_EMV_CAPTURE_DATA_MAX;
        }
        poom_nfc_emv_capture_t* grown = (poom_nfc_emv_capture_t*)realloc(
            workspace->capture, sizeof(*grown) + new_capacity);
        if(grown == NULL)
        {
            if(workspace->capture != NULL)
            {
                workspace->capture->truncated = true;
            }
            return;
        }
        workspace->capture = grown;
        workspace->capture_capacity = new_capacity;
        if(current_count == 0U && current_len == 0U)
        {
            workspace->capture->data_len = 0U;
            workspace->capture->exchange_count = 0U;
            workspace->capture->truncated = false;
        }
    }

    poom_nfc_emv_exchange_t* exchange =
        &workspace->capture->exchanges[workspace->capture->exchange_count++];
    exchange->command_offset = (uint16_t)workspace->capture->data_len;
    exchange->command_len = (uint16_t)command_len;
    (void)memcpy(&workspace->capture->data[workspace->capture->data_len], command, command_len);
    workspace->capture->data_len += command_len;
    exchange->response_offset = (uint16_t)workspace->capture->data_len;
    exchange->response_len = (uint16_t)response_len;
    if(response_len > 0U && response != NULL)
    {
        (void)memcpy(&workspace->capture->data[workspace->capture->data_len], response, response_len);
        workspace->capture->data_len += response_len;
    }
    exchange->transport_ok = transport_ok;
}

static void poom_nfc_emv_capture_finalize_(poom_nfc_emv_workspace_t* workspace,
                                           poom_nfc_emv_card_t* card)
{
    if(workspace == NULL || card == NULL || workspace->capture == NULL ||
       workspace->capture->exchange_count == 0U)
    {
        return;
    }

    poom_nfc_emv_capture_t* exact = (poom_nfc_emv_capture_t*)realloc(
        workspace->capture, sizeof(*exact) + workspace->capture->data_len);
    if(exact != NULL)
    {
        workspace->capture = exact;
    }
    card->capture = workspace->capture;
    workspace->capture = NULL;
    workspace->capture_capacity = 0U;
}

static bool poom_nfc_emv_card_gone_(void)
{
    return s_poom_nfc_emv_transport_failures >= POOM_EMV_CARD_GONE_THRESHOLD;
}

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
 * @param[in,out] stop_requested Parameter passed to the function.
 * @return bool
 */
static bool poom_nfc_emv_walk_ppse_(const uint8_t* buf,
                                    size_t buf_len,
                                    poom_nfc_emv_app_cb_t cb,
                                    void* user_ctx,
                                    size_t* io_count,
                                    bool* stop_requested)
{
    size_t off = 0U;
    poom_tlv_view_t tlv;

    if((buf == NULL) || ((buf_len > 0U) && (stop_requested == NULL)))
    {
        return false;
    }

    while(poom_tlv_next(buf, buf_len, &off, &tlv))
    {
        if((stop_requested != NULL) && *stop_requested)
        {
            break;
        }

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
                    if(stop_requested != NULL)
                    {
                        *stop_requested = true;
                    }
                    break;
                }
            }
        }

        if(tlv.constructed && tlv.value_len > 0U)
        {
            if(!poom_nfc_emv_walk_ppse_(
                   tlv.value, tlv.value_len, cb, user_ctx, io_count, stop_requested))
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
    bool stop_requested = false;

    if(out_count != NULL)
    {
        *out_count = 0U;
    }

    if(!poom_iso7816_parse_rapdu(rapdu, rapdu_len, &view))
    {
        return false;
    }

    if(!poom_nfc_emv_walk_ppse_(
           view.data, view.data_len, cb, user_ctx, &count, &stop_requested))
    {
        return false;
    }

    if(out_count != NULL)
    {
        *out_count = count;
    }
    return true;
}

static bool poom_nfc_emv_tlv_find_(const uint8_t* buf,
                                    size_t buf_len,
                                    uint32_t wanted_tag,
                                    poom_tlv_view_t* out_tlv)
{
    size_t off = 0U;
    poom_tlv_view_t tlv;

    if(buf == NULL || out_tlv == NULL)
    {
        return false;
    }

    while(poom_tlv_next(buf, buf_len, &off, &tlv))
    {
        if(tlv.tag == wanted_tag)
        {
            *out_tlv = tlv;
            return true;
        }
        if(tlv.constructed && tlv.value_len > 0U &&
           poom_nfc_emv_tlv_find_(tlv.value, tlv.value_len, wanted_tag, out_tlv))
        {
            return true;
        }
    }

    return false;
}

/* Exchange one short C-APDU, including the common 6Cxx and 61xx recovery. */
static bool poom_nfc_emv_exchange_(poom_nfc_emv_workspace_t* workspace,
                                    const uint8_t* apdu,
                                    size_t apdu_len,
                                    uint8_t* out_data,
                                    size_t out_max,
                                    size_t* out_data_len)
{
    size_t command_len = apdu_len;
    size_t rapdu_len = 0U;
    size_t total = 0U;
    uint8_t get_response_count = 0U;
    bool length_corrected = false;

    if(workspace == NULL || apdu == NULL || apdu_len < 5U ||
       apdu_len > sizeof(workspace->command) || out_data_len == NULL)
    {
        return false;
    }
    *out_data_len = 0U;
    workspace->last_exchange_error = POOM_EMV_EXCHANGE_ERROR_NONE;
    (void)memcpy(workspace->command, apdu, apdu_len);

    for(;;)
    {
        poom_iso7816_rapdu_view_t view;

        if(!poom_reader_isodep_transceive_apdu(
               workspace->command,
               command_len,
               workspace->rapdu,
               sizeof(workspace->rapdu),
               &rapdu_len))
        {
            poom_nfc_emv_capture_exchange_(
                workspace, workspace->command, command_len, NULL, 0U, false);
            workspace->last_exchange_error = POOM_EMV_EXCHANGE_ERROR_TRANSPORT;
            if(s_poom_nfc_emv_transport_failures < 0xFFU)
            {
                s_poom_nfc_emv_transport_failures++;
            }
            return false;
        }
        s_poom_nfc_emv_transport_failures = 0U;
        poom_nfc_emv_capture_exchange_(workspace,
                                       workspace->command,
                                       command_len,
                                       workspace->rapdu,
                                       rapdu_len,
                                       true);
        if(!poom_iso7816_parse_rapdu(workspace->rapdu, rapdu_len, &view))
        {
            workspace->last_exchange_error = POOM_EMV_EXCHANGE_ERROR_RESPONSE;
            return false;
        }

        if(view.sw1 == 0x6CU && !length_corrected && total == 0U)
        {
            workspace->command[command_len - 1U] = view.sw2;
            length_corrected = true;
            continue;
        }

        if(view.data_len > (out_max - total) || (view.data_len > 0U && out_data == NULL))
        {
            workspace->last_exchange_error = POOM_EMV_EXCHANGE_ERROR_RESPONSE;
            return false;
        }
        if(view.data_len > 0U)
        {
            (void)memcpy(out_data + total, view.data, view.data_len);
            total += view.data_len;
        }

        if(view.sw1 == 0x61U && get_response_count < POOM_EMV_GET_RESPONSE_MAX)
        {
            const uint8_t get_response[5] = {0x00U, 0xC0U, 0x00U, 0x00U, view.sw2};
            (void)memcpy(workspace->command, get_response, sizeof(get_response));
            command_len = sizeof(get_response);
            get_response_count++;
            continue;
        }

        if(!poom_iso7816_status_is_ok(view.sw1, view.sw2))
        {
            workspace->last_exchange_error = POOM_EMV_EXCHANGE_ERROR_STATUS;
            return false;
        }
        *out_data_len = total;
        return true;
    }
}

static size_t poom_nfc_emv_build_apdu_(uint8_t cla,
                                       uint8_t ins,
                                       uint8_t p1,
                                       uint8_t p2,
                                       const uint8_t* data,
                                       size_t data_len,
                                       uint8_t* out,
                                       size_t out_max)
{
    if(out == NULL || data_len > 0xFFU || (data_len > 0U && data == NULL))
    {
        return 0U;
    }

    const size_t needed = (data_len > 0U) ? (data_len + 6U) : 5U;
    if(needed > out_max)
    {
        return 0U;
    }

    out[0] = cla;
    out[1] = ins;
    out[2] = p1;
    out[3] = p2;
    if(data_len == 0U)
    {
        out[4] = 0x00U;
        return 5U;
    }

    out[4] = (uint8_t)data_len;
    (void)memcpy(&out[5], data, data_len);
    out[5U + data_len] = 0x00U;
    return needed;
}

static bool poom_nfc_emv_select_body_(poom_nfc_emv_workspace_t* workspace,
                                      const uint8_t* name,
                                      size_t name_len,
                                      uint8_t* out_data,
                                      size_t out_max,
                                      size_t* out_data_len)
{
    if(workspace == NULL)
    {
        return false;
    }
    const size_t apdu_len = poom_iso7816_build_select_df_name(
        name, name_len, workspace->apdu, sizeof(workspace->apdu));

    return apdu_len > 0U &&
           poom_nfc_emv_exchange_(
               workspace, workspace->apdu, apdu_len, out_data, out_max, out_data_len);
}

static uint8_t poom_nfc_emv_bcd_(unsigned value)
{
    return (uint8_t)((((value / 10U) % 10U) << 4U) | (value % 10U));
}

static bool poom_nfc_emv_compile_date_(uint8_t out[3])
{
    static const char months[] = "JanFebMarAprMayJunJulAugSepOctNovDec";
    const char* build_date = __DATE__;
    unsigned month = 0U;
    unsigned day;
    unsigned year;

    if(out == NULL)
    {
        return false;
    }
    for(unsigned i = 0U; i < 12U; i++)
    {
        if(memcmp(build_date, &months[i * 3U], 3U) == 0)
        {
            month = i + 1U;
            break;
        }
    }
    if(month == 0U)
    {
        return false;
    }

    day = (build_date[4] == ' ') ? 0U : (unsigned)(build_date[4] - '0');
    day = day * 10U + (unsigned)(build_date[5] - '0');
    year = (unsigned)(build_date[7] - '0') * 1000U +
           (unsigned)(build_date[8] - '0') * 100U +
           (unsigned)(build_date[9] - '0') * 10U +
           (unsigned)(build_date[10] - '0');
    if(day == 0U || day > 31U || year < 2020U || year > 2099U)
    {
        return false;
    }

    out[0] = poom_nfc_emv_bcd_(year % 100U);
    out[1] = poom_nfc_emv_bcd_(month);
    out[2] = poom_nfc_emv_bcd_(day);
    return true;
}

static void poom_nfc_emv_pdol_value_(uint32_t tag, uint8_t* out, size_t len)
{
    uint8_t value[20] = {0};
    size_t value_len = 0U;

    if(out == NULL)
    {
        return;
    }
    (void)memset(out, 0, len);

    switch(tag)
    {
        case 0x9F66U: /* Terminal Transaction Qualifiers. */
            /* Read-only EMV-mode terminal; all RFU and unsupported CVM bits stay clear. */
            value[0] = 0x20U;
            value[1] = 0x00U;
            value[2] = 0x00U;
            value[3] = 0x00U;
            value_len = 4U;
            break;
        case 0x9F33U: /* Terminal capabilities. */
            value[0] = 0xE0U;
            value[1] = 0xF8U;
            value[2] = 0xC8U;
            value_len = 3U;
            break;
        case 0x9F35U: /* Unattended terminal, online capable. */
            value[0] = 0x22U;
            value_len = 1U;
            break;
        case 0x9F40U: /* Additional terminal capabilities. */
            value[0] = 0x60U;
            value[1] = 0x00U;
            value[2] = 0xF0U;
            value[3] = 0xA0U;
            value[4] = 0x01U;
            value_len = 5U;
            break;
        case 0x9A: /* Transaction date, YYMMDD. */
        {
            time_t now = time(NULL);
            struct tm utc_time;
            if(now > 0 && gmtime_r(&now, &utc_time) != NULL &&
               utc_time.tm_year >= 120 && utc_time.tm_year <= 199)
            {
                value[0] = poom_nfc_emv_bcd_((unsigned)((utc_time.tm_year + 1900) % 100));
                value[1] = poom_nfc_emv_bcd_((unsigned)(utc_time.tm_mon + 1));
                value[2] = poom_nfc_emv_bcd_((unsigned)utc_time.tm_mday);
                value_len = 3U;
            }
            else if(poom_nfc_emv_compile_date_(value))
            {
                value_len = 3U;
            }
            break;
        }
        case 0x9F21U: /* Transaction time, HHMMSS. */
        {
            time_t now = time(NULL);
            struct tm utc_time;
            if(now > 0 && gmtime_r(&now, &utc_time) != NULL)
            {
                value[0] = poom_nfc_emv_bcd_((unsigned)utc_time.tm_hour);
                value[1] = poom_nfc_emv_bcd_((unsigned)utc_time.tm_min);
                value[2] = poom_nfc_emv_bcd_((unsigned)utc_time.tm_sec);
                value_len = 3U;
            }
            break;
        }
        case 0x9F37U: /* Unpredictable number. */
        {
            const uint32_t random_value = esp_random();
            value[0] = (uint8_t)(random_value >> 24U);
            value[1] = (uint8_t)(random_value >> 16U);
            value[2] = (uint8_t)(random_value >> 8U);
            value[3] = (uint8_t)random_value;
            value_len = 4U;
            break;
        }
        case POOM_EMV_TAG_TERMINAL_COUNTRY:
            value[0] = (uint8_t)(POOM_NFC_EMV_TERMINAL_COUNTRY_CODE_BCD >> 8U);
            value[1] = (uint8_t)POOM_NFC_EMV_TERMINAL_COUNTRY_CODE_BCD;
            value_len = 2U;
            break;
        case POOM_EMV_TAG_TRANSACTION_CURRENCY:
            value[0] = (uint8_t)(POOM_NFC_EMV_TRANSACTION_CURRENCY_CODE_BCD >> 8U);
            value[1] = (uint8_t)POOM_NFC_EMV_TRANSACTION_CURRENCY_CODE_BCD;
            value_len = 2U;
            break;
        default:
            break;
    }

    if(value_len > len)
    {
        value_len = len;
    }
    if(value_len > 0U)
    {
        (void)memcpy(out, value, value_len);
    }
}

static bool poom_nfc_emv_dol_next_(const uint8_t* dol,
                                    size_t dol_len,
                                    size_t* io_off,
                                    uint32_t* out_tag,
                                    uint8_t* out_len)
{
    size_t off;
    uint32_t tag;
    uint8_t byte;

    if(dol == NULL || io_off == NULL || out_tag == NULL || out_len == NULL || *io_off >= dol_len)
    {
        return false;
    }

    off = *io_off;
    tag = dol[off++];
    if((tag & 0x1FU) == 0x1FU)
    {
        unsigned tag_bytes = 1U;
        do
        {
            if(off >= dol_len || tag_bytes >= 4U)
            {
                return false;
            }
            byte = dol[off++];
            tag = (tag << 8U) | byte;
            tag_bytes++;
        } while((byte & 0x80U) != 0U);
    }
    if(off >= dol_len)
    {
        return false;
    }

    *out_tag = tag;
    *out_len = dol[off++];
    *io_off = off;
    return true;
}

static bool poom_nfc_emv_prepare_pdol_(const uint8_t* pdol,
                                       size_t pdol_len,
                                       uint8_t* out,
                                       size_t out_max,
                                       size_t* out_len)
{
    size_t in_off = 0U;
    size_t out_off = 0U;

    if(out == NULL || out_len == NULL || (pdol_len > 0U && pdol == NULL))
    {
        return false;
    }

    while(in_off < pdol_len)
    {
        uint32_t tag;
        uint8_t value_len;
        if(!poom_nfc_emv_dol_next_(pdol, pdol_len, &in_off, &tag, &value_len) ||
           value_len > (out_max - out_off))
        {
            return false;
        }
        poom_nfc_emv_pdol_value_(tag, &out[out_off], value_len);
        out_off += value_len;
    }

    *out_len = out_off;
    return true;
}

static void poom_nfc_emv_copy_text_(char* out,
                                    size_t out_max,
                                    const uint8_t* value,
                                    size_t value_len)
{
    size_t copied = 0U;

    if(out == NULL || out_max == 0U || value == NULL)
    {
        return;
    }
    while(copied < value_len && copied + 1U < out_max)
    {
        const uint8_t c = value[copied];
        out[copied] = (c >= 0x20U && c <= 0x7EU) ? (char)c : '?';
        copied++;
    }
    while(copied > 0U && out[copied - 1U] == ' ')
    {
        copied--;
    }
    out[copied] = '\0';
}

static void poom_nfc_emv_set_pan_bcd_(poom_nfc_emv_card_t* card,
                                      const uint8_t* value,
                                      size_t value_len)
{
    if(card == NULL || value == NULL || card->pan_len > 0U)
    {
        return;
    }

    for(size_t i = 0U; i < value_len && card->pan_len < POOM_NFC_EMV_PAN_MAX_DIGITS; i++)
    {
        const uint8_t nibbles[2] = {(uint8_t)(value[i] >> 4U), (uint8_t)(value[i] & 0x0FU)};
        for(size_t n = 0U; n < 2U; n++)
        {
            if(nibbles[n] > 9U)
            {
                card->pan[card->pan_len] = '\0';
                return;
            }
            card->pan[card->pan_len++] = (char)('0' + nibbles[n]);
        }
    }
    card->pan[card->pan_len] = '\0';
}

static uint64_t poom_nfc_emv_bcd_amount_(const uint8_t* value, size_t value_len);

static void poom_nfc_emv_decode_track1_(poom_nfc_emv_card_t* card,
                                        const uint8_t* value,
                                        size_t value_len)
{
    size_t start = 0U;
    size_t first_separator;
    size_t second_separator;

    if(card == NULL || value == NULL || value_len == 0U)
    {
        return;
    }
    if(value[start] == (uint8_t)'%')
    {
        start++;
    }
    if(start < value_len && value[start] == (uint8_t)'B')
    {
        start++;
    }
    first_separator = start;
    while(first_separator < value_len && value[first_separator] != (uint8_t)'^')
    {
        first_separator++;
    }
    if(first_separator >= value_len)
    {
        return;
    }

    if(card->pan_len == 0U)
    {
        for(size_t i = start;
            i < first_separator && card->pan_len < POOM_NFC_EMV_PAN_MAX_DIGITS;
            i++)
        {
            if(value[i] < (uint8_t)'0' || value[i] > (uint8_t)'9')
            {
                card->pan_len = 0U;
                card->pan[0] = '\0';
                break;
            }
            card->pan[card->pan_len++] = (char)value[i];
        }
        card->pan[card->pan_len] = '\0';
    }

    second_separator = first_separator + 1U;
    while(second_separator < value_len && value[second_separator] != (uint8_t)'^')
    {
        second_separator++;
    }
    if(second_separator >= value_len)
    {
        return;
    }
    if(card->cardholder_name[0] == '\0' && second_separator > first_separator + 1U)
    {
        poom_nfc_emv_copy_text_(card->cardholder_name,
                                sizeof(card->cardholder_name),
                                &value[first_separator + 1U],
                                second_separator - first_separator - 1U);
    }

    const size_t discretionary = second_separator + 1U;
    if(discretionary + 4U <= value_len && !card->has_expiration_date)
    {
        bool valid = true;
        uint8_t digits[4];
        for(size_t i = 0U; i < sizeof(digits); i++)
        {
            if(value[discretionary + i] < (uint8_t)'0' ||
               value[discretionary + i] > (uint8_t)'9')
            {
                valid = false;
                digits[i] = 0U;
            }
            else
            {
                digits[i] = (uint8_t)(value[discretionary + i] - (uint8_t)'0');
            }
        }
        if(valid)
        {
            card->expiration_date[0] = (uint8_t)((digits[0] << 4U) | digits[1]);
            card->expiration_date[1] = (uint8_t)((digits[2] << 4U) | digits[3]);
            card->expiration_date[2] = 0U;
            card->has_expiration_date = true;
        }
    }
    if(discretionary + 7U <= value_len && !card->has_service_code)
    {
        uint16_t service_code = 0U;
        bool valid = true;
        for(size_t i = 4U; i < 7U; i++)
        {
            if(value[discretionary + i] < (uint8_t)'0' ||
               value[discretionary + i] > (uint8_t)'9')
            {
                valid = false;
                break;
            }
            service_code = (uint16_t)(service_code * 10U +
                                      (uint16_t)(value[discretionary + i] - (uint8_t)'0'));
        }
        if(valid)
        {
            card->service_code = service_code;
            card->has_service_code = true;
        }
    }
}

static void poom_nfc_emv_decode_track2_(poom_nfc_emv_card_t* card,
                                        const uint8_t* value,
                                        size_t value_len)
{
    bool separator_seen = false;
    const bool collect_pan = (card != NULL && card->pan_len == 0U);
    uint8_t post_separator_digits[7] = {0};
    size_t post_separator_count = 0U;

    if(card == NULL || value == NULL)
    {
        return;
    }

    for(size_t i = 0U; i < value_len; i++)
    {
        const uint8_t nibbles[2] = {(uint8_t)(value[i] >> 4U), (uint8_t)(value[i] & 0x0FU)};
        for(size_t n = 0U; n < 2U; n++)
        {
            const uint8_t nibble = nibbles[n];
            if(!separator_seen)
            {
                if(nibble == 0x0DU)
                {
                    separator_seen = true;
                }
                else if(collect_pan && nibble <= 9U && card->pan_len < POOM_NFC_EMV_PAN_MAX_DIGITS)
                {
                    card->pan[card->pan_len++] = (char)('0' + nibble);
                    card->pan[card->pan_len] = '\0';
                }
            }
            else if(nibble <= 9U && post_separator_count < sizeof(post_separator_digits))
            {
                post_separator_digits[post_separator_count++] = nibble;
            }
        }
    }

    if(post_separator_count >= 4U && !card->has_expiration_date)
    {
        card->expiration_date[0] =
            (uint8_t)((post_separator_digits[0] << 4U) | post_separator_digits[1]);
        card->expiration_date[1] =
            (uint8_t)((post_separator_digits[2] << 4U) | post_separator_digits[3]);
        card->expiration_date[2] = 0U;
        card->has_expiration_date = true;
    }
    if(post_separator_count >= 7U && !card->has_service_code)
    {
        card->service_code = (uint16_t)(post_separator_digits[4] * 100U +
                                        post_separator_digits[5] * 10U +
                                        post_separator_digits[6]);
        card->has_service_code = true;
    }
}

static size_t poom_nfc_emv_copy_binary_(uint8_t* out,
                                        size_t out_max,
                                        const uint8_t* value,
                                        size_t value_len)
{
    const size_t copy_len = (value_len < out_max) ? value_len : out_max;
    if(out != NULL && value != NULL && copy_len > 0U)
    {
        (void)memcpy(out, value, copy_len);
    }
    return copy_len;
}

static void poom_nfc_emv_decode_common_details_(const uint8_t* buf,
                                                size_t buf_len,
                                                poom_nfc_emv_card_t* card)
{
    poom_tlv_view_t tlv;
    poom_nfc_emv_details_t* details;

    if(buf == NULL || card == NULL)
    {
        return;
    }

#define POOM_EMV_DETAILS_FIND(tag_value)                                                   \
    (poom_nfc_emv_tlv_find_(buf, buf_len, (tag_value), &tlv) &&                           \
     ((details = poom_nfc_emv_details_get_(card)) != NULL))

    details = card->details;
    if(POOM_EMV_DETAILS_FIND(POOM_EMV_TAG_LANGUAGE_PREFERENCE) &&
       details->language_preferences_len == 0U)
    {
        details->language_preferences_len = poom_nfc_emv_copy_binary_(
            details->language_preferences,
            sizeof(details->language_preferences),
            tlv.value,
            tlv.value_len);
    }
    if(POOM_EMV_DETAILS_FIND(POOM_EMV_TAG_APPLICATION_VERSION_NUMBER) &&
       !details->has_application_version_number && tlv.value_len >= 2U)
    {
        details->application_version_number =
            (uint16_t)(((uint16_t)tlv.value[0] << 8U) | tlv.value[1]);
        details->has_application_version_number = true;
    }
    if(POOM_EMV_DETAILS_FIND(POOM_EMV_TAG_APPLICATION_USAGE_CONTROL) &&
       !details->has_application_usage_control && tlv.value_len >= 2U)
    {
        details->application_usage_control[0] = tlv.value[0];
        details->application_usage_control[1] = tlv.value[1];
        details->has_application_usage_control = true;
    }
    if(POOM_EMV_DETAILS_FIND(POOM_EMV_TAG_CVM_LIST) && details->cvm_list_len == 0U)
    {
        details->cvm_list_len = poom_nfc_emv_copy_binary_(
            details->cvm_list, sizeof(details->cvm_list), tlv.value, tlv.value_len);
    }
    if(POOM_EMV_DETAILS_FIND(POOM_EMV_TAG_CDOL1) && details->cdol1_len == 0U)
    {
        details->cdol1_len = poom_nfc_emv_copy_binary_(
            details->cdol1, sizeof(details->cdol1), tlv.value, tlv.value_len);
    }
    if(POOM_EMV_DETAILS_FIND(POOM_EMV_TAG_CDOL2) && details->cdol2_len == 0U)
    {
        details->cdol2_len = poom_nfc_emv_copy_binary_(
            details->cdol2, sizeof(details->cdol2), tlv.value, tlv.value_len);
    }
    if(POOM_EMV_DETAILS_FIND(POOM_EMV_TAG_IAC_DEFAULT) &&
       !details->has_issuer_action_code_default && tlv.value_len >= POOM_NFC_EMV_IAC_LEN)
    {
        (void)memcpy(details->issuer_action_code_default, tlv.value, POOM_NFC_EMV_IAC_LEN);
        details->has_issuer_action_code_default = true;
    }
    if(POOM_EMV_DETAILS_FIND(POOM_EMV_TAG_IAC_DENIAL) &&
       !details->has_issuer_action_code_denial && tlv.value_len >= POOM_NFC_EMV_IAC_LEN)
    {
        (void)memcpy(details->issuer_action_code_denial, tlv.value, POOM_NFC_EMV_IAC_LEN);
        details->has_issuer_action_code_denial = true;
    }
    if(POOM_EMV_DETAILS_FIND(POOM_EMV_TAG_IAC_ONLINE) &&
       !details->has_issuer_action_code_online && tlv.value_len >= POOM_NFC_EMV_IAC_LEN)
    {
        (void)memcpy(details->issuer_action_code_online, tlv.value, POOM_NFC_EMV_IAC_LEN);
        details->has_issuer_action_code_online = true;
    }
    if(POOM_EMV_DETAILS_FIND(POOM_EMV_TAG_SDA_TAG_LIST) && details->sda_tag_list_len == 0U)
    {
        details->sda_tag_list_len = poom_nfc_emv_copy_binary_(
            details->sda_tag_list, sizeof(details->sda_tag_list), tlv.value, tlv.value_len);
    }
    if(POOM_EMV_DETAILS_FIND(POOM_EMV_TAG_CA_PUBLIC_KEY_INDEX) &&
       !details->has_ca_public_key_index && tlv.value_len >= 1U)
    {
        details->ca_public_key_index = tlv.value[0];
        details->has_ca_public_key_index = true;
    }
    if(POOM_EMV_DETAILS_FIND(POOM_EMV_TAG_ISSUER_PUBLIC_KEY_CERTIFICATE) &&
       details->issuer_public_key_certificate_len == 0U)
    {
        details->issuer_public_key_certificate_len = tlv.value_len;
    }
    if(POOM_EMV_DETAILS_FIND(POOM_EMV_TAG_ISSUER_PUBLIC_KEY_REMAINDER) &&
       details->issuer_public_key_remainder_len == 0U)
    {
        details->issuer_public_key_remainder_len = tlv.value_len;
    }
    if(POOM_EMV_DETAILS_FIND(POOM_EMV_TAG_ISSUER_PUBLIC_KEY_EXPONENT) &&
       details->issuer_public_key_exponent_len == 0U)
    {
        details->issuer_public_key_exponent_len = poom_nfc_emv_copy_binary_(
            details->issuer_public_key_exponent,
            sizeof(details->issuer_public_key_exponent),
            tlv.value,
            tlv.value_len);
    }
    if(POOM_EMV_DETAILS_FIND(POOM_EMV_TAG_ICC_PUBLIC_KEY_CERTIFICATE) &&
       details->icc_public_key_certificate_len == 0U)
    {
        details->icc_public_key_certificate_len = tlv.value_len;
    }
    if(POOM_EMV_DETAILS_FIND(POOM_EMV_TAG_ICC_PUBLIC_KEY_REMAINDER) &&
       details->icc_public_key_remainder_len == 0U)
    {
        details->icc_public_key_remainder_len = tlv.value_len;
    }
    if(POOM_EMV_DETAILS_FIND(POOM_EMV_TAG_ICC_PUBLIC_KEY_EXPONENT) &&
       details->icc_public_key_exponent_len == 0U)
    {
        details->icc_public_key_exponent_len = poom_nfc_emv_copy_binary_(
            details->icc_public_key_exponent,
            sizeof(details->icc_public_key_exponent),
            tlv.value,
            tlv.value_len);
    }
    if(POOM_EMV_DETAILS_FIND(POOM_EMV_TAG_DDOL) && details->ddol_len == 0U)
    {
        details->ddol_len = poom_nfc_emv_copy_binary_(
            details->ddol, sizeof(details->ddol), tlv.value, tlv.value_len);
    }
    if(POOM_EMV_DETAILS_FIND(POOM_EMV_TAG_CUSTOMER_EXCLUSIVE_DATA) &&
       details->customer_exclusive_data_len == 0U)
    {
        details->customer_exclusive_data_len = poom_nfc_emv_copy_binary_(
            details->customer_exclusive_data,
            sizeof(details->customer_exclusive_data),
            tlv.value,
            tlv.value_len);
    }

#undef POOM_EMV_DETAILS_FIND
}

static void poom_nfc_emv_decode_visa_(const uint8_t* buf,
                                      size_t buf_len,
                                      poom_nfc_emv_card_t* card)
{
    poom_tlv_view_t tlv;

    if(card->application_program_identifier_len == 0U &&
       poom_nfc_emv_tlv_find_(buf, buf_len, POOM_EMV_TAG_APPLICATION_PROGRAM_IDENTIFIER, &tlv))
    {
        card->application_program_identifier_len = poom_nfc_emv_copy_binary_(
            card->application_program_identifier,
            sizeof(card->application_program_identifier),
            tlv.value,
            tlv.value_len);
    }
    if(!card->has_offline_spending_amount &&
       poom_nfc_emv_tlv_find_(buf, buf_len, POOM_EMV_TAG_SCHEME_9F5D, &tlv))
    {
        card->offline_spending_amount = poom_nfc_emv_bcd_amount_(tlv.value, tlv.value_len);
        card->has_offline_spending_amount = true;
    }
    if(card->card_transaction_qualifiers_len == 0U &&
       poom_nfc_emv_tlv_find_(buf, buf_len, POOM_EMV_TAG_SCHEME_9F6C, &tlv))
    {
        card->card_transaction_qualifiers_len = poom_nfc_emv_copy_binary_(
            card->card_transaction_qualifiers,
            sizeof(card->card_transaction_qualifiers),
            tlv.value,
            tlv.value_len);
    }
    if(card->form_factor_indicator_len == 0U &&
       poom_nfc_emv_tlv_find_(buf, buf_len, POOM_EMV_TAG_SCHEME_9F6E, &tlv))
    {
        card->form_factor_indicator_len = poom_nfc_emv_copy_binary_(
            card->form_factor_indicator,
            sizeof(card->form_factor_indicator),
            tlv.value,
            tlv.value_len);
    }
}

static void poom_nfc_emv_decode_mastercard_(const uint8_t* buf,
                                            size_t buf_len,
                                            poom_nfc_emv_card_t* card)
{
    poom_tlv_view_t tlv;
    poom_nfc_emv_details_t* details;

    if(poom_nfc_emv_tlv_find_(buf, buf_len, POOM_EMV_TAG_SCHEME_9F5D, &tlv) &&
       (details = poom_nfc_emv_details_get_(card)) != NULL &&
       details->mastercard_application_capabilities_len == 0U)
    {
        details->mastercard_application_capabilities_len = poom_nfc_emv_copy_binary_(
            details->mastercard_application_capabilities,
            sizeof(details->mastercard_application_capabilities),
            tlv.value,
            tlv.value_len);
    }
    if(poom_nfc_emv_tlv_find_(buf, buf_len, POOM_EMV_TAG_SCHEME_9F6C, &tlv) &&
       (details = poom_nfc_emv_details_get_(card)) != NULL &&
       details->mastercard_9f6c_len == 0U)
    {
        details->mastercard_9f6c_len = poom_nfc_emv_copy_binary_(
            details->mastercard_9f6c, sizeof(details->mastercard_9f6c), tlv.value, tlv.value_len);
    }
    if(poom_nfc_emv_tlv_find_(buf, buf_len, POOM_EMV_TAG_SCHEME_9F6E, &tlv) &&
       (details = poom_nfc_emv_details_get_(card)) != NULL &&
       details->mastercard_third_party_data_len == 0U)
    {
        details->mastercard_third_party_data_len = poom_nfc_emv_copy_binary_(
            details->mastercard_third_party_data,
            sizeof(details->mastercard_third_party_data),
            tlv.value,
            tlv.value_len);
    }
}

static void poom_nfc_emv_decode_scheme_details_(const uint8_t* buf,
                                                size_t buf_len,
                                                poom_nfc_emv_card_t* card)
{
    if(card == NULL)
    {
        return;
    }
    if(card->scheme == POOM_NFC_EMV_SCHEME_VISA)
    {
        poom_nfc_emv_decode_visa_(buf, buf_len, card);
    }
    else if(card->scheme == POOM_NFC_EMV_SCHEME_MASTERCARD)
    {
        poom_nfc_emv_decode_mastercard_(buf, buf_len, card);
    }
}

static void poom_nfc_emv_decode_records_(const uint8_t* buf,
                                         size_t buf_len,
                                         poom_nfc_emv_card_t* card,
                                         uint8_t* out_log_sfi,
                                         uint8_t* out_log_records)
{
    poom_tlv_view_t tlv;

    if(buf == NULL || card == NULL)
    {
        return;
    }

    if(card->pan_len == 0U && poom_nfc_emv_tlv_find_(buf, buf_len, POOM_EMV_TAG_PAN, &tlv))
    {
        poom_nfc_emv_set_pan_bcd_(card, tlv.value, tlv.value_len);
    }
    if(poom_nfc_emv_tlv_find_(buf, buf_len, POOM_EMV_TAG_TRACK_1_DATA, &tlv))
    {
        poom_nfc_emv_decode_track1_(card, tlv.value, tlv.value_len);
    }
    if(poom_nfc_emv_tlv_find_(buf, buf_len, POOM_EMV_TAG_TRACK_2_EQUIVALENT, &tlv))
    {
        poom_nfc_emv_decode_track2_(card, tlv.value, tlv.value_len);
    }
    else if(poom_nfc_emv_tlv_find_(buf, buf_len, POOM_EMV_TAG_TRACK_2_DATA, &tlv))
    {
        poom_nfc_emv_decode_track2_(card, tlv.value, tlv.value_len);
    }
    if(card->cardholder_name[0] == '\0' &&
       poom_nfc_emv_tlv_find_(buf, buf_len, POOM_EMV_TAG_CARDHOLDER_NAME, &tlv))
    {
        poom_nfc_emv_copy_text_(card->cardholder_name, sizeof(card->cardholder_name), tlv.value, tlv.value_len);
    }
    if(card->cardholder_name[0] == '\0' &&
       poom_nfc_emv_tlv_find_(buf, buf_len, POOM_EMV_TAG_CARDHOLDER_NAME_EXTENDED, &tlv))
    {
        poom_nfc_emv_copy_text_(card->cardholder_name, sizeof(card->cardholder_name), tlv.value, tlv.value_len);
    }
    if(poom_nfc_emv_tlv_find_(buf, buf_len, POOM_EMV_TAG_EXPIRATION_DATE, &tlv) && tlv.value_len >= 2U)
    {
        const size_t copy_len = (tlv.value_len < 3U) ? tlv.value_len : 3U;
        (void)memcpy(card->expiration_date, tlv.value, copy_len);
        card->has_expiration_date = true;
    }
    if(poom_nfc_emv_tlv_find_(buf, buf_len, POOM_EMV_TAG_EFFECTIVE_DATE, &tlv) && tlv.value_len >= 2U)
    {
        const size_t copy_len = (tlv.value_len < 3U) ? tlv.value_len : 3U;
        (void)memcpy(card->effective_date, tlv.value, copy_len);
        card->has_effective_date = true;
    }
    if(poom_nfc_emv_tlv_find_(buf, buf_len, POOM_EMV_TAG_COUNTRY_CODE, &tlv) && tlv.value_len >= 2U)
    {
        card->country_code = (uint16_t)(((uint16_t)tlv.value[0] << 8U) | tlv.value[1]);
        card->has_country_code = true;
    }
    if(poom_nfc_emv_tlv_find_(buf, buf_len, POOM_EMV_TAG_CURRENCY_CODE, &tlv) && tlv.value_len >= 2U)
    {
        card->currency_code = (uint16_t)(((uint16_t)tlv.value[0] << 8U) | tlv.value[1]);
        card->has_currency_code = true;
    }
    if(poom_nfc_emv_tlv_find_(buf, buf_len, POOM_EMV_TAG_ATC, &tlv) && tlv.value_len >= 2U)
    {
        card->application_transaction_counter =
            (uint16_t)(((uint16_t)tlv.value[0] << 8U) | tlv.value[1]);
        card->has_application_transaction_counter = true;
    }
    if(!card->has_aip && poom_nfc_emv_tlv_find_(buf, buf_len, POOM_EMV_TAG_AIP, &tlv) &&
       tlv.value_len >= 2U)
    {
        card->aip[0] = tlv.value[0];
        card->aip[1] = tlv.value[1];
        card->has_aip = true;
    }
    if(!card->has_pan_sequence_number &&
       poom_nfc_emv_tlv_find_(buf, buf_len, POOM_EMV_TAG_PAN_SEQUENCE_NUMBER, &tlv) &&
       tlv.value_len >= 1U)
    {
        card->pan_sequence_number = tlv.value[0];
        card->has_pan_sequence_number = true;
    }
    if(!card->has_issuer_code_table_index &&
       poom_nfc_emv_tlv_find_(buf, buf_len, POOM_EMV_TAG_ISSUER_CODE_TABLE_INDEX, &tlv) &&
       tlv.value_len >= 1U)
    {
        card->issuer_code_table_index = tlv.value[0];
        card->has_issuer_code_table_index = true;
    }
    if(card->issuer_application_data_len == 0U &&
       poom_nfc_emv_tlv_find_(buf, buf_len, POOM_EMV_TAG_ISSUER_APPLICATION_DATA, &tlv))
    {
        card->issuer_application_data_len = poom_nfc_emv_copy_binary_(
            card->issuer_application_data, sizeof(card->issuer_application_data), tlv.value, tlv.value_len);
    }
    if(card->application_cryptogram_len == 0U &&
       poom_nfc_emv_tlv_find_(buf, buf_len, POOM_EMV_TAG_APPLICATION_CRYPTOGRAM, &tlv))
    {
        card->application_cryptogram_len = poom_nfc_emv_copy_binary_(
            card->application_cryptogram, sizeof(card->application_cryptogram), tlv.value, tlv.value_len);
    }
    if(!card->has_cryptogram_information_data &&
       poom_nfc_emv_tlv_find_(buf, buf_len, POOM_EMV_TAG_CRYPTOGRAM_INFORMATION_DATA, &tlv) &&
       tlv.value_len >= 1U)
    {
        card->cryptogram_information_data = tlv.value[0];
        card->has_cryptogram_information_data = true;
    }
    if(card->pdol_definition_len == 0U &&
       poom_nfc_emv_tlv_find_(buf, buf_len, POOM_EMV_TAG_PDOL, &tlv))
    {
        card->pdol_definition_len = poom_nfc_emv_copy_binary_(
            card->pdol_definition, sizeof(card->pdol_definition), tlv.value, tlv.value_len);
    }
    if(out_log_sfi != NULL && out_log_records != NULL &&
       poom_nfc_emv_tlv_find_(buf, buf_len, POOM_EMV_TAG_LOG_ENTRY, &tlv) && tlv.value_len >= 2U)
    {
        *out_log_sfi = tlv.value[0];
        *out_log_records = tlv.value[1];
    }
    poom_nfc_emv_decode_common_details_(buf, buf_len, card);
    poom_nfc_emv_decode_scheme_details_(buf, buf_len, card);
}

static bool poom_nfc_emv_read_record_(poom_nfc_emv_workspace_t* workspace,
                                      uint8_t sfi,
                                      uint8_t record,
                                      uint8_t* out,
                                      size_t out_max,
                                      size_t* out_len)
{
    uint8_t apdu[5];
    const size_t apdu_len = poom_nfc_emv_build_apdu_(
        0x00U, 0xB2U, record, (uint8_t)((sfi << 3U) | 0x04U), NULL, 0U, apdu, sizeof(apdu));

    return apdu_len > 0U &&
           poom_nfc_emv_exchange_(workspace, apdu, apdu_len, out, out_max, out_len);
}

static bool poom_nfc_emv_get_data_(poom_nfc_emv_workspace_t* workspace,
                                   uint32_t tag,
                                   uint8_t* out,
                                   size_t out_max,
                                   size_t* out_len)
{
    uint8_t apdu[5];
    const size_t apdu_len = poom_nfc_emv_build_apdu_(0x80U,
                                                     0xCAU,
                                                     (uint8_t)(tag >> 8U),
                                                     (uint8_t)tag,
                                                     NULL,
                                                     0U,
                                                     apdu,
                                                     sizeof(apdu));

    return apdu_len > 0U &&
           poom_nfc_emv_exchange_(workspace, apdu, apdu_len, out, out_max, out_len);
}

static bool poom_nfc_emv_get_optional_data_(poom_nfc_emv_workspace_t* workspace,
                                            poom_nfc_emv_card_t* card,
                                            uint32_t tag,
                                            uint8_t* out,
                                            size_t out_max,
                                            size_t* out_len)
{
    const bool result = poom_nfc_emv_get_data_(workspace, tag, out, out_max, out_len);
    if(!result && card != NULL &&
       workspace->last_exchange_error == POOM_EMV_EXCHANGE_ERROR_STATUS)
    {
        card->optional_data_unsupported = true;
    }
    return result;
}

static uint64_t poom_nfc_emv_bcd_amount_(const uint8_t* value, size_t value_len)
{
    uint64_t result = 0U;

    for(size_t i = 0U; i < value_len && i < 6U; i++)
    {
        result = result * 100U + (uint64_t)((value[i] >> 4U) * 10U + (value[i] & 0x0FU));
    }
    return result;
}

static void poom_nfc_emv_decode_log_(const uint8_t* record,
                                     size_t record_len,
                                     const uint8_t* format,
                                     size_t format_len,
                                     poom_nfc_emv_transaction_t* transaction)
{
    poom_tlv_view_t wrapper;
    size_t format_off = 0U;
    size_t record_off = 0U;

    if(record == NULL || format == NULL || transaction == NULL)
    {
        return;
    }
    (void)memset(transaction, 0, sizeof(*transaction));

    if(poom_tlv_parse_one(record, record_len, &wrapper) &&
       wrapper.tag == POOM_EMV_TAG_READ_RECORD_TEMPLATE && wrapper.total_len <= record_len)
    {
        record = wrapper.value;
        record_len = wrapper.value_len;
    }

    while(format_off < format_len && record_off < record_len)
    {
        uint32_t tag;
        uint8_t value_len;
        if(!poom_nfc_emv_dol_next_(format, format_len, &format_off, &tag, &value_len) ||
           value_len > (record_len - record_off))
        {
            break;
        }

        const uint8_t* value = &record[record_off];
        switch(tag)
        {
            case POOM_EMV_TAG_ATC:
                if(value_len >= 2U)
                {
                    transaction->atc = (uint16_t)(((uint16_t)value[0] << 8U) | value[1]);
                    transaction->has_atc = true;
                }
                break;
            case POOM_EMV_TAG_AMOUNT_AUTHORISED:
                transaction->amount = poom_nfc_emv_bcd_amount_(value, value_len);
                transaction->has_amount = true;
                break;
            case POOM_EMV_TAG_TERMINAL_COUNTRY:
                if(value_len >= 2U)
                {
                    transaction->country_code = (uint16_t)(((uint16_t)value[0] << 8U) | value[1]);
                    transaction->has_country_code = true;
                }
                break;
            case POOM_EMV_TAG_TRANSACTION_CURRENCY:
                if(value_len >= 2U)
                {
                    transaction->currency_code = (uint16_t)(((uint16_t)value[0] << 8U) | value[1]);
                    transaction->has_currency_code = true;
                }
                break;
            case POOM_EMV_TAG_TRANSACTION_DATE:
                if(value_len >= 3U)
                {
                    (void)memcpy(transaction->date, value, 3U);
                    transaction->has_date = true;
                }
                break;
            case POOM_EMV_TAG_TRANSACTION_TIME:
                if(value_len >= 3U)
                {
                    (void)memcpy(transaction->time, value, 3U);
                    transaction->has_time = true;
                }
                break;
            default:
                break;
        }
        record_off += value_len;
    }
}

static bool poom_nfc_emv_read_application_with_workspace_(poom_nfc_emv_workspace_t* workspace,
                                                          const uint8_t* aid,
                                                          size_t aid_len,
                                                          poom_nfc_emv_card_t* out_card)
{
#define response (workspace->response)
#define pdol_data (workspace->pdol_data)
#define gpo_data (workspace->gpo_data)
#define apdu (workspace->apdu)
#define afl (workspace->afl)
#define log_format (workspace->log_format)
    size_t response_len = 0U;
    size_t pdol_data_len = 0U;
    size_t gpo_data_len = 0U;
    size_t afl_len = 0U;
    size_t log_format_len = 0U;
    uint8_t log_sfi = 0U;
    uint8_t log_records = 0U;
    bool gpo_response_received = false;
    poom_tlv_view_t tlv;

    if(workspace == NULL || aid == NULL || aid_len == 0U ||
       aid_len > POOM_NFC_EMV_AID_MAX_LEN || out_card == NULL)
    {
        return false;
    }

    (void)memset(out_card, 0, sizeof(*out_card));
    out_card->read_status = POOM_NFC_EMV_READ_STATUS_NOT_STARTED;
    s_poom_nfc_emv_transport_failures = 0U;
    (void)memcpy(out_card->aid, aid, aid_len);
    out_card->aid_len = aid_len;
    out_card->scheme = poom_nfc_emv_scheme_from_aid(aid, aid_len);

    if(!poom_nfc_emv_select_body_(
           workspace, aid, aid_len, response, sizeof(response), &response_len))
    {
        out_card->read_status = POOM_NFC_EMV_READ_STATUS_SELECT_FAILED;
        return false;
    }
    out_card->read_status = POOM_NFC_EMV_READ_STATUS_PARTIAL;

    if(poom_nfc_emv_tlv_find_(response, response_len, POOM_EMV_TAG_APPLICATION_LABEL, &tlv))
    {
        poom_nfc_emv_copy_text_(out_card->application_label,
                                sizeof(out_card->application_label),
                                tlv.value,
                                tlv.value_len);
    }
    if(poom_nfc_emv_tlv_find_(response, response_len, POOM_EMV_TAG_PREFERRED_NAME, &tlv))
    {
        poom_nfc_emv_copy_text_(out_card->application_name,
                                sizeof(out_card->application_name),
                                tlv.value,
                                tlv.value_len);
    }
    if(poom_nfc_emv_tlv_find_(response, response_len, POOM_EMV_TAG_APPLICATION_PRIORITY, &tlv) &&
       tlv.value_len >= 1U)
    {
        out_card->priority = tlv.value[0];
        out_card->has_priority = true;
    }
    poom_nfc_emv_decode_records_(response, response_len, out_card, &log_sfi, &log_records);

    if(poom_nfc_emv_tlv_find_(response, response_len, POOM_EMV_TAG_PDOL, &tlv))
    {
        if(!poom_nfc_emv_prepare_pdol_(
               tlv.value, tlv.value_len, pdol_data, sizeof(pdol_data), &pdol_data_len))
        {
            pdol_data_len = 0U;
        }
    }

    if(pdol_data_len <= 0x7FU)
    {
        gpo_data[0] = 0x83U;
        gpo_data[1] = (uint8_t)pdol_data_len;
        gpo_data_len = 2U;
    }
    else
    {
        gpo_data[0] = 0x83U;
        gpo_data[1] = 0x81U;
        gpo_data[2] = (uint8_t)pdol_data_len;
        gpo_data_len = 3U;
    }
    (void)memcpy(&gpo_data[gpo_data_len], pdol_data, pdol_data_len);
    gpo_data_len += pdol_data_len;

    const size_t gpo_apdu_len = poom_nfc_emv_build_apdu_(
        0x80U, 0xA8U, 0x00U, 0x00U, gpo_data, gpo_data_len, apdu, sizeof(apdu));
    if(gpo_apdu_len == 0U)
    {
        out_card->read_status = POOM_NFC_EMV_READ_STATUS_GPO_INVALID;
    }
    else if(poom_nfc_emv_exchange_(
                workspace, apdu, gpo_apdu_len, response, sizeof(response), &response_len))
    {
        gpo_response_received = true;
        if(poom_nfc_emv_tlv_find_(response, response_len, POOM_EMV_TAG_GPO_FORMAT_1, &tlv) &&
           tlv.value_len >= 2U)
        {
            out_card->aip[0] = tlv.value[0];
            out_card->aip[1] = tlv.value[1];
            out_card->has_aip = true;
            afl_len = tlv.value_len - 2U;
            if(afl_len > sizeof(afl))
            {
                afl_len = sizeof(afl);
            }
            (void)memcpy(afl, &tlv.value[2], afl_len);
        }
        else
        {
            if(poom_nfc_emv_tlv_find_(response, response_len, POOM_EMV_TAG_AIP, &tlv) &&
               tlv.value_len >= 2U)
            {
                out_card->aip[0] = tlv.value[0];
                out_card->aip[1] = tlv.value[1];
                out_card->has_aip = true;
            }
            if(poom_nfc_emv_tlv_find_(response, response_len, POOM_EMV_TAG_AFL, &tlv))
            {
                afl_len = (tlv.value_len < sizeof(afl)) ? tlv.value_len : sizeof(afl);
                (void)memcpy(afl, tlv.value, afl_len);
            }
        }
        poom_nfc_emv_decode_records_(
            response, response_len, out_card, &log_sfi, &log_records);
    }
    else
    {
        if(workspace->last_exchange_error == POOM_EMV_EXCHANGE_ERROR_TRANSPORT)
        {
            out_card->read_status = POOM_NFC_EMV_READ_STATUS_GPO_TRANSPORT_ERROR;
        }
        else if(workspace->last_exchange_error == POOM_EMV_EXCHANGE_ERROR_STATUS)
        {
            out_card->read_status = POOM_NFC_EMV_READ_STATUS_GPO_REJECTED;
        }
        else
        {
            out_card->read_status = POOM_NFC_EMV_READ_STATUS_GPO_INVALID;
        }
    }

    if(!gpo_response_received || !out_card->has_aip)
    {
        if(gpo_response_received)
        {
            out_card->read_status = POOM_NFC_EMV_READ_STATUS_GPO_INVALID;
        }
        goto read_complete;
    }
    if(afl_len > 0U && (afl_len < 4U || (afl_len % 4U) != 0U))
    {
        out_card->read_status = POOM_NFC_EMV_READ_STATUS_AFL_INVALID;
        goto read_complete;
    }
    for(size_t i = 0U; i + 3U < afl_len; i += 4U)
    {
        const uint8_t sfi = (uint8_t)((afl[i] >> 3U) & 0x1FU);
        const uint8_t first_record = afl[i + 1U];
        const uint8_t last_record = afl[i + 2U];
        const uint8_t offline_records = afl[i + 3U];
        if(sfi == 0U || first_record == 0U || last_record < first_record ||
           offline_records > (uint8_t)(last_record - first_record + 1U))
        {
            out_card->read_status = POOM_NFC_EMV_READ_STATUS_AFL_INVALID;
            goto read_complete;
        }
    }
    out_card->gpo_succeeded = true;
    out_card->afl_present = (afl_len >= 4U);
    out_card->read_status = POOM_NFC_EMV_READ_STATUS_PARTIAL;

    for(size_t i = 0U; i + 3U < afl_len && !poom_nfc_emv_card_gone_(); i += 4U)
    {
        const uint8_t sfi = (uint8_t)((afl[i] >> 3U) & 0x1FU);
        const uint8_t first_record = afl[i + 1U];
        const uint8_t last_record = afl[i + 2U];
        if(sfi == 0U || first_record == 0U || last_record < first_record)
        {
            continue;
        }
        for(uint16_t record = first_record;
            record <= last_record && !poom_nfc_emv_card_gone_();
            record++)
        {
            if(poom_nfc_emv_read_record_(workspace,
                                         sfi,
                                         (uint8_t)record,
                                         response,
                                         sizeof(response),
                                         &response_len))
            {
                poom_nfc_emv_decode_records_(
                    response, response_len, out_card, &log_sfi, &log_records);
            }
        }
    }

    if(!poom_nfc_emv_card_gone_() && poom_nfc_emv_get_optional_data_(workspace,
                                                                     out_card,
                                                                     POOM_EMV_TAG_PIN_TRY_COUNTER,
                                                                     response,
                                                                     sizeof(response),
                                                                     &response_len) &&
       poom_nfc_emv_tlv_find_(response, response_len, POOM_EMV_TAG_PIN_TRY_COUNTER, &tlv) &&
       tlv.value_len >= 1U)
    {
        out_card->pin_try_counter = tlv.value[0];
        out_card->has_pin_try_counter = true;
    }
    if(!poom_nfc_emv_card_gone_() &&
       poom_nfc_emv_get_optional_data_(workspace,
                                       out_card,
                                       POOM_EMV_TAG_LAST_ONLINE_ATC,
                                       response,
                                       sizeof(response),
                                       &response_len) &&
       poom_nfc_emv_tlv_find_(response, response_len, POOM_EMV_TAG_LAST_ONLINE_ATC, &tlv) &&
       tlv.value_len >= 2U)
    {
        out_card->last_online_atc = (uint16_t)(((uint16_t)tlv.value[0] << 8U) | tlv.value[1]);
        out_card->has_last_online_atc = true;
    }
    if(!poom_nfc_emv_card_gone_() &&
       poom_nfc_emv_get_optional_data_(workspace,
                                       out_card,
                                       POOM_EMV_TAG_ATC,
                                       response,
                                       sizeof(response),
                                       &response_len) &&
       poom_nfc_emv_tlv_find_(response, response_len, POOM_EMV_TAG_ATC, &tlv) && tlv.value_len >= 2U)
    {
        out_card->application_transaction_counter =
            (uint16_t)(((uint16_t)tlv.value[0] << 8U) | tlv.value[1]);
        out_card->has_application_transaction_counter = true;
    }

    if(!poom_nfc_emv_card_gone_() && log_sfi > 0U && log_records > 0U &&
       poom_nfc_emv_get_optional_data_(workspace,
                                       out_card,
                                       POOM_EMV_TAG_LOG_FORMAT,
                                       response,
                                       sizeof(response),
                                       &response_len) &&
       poom_nfc_emv_tlv_find_(response, response_len, POOM_EMV_TAG_LOG_FORMAT, &tlv))
    {
        log_format_len = (tlv.value_len < sizeof(log_format)) ? tlv.value_len : sizeof(log_format);
        (void)memcpy(log_format, tlv.value, log_format_len);
        for(uint16_t record = 1U;
            record <= log_records && out_card->transaction_count < POOM_NFC_EMV_TRANSACTION_MAX &&
            !poom_nfc_emv_card_gone_();
            record++)
        {
            if(!poom_nfc_emv_read_record_(workspace,
                                          log_sfi,
                                          (uint8_t)record,
                                          response,
                                          sizeof(response),
                                          &response_len))
            {
                break;
            }
            poom_nfc_emv_decode_log_(response,
                                     response_len,
                                     log_format,
                                     log_format_len,
                                     &out_card->transactions[out_card->transaction_count]);
            out_card->transaction_count++;
        }
    }

    out_card->read_completed = !poom_nfc_emv_card_gone_();
    out_card->read_status = out_card->read_completed ? POOM_NFC_EMV_READ_STATUS_COMPLETE :
                                                       POOM_NFC_EMV_READ_STATUS_LINK_LOST;

read_complete:
#undef response
#undef pdol_data
#undef gpo_data
#undef apdu
#undef afl
#undef log_format
    return true;
}

bool poom_nfc_emv_read_application(const uint8_t* aid,
                                   size_t aid_len,
                                   poom_nfc_emv_card_t* out_card)
{
    poom_nfc_emv_workspace_t* workspace =
        (poom_nfc_emv_workspace_t*)calloc(1U, sizeof(*workspace));
    if(workspace == NULL)
    {
        return false;
    }

    /* Keep the discovery exchange in the raw transcript as well. A rejected
     * PPSE does not prevent direct-AID cards from being read. */
    size_t ppse_response_len = 0U;
    (void)poom_nfc_emv_select_body_(workspace,
                                    k_poom_emv_ppse_name,
                                    sizeof(k_poom_emv_ppse_name),
                                    workspace->response,
                                    sizeof(workspace->response),
                                    &ppse_response_len);

    const bool result =
        poom_nfc_emv_read_application_with_workspace_(workspace, aid, aid_len, out_card);
    if(result)
    {
        poom_nfc_emv_capture_finalize_(workspace, out_card);
    }
    free(workspace->capture);
    free(workspace);
    return result;
}

typedef struct
{
    uint8_t aid[POOM_NFC_EMV_AID_MAX_LEN];
    size_t aid_len;
    uint8_t priority;
    bool has_app;
    bool has_priority;
} poom_nfc_emv_choice_t;

static bool poom_nfc_emv_choose_app_(const poom_nfc_emv_app_t* app, void* user_ctx)
{
    poom_nfc_emv_choice_t* choice = (poom_nfc_emv_choice_t*)user_ctx;

    if(app == NULL || choice == NULL || app->aid_len == 0U || app->aid_len > sizeof(choice->aid))
    {
        return true;
    }
    const uint8_t priority = app->has_priority ? (uint8_t)(app->priority & 0x0FU) : 0x0FU;
    const uint8_t current_priority = choice->has_priority ? (uint8_t)(choice->priority & 0x0FU) : 0x0FU;
    if(!choice->has_app || priority < current_priority)
    {
        (void)memcpy(choice->aid, app->aid, app->aid_len);
        choice->aid_len = app->aid_len;
        choice->priority = app->priority;
        choice->has_priority = app->has_priority;
        choice->has_app = true;
    }
    return true;
}

bool poom_nfc_emv_read_card(poom_nfc_emv_card_t* out_card)
{
    static const uint8_t fallback_aids[][7] = {
        {0xA0U, 0x00U, 0x00U, 0x00U, 0x03U, 0x10U, 0x10U}, /* Visa. */
        {0xA0U, 0x00U, 0x00U, 0x00U, 0x04U, 0x10U, 0x10U}, /* Mastercard. */
        {0xA0U, 0x00U, 0x00U, 0x00U, 0x04U, 0x30U, 0x60U}, /* Maestro. */
    };
    size_t response_len = 0U;
    size_t app_count = 0U;
    poom_nfc_emv_choice_t choice = {0};
    poom_nfc_emv_workspace_t* workspace = NULL;
    bool result = false;

    if(out_card == NULL)
    {
        return false;
    }
    workspace = (poom_nfc_emv_workspace_t*)calloc(1U, sizeof(*workspace));
    if(workspace == NULL)
    {
        return false;
    }

    if(poom_nfc_emv_select_body_(workspace,
                                 k_poom_emv_ppse_name,
                                 sizeof(k_poom_emv_ppse_name),
                                 workspace->response,
                                 sizeof(workspace->response),
                                 &response_len))
    {
        bool stop_requested = false;
        if(!poom_nfc_emv_walk_ppse_(workspace->response,
                                    response_len,
                                    poom_nfc_emv_choose_app_,
                                    &choice,
                                    &app_count,
                                    &stop_requested))
        {
            goto cleanup;
        }
    }

    if(choice.has_app &&
       poom_nfc_emv_read_application_with_workspace_(
           workspace, choice.aid, choice.aid_len, out_card))
    {
        result = true;
        goto cleanup;
    }

    for(size_t i = 0U; i < (sizeof(fallback_aids) / sizeof(fallback_aids[0])); i++)
    {
        if(poom_nfc_emv_read_application_with_workspace_(
               workspace, fallback_aids[i], sizeof(fallback_aids[i]), out_card))
        {
            result = true;
            break;
        }
    }

cleanup:
    if(result)
    {
        poom_nfc_emv_capture_finalize_(workspace, out_card);
    }
    free(workspace->capture);
    free(workspace);
    return result;
}

const char* poom_nfc_emv_read_status_str(poom_nfc_emv_read_status_t status)
{
    switch(status)
    {
        case POOM_NFC_EMV_READ_STATUS_NOT_STARTED: return "not-started";
        case POOM_NFC_EMV_READ_STATUS_SELECT_FAILED: return "select-failed";
        case POOM_NFC_EMV_READ_STATUS_GPO_TRANSPORT_ERROR: return "gpo-timeout";
        case POOM_NFC_EMV_READ_STATUS_GPO_REJECTED: return "gpo-rejected";
        case POOM_NFC_EMV_READ_STATUS_GPO_INVALID: return "gpo-invalid";
        case POOM_NFC_EMV_READ_STATUS_AFL_INVALID: return "afl-invalid";
        case POOM_NFC_EMV_READ_STATUS_DATA_NOT_SUPPORTED: return "data-not-supported";
        case POOM_NFC_EMV_READ_STATUS_LINK_LOST: return "link-lost";
        case POOM_NFC_EMV_READ_STATUS_PARTIAL: return "partial";
        case POOM_NFC_EMV_READ_STATUS_COMPLETE: return "complete";
        default: return "unknown";
    }
}

const char* poom_nfc_emv_cryptogram_type_str(uint8_t cryptogram_information_data)
{
    switch(cryptogram_information_data & 0xC0U)
    {
        case 0x00U: return "AAC";
        case 0x40U: return "TC";
        case 0x80U: return "ARQC";
        default: return "RFU";
    }
}

static void poom_nfc_emv_text_append_(char* out,
                                      size_t out_len,
                                      const char* text,
                                      bool separator)
{
    size_t used;

    if(out == NULL || out_len == 0U || text == NULL)
    {
        return;
    }
    used = strlen(out);
    const size_t separator_len = (separator && used > 0U) ? 1U : 0U;
    const size_t text_len = strlen(text);
    if(used + separator_len + text_len >= out_len)
    {
        return;
    }
    if(separator_len > 0U)
    {
        out[used++] = ',';
        out[used] = '\0';
    }
    (void)memcpy(&out[used], text, text_len + 1U);
}

void poom_nfc_emv_format_aip(const poom_nfc_emv_card_t* card, char* out, size_t out_len)
{
    if(out == NULL || out_len == 0U)
    {
        return;
    }
    out[0] = '\0';
    if(card == NULL || !card->has_aip)
    {
        return;
    }

    if((card->aip[0] & 0x80U) != 0U) poom_nfc_emv_text_append_(out, out_len, "SDA", true);
    if((card->aip[0] & 0x40U) != 0U) poom_nfc_emv_text_append_(out, out_len, "DDA", true);
    if((card->aip[0] & 0x20U) != 0U) poom_nfc_emv_text_append_(out, out_len, "CVM", true);
    if((card->aip[0] & 0x10U) != 0U) poom_nfc_emv_text_append_(out, out_len, "TRM", true);
    if((card->aip[0] & 0x08U) != 0U) poom_nfc_emv_text_append_(out, out_len, "Issuer auth", true);
    if((card->aip[0] & 0x02U) != 0U) poom_nfc_emv_text_append_(out, out_len, "CDA", true);
    if(out[0] == '\0')
    {
        (void)snprintf(out, out_len, "No common flags");
    }
}

void poom_nfc_emv_format_auc(const poom_nfc_emv_card_t* card, char* out, size_t out_len)
{
    if(out == NULL || out_len == 0U)
    {
        return;
    }
    out[0] = '\0';
    if(card == NULL || card->details == NULL ||
       !card->details->has_application_usage_control)
    {
        return;
    }

    const uint8_t first = card->details->application_usage_control[0];
    const uint8_t second = card->details->application_usage_control[1];
    if((first & 0x80U) != 0U) poom_nfc_emv_text_append_(out, out_len, "Dom cash", true);
    if((first & 0x40U) != 0U) poom_nfc_emv_text_append_(out, out_len, "Intl cash", true);
    if((first & 0x20U) != 0U) poom_nfc_emv_text_append_(out, out_len, "Dom goods", true);
    if((first & 0x10U) != 0U) poom_nfc_emv_text_append_(out, out_len, "Intl goods", true);
    if((first & 0x08U) != 0U) poom_nfc_emv_text_append_(out, out_len, "Dom services", true);
    if((first & 0x04U) != 0U) poom_nfc_emv_text_append_(out, out_len, "Intl services", true);
    if((first & 0x02U) != 0U) poom_nfc_emv_text_append_(out, out_len, "ATM", true);
    if((first & 0x01U) != 0U) poom_nfc_emv_text_append_(out, out_len, "Non-ATM", true);
    if((second & 0x80U) != 0U) poom_nfc_emv_text_append_(out, out_len, "Dom cashback", true);
    if((second & 0x40U) != 0U) poom_nfc_emv_text_append_(out, out_len, "Intl cashback", true);
    if(out[0] == '\0')
    {
        (void)snprintf(out, out_len, "No usage enabled");
    }
}

static const char* poom_nfc_emv_cvm_method_(uint8_t method)
{
    switch(method & 0x3FU)
    {
        case 0x00U: return "Fail CVM";
        case 0x01U: return "Plain PIN";
        case 0x02U: return "Online PIN";
        case 0x03U: return "PIN+signature";
        case 0x04U: return "Enciphered PIN";
        case 0x05U: return "Enc PIN+signature";
        case 0x1EU: return "Signature";
        case 0x1FU: return "No CVM";
        default: return NULL;
    }
}

void poom_nfc_emv_format_cvm(const poom_nfc_emv_card_t* card, char* out, size_t out_len)
{
    uint64_t seen = 0U;

    if(out == NULL || out_len == 0U)
    {
        return;
    }
    out[0] = '\0';
    if(card == NULL || card->details == NULL || card->details->cvm_list_len < 10U)
    {
        return;
    }

    for(size_t i = 8U; i + 1U < card->details->cvm_list_len; i += 2U)
    {
        const uint8_t code = (uint8_t)(card->details->cvm_list[i] & 0x3FU);
        const uint64_t bit = UINT64_C(1) << code;
        const char* method = poom_nfc_emv_cvm_method_(code);
        if((seen & bit) == 0U && method != NULL)
        {
            poom_nfc_emv_text_append_(out, out_len, method, true);
            seen |= bit;
        }
    }
    if(out[0] == '\0')
    {
        (void)snprintf(out, out_len, "Proprietary/raw");
    }
}

static const char* poom_nfc_emv_dol_tag_name_(uint32_t tag)
{
    switch(tag)
    {
        case 0x9F02U: return "Amt";
        case 0x9F03U: return "Other";
        case 0x9F1AU: return "Country";
        case 0x95U: return "TVR";
        case 0x5F2AU: return "Currency";
        case 0x9AU: return "Date";
        case 0x9CU: return "Type";
        case 0x9F37U: return "UN";
        case 0x9F35U: return "Term type";
        case 0x9F34U: return "CVM result";
        case 0x9F45U: return "Auth code";
        case 0x9F4CU: return "ICC dyn no";
        case 0x9F21U: return "Time";
        case 0x9F7CU: return "Customer";
        default: return NULL;
    }
}

void poom_nfc_emv_format_dol(const uint8_t* dol,
                             size_t dol_len,
                             char* out,
                             size_t out_len)
{
    size_t off = 0U;

    if(out == NULL || out_len == 0U)
    {
        return;
    }
    out[0] = '\0';
    if(dol == NULL || dol_len == 0U)
    {
        return;
    }

    while(off < dol_len)
    {
        uint32_t tag;
        uint8_t value_len;
        char unknown[12];
        const char* name;
        if(!poom_nfc_emv_dol_next_(dol, dol_len, &off, &tag, &value_len))
        {
            poom_nfc_emv_text_append_(out, out_len, "Malformed", true);
            break;
        }
        name = poom_nfc_emv_dol_tag_name_(tag);
        if(name == NULL)
        {
            (void)snprintf(unknown, sizeof(unknown), "%lX", (unsigned long)tag);
            name = unknown;
        }
        poom_nfc_emv_text_append_(out, out_len, name, true);
        (void)value_len;
    }
}

void poom_nfc_emv_card_release(poom_nfc_emv_card_t* card)
{
    if(card != NULL)
    {
        free(card->details);
        card->details = NULL;
        free(card->capture);
        card->capture = NULL;
    }
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
