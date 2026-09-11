// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 THE POOM

/* EMV discovery and best-effort application reading for POOM NFC. */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    const uint8_t* aid;     /* Tag 4F / ADF Name bytes. */
    size_t aid_len;         /* Number of AID bytes. */
    const uint8_t* label;   /* Tag 50 / Application Label bytes, when present. */
    size_t label_len;       /* Number of label bytes. */
    bool label_printable;   /* True when `label` can be shown as text. */
    bool has_priority;      /* True when tag 87 was present. */
    uint8_t priority;       /* Tag 87 / Application Priority Indicator. */
} poom_nfc_emv_app_t;

/**
 * @brief Callback used while iterating EMV applications discovered from PPSE.
 *
 * The `app` data aliases the original R-APDU buffer; it is valid only for the
 * duration of the callback.
 *
 * @param[in] app Decoded view of one advertised EMV application.
 * @param[in] user_ctx Opaque caller context.
 * @return true to continue parsing additional applications, false to stop.
 */
typedef bool (*poom_nfc_emv_app_cb_t)(const poom_nfc_emv_app_t* app, void* user_ctx);

#define POOM_NFC_EMV_AID_MAX_LEN (16U)
#define POOM_NFC_EMV_PAN_MAX_DIGITS (19U)
#define POOM_NFC_EMV_LABEL_MAX_LEN (32U)
#define POOM_NFC_EMV_NAME_MAX_LEN (32U)
#define POOM_NFC_EMV_CARDHOLDER_MAX_LEN (32U)
#define POOM_NFC_EMV_TRANSACTION_MAX (10U)
#define POOM_NFC_EMV_IAD_MAX_LEN (32U)
#define POOM_NFC_EMV_AC_MAX_LEN (8U)
#define POOM_NFC_EMV_PROGRAM_ID_MAX_LEN (16U)
#define POOM_NFC_EMV_CTQ_MAX_LEN (4U)
#define POOM_NFC_EMV_FORM_FACTOR_MAX_LEN (16U)
#define POOM_NFC_EMV_PDOL_DEFINITION_MAX_LEN (64U)
#define POOM_NFC_EMV_CAPTURE_EXCHANGE_MAX (24U)
#define POOM_NFC_EMV_LANGUAGE_MAX_LEN (8U)
#define POOM_NFC_EMV_DOL_MAX_LEN (64U)
#define POOM_NFC_EMV_CVM_LIST_MAX_LEN (64U)
#define POOM_NFC_EMV_IAC_LEN (5U)
#define POOM_NFC_EMV_SDA_TAG_LIST_MAX_LEN (32U)
#define POOM_NFC_EMV_EXPONENT_MAX_LEN (4U)
#define POOM_NFC_EMV_SCHEME_DATA_MAX_LEN (32U)

/* EMV numeric codes encoded as packed BCD. Override at build time if needed. */
#ifndef POOM_NFC_EMV_TERMINAL_COUNTRY_CODE_BCD
#define POOM_NFC_EMV_TERMINAL_COUNTRY_CODE_BCD (0x0840U) /* United States, ISO 3166-1 840. */
#endif
#ifndef POOM_NFC_EMV_TRANSACTION_CURRENCY_CODE_BCD
#define POOM_NFC_EMV_TRANSACTION_CURRENCY_CODE_BCD (0x0840U) /* USD, ISO 4217 840. */
#endif

/** One entry decoded from the optional EMV transaction log. */
typedef struct
{
    uint64_t amount;
    uint16_t atc;
    uint16_t country_code;
    uint16_t currency_code;
    uint8_t date[3];
    uint8_t time[3];
    uint8_t has_atc : 1;
    uint8_t has_amount : 1;
    uint8_t has_country_code : 1;
    uint8_t has_currency_code : 1;
    uint8_t has_date : 1;
    uint8_t has_time : 1;
} poom_nfc_emv_transaction_t;

/** Final outcome of the best-effort EMV application read. */
typedef enum
{
    POOM_NFC_EMV_READ_STATUS_NOT_STARTED = 0,
    POOM_NFC_EMV_READ_STATUS_SELECT_FAILED,
    POOM_NFC_EMV_READ_STATUS_GPO_TRANSPORT_ERROR,
    POOM_NFC_EMV_READ_STATUS_GPO_REJECTED,
    POOM_NFC_EMV_READ_STATUS_GPO_INVALID,
    POOM_NFC_EMV_READ_STATUS_AFL_INVALID,
    POOM_NFC_EMV_READ_STATUS_DATA_NOT_SUPPORTED,
    POOM_NFC_EMV_READ_STATUS_LINK_LOST,
    POOM_NFC_EMV_READ_STATUS_PARTIAL,
    POOM_NFC_EMV_READ_STATUS_COMPLETE,
} poom_nfc_emv_read_status_t;

/** Location of one captured C-APDU/R-APDU pair in an EMV capture. */
typedef struct
{
    uint16_t command_offset;
    uint16_t command_len;
    uint16_t response_offset;
    uint16_t response_len;
    bool transport_ok;
} poom_nfc_emv_exchange_t;

/**
 * Exact-size raw transcript. Offsets in `exchanges` refer to `data`.
 * Unknown/proprietary TLVs are therefore preserved even when not decoded.
 */
typedef struct
{
    size_t data_len;
    size_t exchange_count;
    bool truncated;
    poom_nfc_emv_exchange_t exchanges[POOM_NFC_EMV_CAPTURE_EXCHANGE_MAX];
    uint8_t data[];
} poom_nfc_emv_capture_t;

/** Payment-system family inferred from the five-byte RID at the start of the AID. */
typedef enum
{
    POOM_NFC_EMV_SCHEME_UNKNOWN = 0,
    POOM_NFC_EMV_SCHEME_VISA,
    POOM_NFC_EMV_SCHEME_MASTERCARD,
} poom_nfc_emv_scheme_t;

/** Optional detailed EMV objects, allocated only when at least one is present. */
typedef struct
{
    uint8_t language_preferences[POOM_NFC_EMV_LANGUAGE_MAX_LEN];
    size_t language_preferences_len;
    uint16_t application_version_number;
    bool has_application_version_number;
    uint8_t application_usage_control[2];
    bool has_application_usage_control;
    uint8_t cvm_list[POOM_NFC_EMV_CVM_LIST_MAX_LEN];
    size_t cvm_list_len;
    uint8_t cdol1[POOM_NFC_EMV_DOL_MAX_LEN];
    size_t cdol1_len;
    uint8_t cdol2[POOM_NFC_EMV_DOL_MAX_LEN];
    size_t cdol2_len;
    uint8_t issuer_action_code_default[POOM_NFC_EMV_IAC_LEN];
    uint8_t issuer_action_code_denial[POOM_NFC_EMV_IAC_LEN];
    uint8_t issuer_action_code_online[POOM_NFC_EMV_IAC_LEN];
    bool has_issuer_action_code_default;
    bool has_issuer_action_code_denial;
    bool has_issuer_action_code_online;
    uint8_t sda_tag_list[POOM_NFC_EMV_SDA_TAG_LIST_MAX_LEN];
    size_t sda_tag_list_len;
    uint8_t ca_public_key_index;
    bool has_ca_public_key_index;
    size_t issuer_public_key_certificate_len;
    size_t issuer_public_key_remainder_len;
    uint8_t issuer_public_key_exponent[POOM_NFC_EMV_EXPONENT_MAX_LEN];
    size_t issuer_public_key_exponent_len;
    size_t icc_public_key_certificate_len;
    size_t icc_public_key_remainder_len;
    uint8_t icc_public_key_exponent[POOM_NFC_EMV_EXPONENT_MAX_LEN];
    size_t icc_public_key_exponent_len;
    uint8_t ddol[POOM_NFC_EMV_DOL_MAX_LEN];
    size_t ddol_len;
    uint8_t customer_exclusive_data[POOM_NFC_EMV_SCHEME_DATA_MAX_LEN];
    size_t customer_exclusive_data_len;
    uint8_t mastercard_application_capabilities[POOM_NFC_EMV_SCHEME_DATA_MAX_LEN];
    size_t mastercard_application_capabilities_len;
    uint8_t mastercard_9f6c[POOM_NFC_EMV_SCHEME_DATA_MAX_LEN];
    size_t mastercard_9f6c_len;
    uint8_t mastercard_third_party_data[POOM_NFC_EMV_SCHEME_DATA_MAX_LEN];
    size_t mastercard_third_party_data_len;
} poom_nfc_emv_details_t;

/** Complete best-effort read of one EMV application. */
typedef struct
{
    uint8_t aid[POOM_NFC_EMV_AID_MAX_LEN];
    size_t aid_len;
    char application_label[POOM_NFC_EMV_LABEL_MAX_LEN + 1U];
    char application_name[POOM_NFC_EMV_NAME_MAX_LEN + 1U];
    char cardholder_name[POOM_NFC_EMV_CARDHOLDER_MAX_LEN + 1U];
    char pan[POOM_NFC_EMV_PAN_MAX_DIGITS + 1U];
    size_t pan_len;
    poom_nfc_emv_scheme_t scheme;
    uint8_t aip[2];
    uint8_t expiration_date[3];
    uint8_t effective_date[3];
    uint16_t country_code;
    uint16_t currency_code;
    uint16_t application_transaction_counter;
    uint16_t last_online_atc;
    uint16_t service_code;
    uint64_t offline_spending_amount;
    uint8_t pin_try_counter;
    uint8_t pan_sequence_number;
    uint8_t issuer_code_table_index;
    uint8_t cryptogram_information_data;
    uint8_t priority;
    uint8_t issuer_application_data[POOM_NFC_EMV_IAD_MAX_LEN];
    size_t issuer_application_data_len;
    uint8_t application_cryptogram[POOM_NFC_EMV_AC_MAX_LEN];
    size_t application_cryptogram_len;
    uint8_t application_program_identifier[POOM_NFC_EMV_PROGRAM_ID_MAX_LEN];
    size_t application_program_identifier_len;
    uint8_t card_transaction_qualifiers[POOM_NFC_EMV_CTQ_MAX_LEN];
    size_t card_transaction_qualifiers_len;
    uint8_t form_factor_indicator[POOM_NFC_EMV_FORM_FACTOR_MAX_LEN];
    size_t form_factor_indicator_len;
    uint8_t pdol_definition[POOM_NFC_EMV_PDOL_DEFINITION_MAX_LEN];
    size_t pdol_definition_len;
    bool has_aip;
    bool has_expiration_date;
    bool has_effective_date;
    bool has_country_code;
    bool has_currency_code;
    bool has_application_transaction_counter;
    bool has_last_online_atc;
    bool has_pin_try_counter;
    bool has_pan_sequence_number;
    bool has_service_code;
    bool has_issuer_code_table_index;
    bool has_cryptogram_information_data;
    bool has_offline_spending_amount;
    bool optional_data_unsupported;
    bool has_priority;
    bool gpo_succeeded;
    bool afl_present;
    bool read_completed;
    poom_nfc_emv_read_status_t read_status;
    poom_nfc_emv_transaction_t transactions[POOM_NFC_EMV_TRANSACTION_MAX];
    size_t transaction_count;
    poom_nfc_emv_details_t* details;
    poom_nfc_emv_capture_t* capture;
} poom_nfc_emv_card_t;

/** Infer the payment scheme from an AID RID without claiming a negotiated kernel. */
poom_nfc_emv_scheme_t poom_nfc_emv_scheme_from_aid(const uint8_t* aid, size_t aid_len);

/** Stable display name for an inferred payment scheme. */
const char* poom_nfc_emv_scheme_str(poom_nfc_emv_scheme_t scheme);

/** Expected contactless kernel family; this is a hint, not negotiated-kernel proof. */
const char* poom_nfc_emv_kernel_hint_str(poom_nfc_emv_scheme_t scheme);

/** Format common AIP capabilities into compact human-readable text. */
void poom_nfc_emv_format_aip(const poom_nfc_emv_card_t* card, char* out, size_t out_len);

/** Format Application Usage Control into compact human-readable text. */
void poom_nfc_emv_format_auc(const poom_nfc_emv_card_t* card, char* out, size_t out_len);

/** Format unique CVM methods advertised in the CVM List. */
void poom_nfc_emv_format_cvm(const poom_nfc_emv_card_t* card, char* out, size_t out_len);

/** Format a DOL as a compact comma-separated list of known data-object names. */
void poom_nfc_emv_format_dol(const uint8_t* dol,
                             size_t dol_len,
                             char* out,
                             size_t out_len);

/** Return a stable printable name for an EMV read status. */
const char* poom_nfc_emv_read_status_str(poom_nfc_emv_read_status_t status);

/** Return the EMV cryptogram type represented by tag 9F27 (AAC/TC/ARQC/RFU). */
const char* poom_nfc_emv_cryptogram_type_str(uint8_t cryptogram_information_data);

/** Release dynamic raw capture data owned by a card result. */
void poom_nfc_emv_card_release(poom_nfc_emv_card_t* card);

/**
 * @brief Select the EMV PPSE (`2PAY.SYS.DDF01`) over the active ISO-DEP link.
 *
 * @param[out] out_rapdu Output buffer that receives the raw R-APDU.
 * @param[in] out_max Capacity of `out_rapdu`.
 * @param[out] out_rapdu_len Number of bytes written to `out_rapdu`.
 * @return true on link-level exchange success, false otherwise.
 */
bool poom_nfc_emv_select_ppse(uint8_t* out_rapdu, size_t out_max, size_t* out_rapdu_len);

/**
 * @brief Select one EMV application by AID over the active ISO-DEP link.
 *
 * @param[in] aid AID bytes to select.
 * @param[in] aid_len Number of AID bytes.
 * @param[out] out_rapdu Output buffer that receives the raw R-APDU.
 * @param[in] out_max Capacity of `out_rapdu`.
 * @param[out] out_rapdu_len Number of bytes written to `out_rapdu`.
 * @return true on link-level exchange success, false otherwise.
 */
bool poom_nfc_emv_select_aid(const uint8_t* aid,
                             size_t aid_len,
                             uint8_t* out_rapdu,
                             size_t out_max,
                             size_t* out_rapdu_len);

/**
 * @brief Parse EMV applications advertised inside a PPSE R-APDU.
 *
 * This walks BER-TLV containers and invokes `cb` once for each directory entry
 * that exposes an AID.
 *
 * @param[in] rapdu Raw PPSE R-APDU including SW1/SW2.
 * @param[in] rapdu_len Number of bytes available in `rapdu`.
 * @param[in] cb Optional callback invoked per application.
 * @param[in] user_ctx Opaque caller context passed to `cb`.
 * @param[out] out_count Optional number of applications found.
 * @return true on successful parse, false when the response is malformed.
 */
bool poom_nfc_emv_parse_ppse_apps(const uint8_t* rapdu,
                                  size_t rapdu_len,
                                  poom_nfc_emv_app_cb_t cb,
                                  void* user_ctx,
                                  size_t* out_count);

/**
 * @brief Check whether a raw EMV label can be shown as printable text.
 *
 * @param[in] s Label bytes to inspect.
 * @param[in] len Number of bytes in `s`.
 * @return true when every byte is printable ASCII.
 */
bool poom_nfc_emv_label_is_printable(const uint8_t* s, size_t len);

/**
 * @brief Return the static PPSE name used for EMV discovery.
 *
 * The returned pointer references read-only storage.
 *
 * @param[out] out_len Optional output length of the PPSE name.
 * @return const uint8_t* Pointer to `2PAY.SYS.DDF01` bytes.
 */
const uint8_t* poom_nfc_emv_ppse_name(size_t* out_len);

/**
 * @brief Select and fully read one EMV application over the active ISO-DEP link.
 *
 * This performs SELECT AID, prepares the card PDOL, sends GPO, follows the AFL,
 * decodes readable records, queries optional counters, and reads the optional
 * transaction log. Unsupported or protected optional data is left unset.
 *
 * @param[in] aid Application identifier to select.
 * @param[in] aid_len Number of AID bytes.
 * @param[out] out_card Decoded result. Call `poom_nfc_emv_card_release()` after use.
 * @return true when the application was selected. Check `out_card->gpo_succeeded`
 * to distinguish a complete GPO/AFL read from partial FCI-only data.
 */
bool poom_nfc_emv_read_application(const uint8_t* aid,
                                   size_t aid_len,
                                   poom_nfc_emv_card_t* out_card);

/**
 * @brief Discover and fully read a payment application.
 *
 * @param[out] out_card Decoded result. Call `poom_nfc_emv_card_release()` after use.
 * @return true when a PPSE-advertised or common fallback application was selected.
 */
bool poom_nfc_emv_read_card(poom_nfc_emv_card_t* out_card);

#ifdef __cplusplus
}
#endif
