// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 THE POOM

/* Small EMV / PPSE discovery helpers for POOM NFC. */
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

#ifdef __cplusplus
}
#endif
