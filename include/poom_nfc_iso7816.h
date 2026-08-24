// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 THE POOM

/* Minimal ISO/IEC 7816-4 APDU helpers for POOM NFC. */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    const uint8_t* data; /* Pointer to R-APDU payload (without SW1/SW2). */
    size_t data_len;     /* Number of payload bytes in `data`. */
    uint8_t sw1;         /* ISO/IEC 7816-4 status byte 1. */
    uint8_t sw2;         /* ISO/IEC 7816-4 status byte 2. */
} poom_iso7816_rapdu_view_t;

/**
 * @brief Parse a raw R-APDU into payload and status word view.
 *
 * The returned payload pointer aliases the input buffer; no copy is performed.
 *
 * @param[in] rapdu Raw R-APDU bytes, including trailing SW1/SW2.
 * @param[in] rapdu_len Number of bytes available in `rapdu`.
 * @param[out] out_view Parsed view over the R-APDU contents.
 * @return true on success, false when the input is invalid or too short.
 */
bool poom_iso7816_parse_rapdu(const uint8_t* rapdu,
                              size_t rapdu_len,
                              poom_iso7816_rapdu_view_t* out_view);

/**
 * @brief Build a short SELECT FILE by DF Name C-APDU.
 *
 * This produces the ISO/IEC 7816-4 form:
 * `00 A4 04 00 Lc <df_name> 00`
 *
 * Only short-length APDUs are supported in this helper.
 *
 * @param[in] df_name DF Name / AID bytes to place in the APDU body.
 * @param[in] df_name_len Number of DF Name bytes.
 * @param[out] out_apdu Output buffer that receives the built APDU.
 * @param[in] out_apdu_max Capacity of `out_apdu`.
 * @return size_t Number of bytes written, or 0 on failure.
 */
size_t poom_iso7816_build_select_df_name(const uint8_t* df_name,
                                         size_t df_name_len,
                                         uint8_t* out_apdu,
                                         size_t out_apdu_max);

/**
 * @brief Return a human-readable description for an ISO/IEC 7816-4 status word.
 *
 * @param[in] sw1 ISO/IEC 7816-4 status byte 1.
 * @param[in] sw2 ISO/IEC 7816-4 status byte 2.
 * @return const char* Static descriptive string.
 */
const char* poom_iso7816_status_desc(uint8_t sw1, uint8_t sw2);

/**
 * @brief Check whether a status word is the standard success code `90 00`.
 *
 * @param[in] sw1 ISO/IEC 7816-4 status byte 1.
 * @param[in] sw2 ISO/IEC 7816-4 status byte 2.
 * @return true when the status word is `90 00`.
 */
bool poom_iso7816_status_is_ok(uint8_t sw1, uint8_t sw2);

#ifdef __cplusplus
}
#endif
