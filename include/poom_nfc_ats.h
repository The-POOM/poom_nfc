// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 THE POOM

/*
 * poom_nfc_ats.h
 *
 * Shared ATS (Answer To Select) parsing helpers for POOM NFC.
 *
 * Purpose:
 * - provide one small decoded view of ISO-DEP ATS bytes
 * - avoid duplicating ATS parsing logic across CLI, reader traces, and emulator
 *
 * Standards mapping:
 * - ISO/IEC 14443-4: ATS returned after RATS during ISO-DEP activation
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ==========================
 * Limits
 * ========================== */

/* Maximum historical bytes copied from ATS into the parsed view. */
#define POOM_NFC_ATS_HB_MAX 15U

/* ==========================
 * Parsed ATS view
 * ========================== */

/**
 * @brief Decoded ISO-DEP ATS fields.
 *
 * This is a compact helper view for CLI, debug traces, and emulation setup.
 * It keeps both the raw optional bytes (`TA`/`TB`/`TC`) and the commonly used
 * derived values (`FSCI`, `FSC`, `FWI`, `SFGI`, `DID/NAD` support).
 */
typedef struct
{
    uint8_t tl;                           /* ATS length byte (includes TL itself). */
    uint8_t t0;                           /* Format byte with FSCI and TA/TB/TC presence. */
    uint8_t ta;                           /* Optional TA(1), when present. */
    uint8_t tb;                           /* Optional TB(1), when present. */
    uint8_t tc;                           /* Optional TC(1), when present. */

    uint8_t fsci;                         /* Frame Size for Proximity Card Integer. */
    uint16_t fsc;                         /* Decoded frame size derived from FSCI. */
    uint8_t fwi;                          /* Frame Waiting Integer. */
    uint8_t sfgi;                         /* Start-up Frame Guard Integer. */

    uint8_t hb[POOM_NFC_ATS_HB_MAX];      /* Historical bytes copied from ATS. */
    uint8_t hb_len;                       /* Number of valid historical bytes in hb[]. */
    uint8_t ats_len;                      /* Effective ATS length consumed by the parser. */

    bool ta_present;                      /* True if TA(1) exists in the ATS. */
    bool tb_present;                      /* True if TB(1) exists in the ATS. */
    bool tc_present;                      /* True if TC(1) exists in the ATS. */
    bool did_supported;                   /* True if TC indicates DID support. */
    bool nad_supported;                   /* True if TC indicates NAD support. */
} poom_nfc_ats_info_t;

/* ==========================
 * Public API
 * ========================== */

/**
 * @brief Parse a raw ATS into a normalized helper structure.
 *
 * The parser trims the effective length to `TL` when needed, decodes the
 * optional interface bytes, and copies the historical bytes into `out_info`.
 *
 * @param[in] ats Raw ATS bytes (`TL`, `T0`, optional `TA/TB/TC`, historical bytes).
 * @param[in] ats_len Number of raw ATS bytes available in `ats`.
 * @param[out] out_info Parsed ATS view.
 * @return true when the ATS is structurally valid and was parsed successfully.
 */
bool poom_nfc_ats_parse(const uint8_t* ats, uint8_t ats_len, poom_nfc_ats_info_t* out_info);

#ifdef __cplusplus
}
#endif
