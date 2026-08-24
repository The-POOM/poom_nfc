// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 THE POOM

/*
 * poom_nfc_iso14443_4.h
 *
 * Minimal public API for the refactored POOM NFC reader module.
 *
 * Notes:
 * - This module is built on top of RFAL (rfal_rf / rfal_nfca/nfcb/nfcv).
 * - It provides:
 *     * connect() that tries 14443-A, then 14443-B, then 15693
 *     * send() that accepts ASCII-hex (like "00A40400...") and sends either:
 *         - ISO-DEP APDU exchange for 14443-A/B (ISO/IEC 14443-4)
 *         - raw transceive for 15693
 *
 * Standards mapping:
 * - ISO/IEC 14443-3: Type A/B activation
 * - ISO/IEC 14443-4: ISO-DEP (APDU over I/R/S blocks)
 * - ISO/IEC 15693: inventory / vicinity cards
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "poom_nfc_profile.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ----------------------------------------------------------------------------
 * Configuration
 * -------------------------------------------------------------------------- */

/**
 * Enable/disable verbose logging (prints TX/RX frames).
 */
void poom_reader_set_verbose(bool enable);
bool poom_reader_is_verbose(void);

/**
 * Set ISO-DEP chunk length (1..250).
 *
 * IMPORTANT:
 * This is NOT the negotiated FSD/FSC from ISO/IEC 14443-4.
 * It's only the maximum INF payload size per I-block that this simple
 * implementation will use when fragmenting a C-APDU into chained I-blocks.
 *
 * Returns:
 *  - true if accepted
 *  - false if out of range
 */
bool poom_reader_set_iso_dep_chunk_len(uint8_t value_1_to_250);

/* ----------------------------------------------------------------------------
 * Operations
 * -------------------------------------------------------------------------- */

/**
 * Try to detect and activate a card:
 *  - ISO/IEC 14443-A (REQA -> anticollision/select -> RATS/PPS)
 *  - ISO/IEC 14443-B (REQB -> ATQB -> ATTRIB)
 *  - ISO/IEC 15693 (Inventory)
 *
 * Returns true on success (card activated).
 */
bool poom_reader_connect_card(void);

/**
 * Send data (ASCII-hex string) to the currently connected card.
 *
 * For 14443-A / 14443-B (ISO-DEP):
 *  - Treats data as a C-APDU byte stream and exchanges it using 14443-4 blocks.
 *
 * For 15693:
 *  - Sends raw bytes as a single transceive (CRC handled by RFAL flags).
 *
 * Example:
 *   poom_reader_send_raw_hex("00A4040007A0000002471001");
 *
 * Output:
 *  - Prints TX/RX frames if verbose is enabled.
 *  - Always prints the final R-APDU for ISO-DEP as hex.
 */
bool poom_reader_send_raw_hex(const char *ascii_hex);

/**
 * Send one binary C-APDU to the currently connected ISO-DEP card.
 *
 * This is a reusable transport helper for higher layers such as ISO7816, EMV,
 * or other APDU-based protocols. It does not interpret the APDU contents.
 *
 * Returns true only when the exchange succeeds at link level and an R-APDU is
 * available. The returned R-APDU still contains the trailing SW1/SW2 bytes.
 */
bool poom_reader_isodep_transceive_apdu(const uint8_t* apdu,
                                        size_t apdu_len,
                                        uint8_t* out_rapdu,
                                        size_t out_max,
                                        size_t* out_len);

/**
 * Copy the last ISO-DEP R-APDU returned by poom_reader_send_raw_hex().
 *
 * Returns true only when a response exists and it fits in out_rapdu.
 * On failure due small buffer, out_len is set to required size.
 */
bool poom_reader_get_last_rapdu(uint8_t* out_rapdu, size_t out_max, size_t* out_len);

/**
 * @brief Get last activation profile captured by poom_reader_connect_card().
 *
 * This is a best-effort snapshot for CLI workflows (emulation setup).
 * It is updated only when poom_reader_connect_card() is called.
 */
bool poom_reader_get_last_profile(poom_nfc_profile_t* out_profile);

#ifdef __cplusplus
}
#endif
