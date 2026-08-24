// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 THE POOM

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#include "rfal_rf.h"
#include "st25r3916.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    rfalMode mode;
    rfalBitRate tx_br;
    rfalBitRate rx_br;
    ReturnCode bitrate_rc;
} poom_nfc_debug_mode_info_t;

typedef struct
{
    uint8_t tx;
    uint8_t rx;
} poom_nfc_debug_obsv_info_t;

typedef struct
{
    uint8_t atqa[2];
} poom_nfc_debug_atqa_t;

/**
 * @brief Set ISO-DEP reader verbosity (prints TX/RX frames).
 *
 * This applies to the reader bridge in `poom_nfc_iso14443_4`.
 */
void poom_nfc_debug_reader_set_verbose(bool enable);

/**
 * @brief Set ISO-DEP reader chunk length (1..250).
 */
bool poom_nfc_debug_reader_set_iso_dep_chunk_len(uint8_t value_1_to_250);

bool poom_nfc_debug_rf_on(void);
bool poom_nfc_debug_rf_off(void);

bool poom_nfc_debug_mode_get(poom_nfc_debug_mode_info_t* out_info);
ReturnCode poom_nfc_debug_mode_set(rfalMode mode, rfalBitRate tx_br, rfalBitRate rx_br);

bool poom_nfc_debug_obsv_get(poom_nfc_debug_obsv_info_t* out_info);
bool poom_nfc_debug_obsv_set_enabled(bool enable, uint8_t tx, uint8_t rx);

const char* poom_nfc_debug_return_code_to_str(ReturnCode rc);

ReturnCode poom_nfc_debug_req_a(poom_nfc_debug_atqa_t* out_atqa);
ReturnCode poom_nfc_debug_wup_a(poom_nfc_debug_atqa_t* out_atqa);

ReturnCode poom_nfc_debug_raw_txrx(const uint8_t* tx,
                                  size_t tx_len,
                                  bool crc_auto,
                                  uint8_t* rx,
                                  size_t rx_max,
                                  size_t* out_rx_len);

ReturnCode poom_nfc_debug_regdump(t_st25r3916Regs* out_dump);

/**
 * @brief Return a static register address map for ST25R3916 Space B.
 *
 */
const uint8_t* poom_nfc_debug_st25_space_b_addr_map(size_t* out_len);

/**
 * @brief Repeated scan helper (finite loop).
 *
 * @param period_ms Delay between scans.
 * @param timeout_ms Per-scan timeout.
 * @param count Number of scans to run (>0).
 */
bool poom_nfc_debug_scan_loop(uint32_t period_ms, uint32_t timeout_ms, uint32_t count);

#ifdef __cplusplus
}
#endif
