// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 THE POOM

#pragma once
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Perform one-time NFC core initialization.
 *
 * Initializes the shared synchronization primitive, I2C device, IRQ handling,
 * and RFAL NFC stack.
 */
bool poom_nfc_core_init(void);

/**
 * @brief Run a single scan/select/read cycle.
 *
 * This helper is intended for simple CLI flows.
 *
 * @param[in] timeout_ms Discovery timeout in milliseconds.
 * @return true on success, false otherwise.
 */
bool poom_nfc_core_read_once(uint32_t timeout_ms);

/**
 * @brief Deinitialize the NFC core and clear runtime state.
 *
 * Powers down the active flow so CLI commands such as `nfc-core-stop` can leave the
 * subsystem in a clean state.
 */
void poom_nfc_core_deinit(void);

#ifdef __cplusplus
}
#endif
