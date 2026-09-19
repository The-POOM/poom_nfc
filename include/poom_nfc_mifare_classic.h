// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 THE POOM

/* MIFARE Classic / Mini support. */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "poom_nfc_card_ident.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum
{
    POOM_MIFARE_KEY_A = 0x60, /* MIFARE Classic AUTH A cmd */
    POOM_MIFARE_KEY_B = 0x61, /* MIFARE Classic AUTH B cmd */
} poom_mifare_key_type_t;

typedef enum
{
    POOM_MIFARE_AUTH_STATUS_NONE = 0,
    POOM_MIFARE_AUTH_STATUS_FAIL,
    POOM_MIFARE_AUTH_STATUS_PARTIAL,
    POOM_MIFARE_AUTH_STATUS_FULL,
} poom_mifare_auth_status_t;

typedef enum
{
    POOM_MIFARE_RESTORE_OK = 0,
    POOM_MIFARE_RESTORE_PARTIAL,
    POOM_MIFARE_RESTORE_INVALID_FILE,
    POOM_MIFARE_RESTORE_SIZE_MISMATCH,
    POOM_MIFARE_RESTORE_NO_CARD,
    POOM_MIFARE_RESTORE_NO_MEMORY,
} poom_mifare_restore_status_t;

/**
 * @brief Predicate used to stop a long-running default-key discovery.
 *
 * @param[in] user_ctx Opaque context supplied by the caller.
 * @return true when discovery should stop.
 */
typedef bool (*poom_mifare_cancel_cb_t)(void* user_ctx);

typedef struct
{
    uint16_t source_blocks;
    uint16_t compared;
    uint16_t unchanged;
    uint16_t written;
    uint16_t verified;
    uint16_t skipped;
    uint16_t failed;
    uint16_t trailers_written;
    bool block0_different;
} poom_mifare_restore_result_t;

typedef void (*poom_mifare_restore_progress_cb_t)(uint16_t completed,
                                                   uint16_t total,
                                                   uint8_t block,
                                                   void* user_ctx);

/* Initialize/reset local Classic/Mini session context. */
void poom_mifare_classic_init(void);
void poom_mifare_classic_reset(void);

/* Returns true for MIFARE Mini/Classic family handled by this module. */
bool poom_mifare_classic_is_supported_card(nfc_card_type_t card_type);

/* Bind the currently selected card (UID + detected type) to the session. */
bool poom_mifare_classic_bind_card(const uint8_t* uid,
                                   uint8_t uid_len,
                                   nfc_card_type_t card_type);
bool poom_mifare_classic_has_card(void);

/* Optional helper: default key dictionary commonly found on blank/test cards.
 */
const uint8_t* poom_mifare_classic_get_default_key(size_t idx);
size_t poom_mifare_classic_get_default_key_count(void);

/*
 * NOTE:
 * - `poom_mifare_classic_auth()` performs the Classic AUTH handshake and (when
 *   supported by the current RFAL path) validates Crypto1 step2/step3.
 * - `poom_mifare_classic_read_block()` / `poom_mifare_classic_write_block()`
 *   implement secure (Crypto1) read/write and will try cached keys, last-known
 *   working keys, then the default dictionary.
 */
bool poom_mifare_classic_auth(uint8_t block,
                              poom_mifare_key_type_t key_type,
                              const uint8_t key[6]);
bool poom_mifare_classic_read_block(uint8_t block, uint8_t out_data[16]);
bool poom_mifare_classic_write_block(uint8_t block, const uint8_t data[16]);

/**
 * @brief Restore a Classic dump by writing only blocks that differ.
 *
 * Block 0 is compared but never written. Data blocks are processed first.
 * Sector trailers are optional and, when enabled, are written last after all
 * ordinary data has been verified.
 *
 * @param[in] rel_path Dump path relative to the SD root (for example
 *            `/nfc/Classic1K_x.nfc`).
 * @param[in] write_trailers Also restore sector keys/access bits.
 * @param[out] out_result Operation counters.
 * @param[in] progress_cb Optional progress callback.
 * @param[in] user_ctx Value passed to progress_cb.
 * @return Detailed restore status.
 */
poom_mifare_restore_status_t poom_mifare_classic_restore_file(
    const char* rel_path,
    bool write_trailers,
    poom_mifare_restore_result_t* out_result,
    poom_mifare_restore_progress_cb_t progress_cb,
    void* user_ctx);

/* Capability helper for CLI/runtime checks (true for current auth phase). */
poom_mifare_auth_status_t poom_mifare_classic_get_last_auth_status(void);

/* Tries the default key dictionary for the given block + key type. */
bool poom_mifare_classic_try_default_keys(uint8_t block,
                                          poom_mifare_key_type_t key_type,
                                          size_t* matched_idx);

/**
 * @brief Return the sector count for the currently bound Classic/Mini card.
 * @return uint8_t Sector count, or 0 when no card is bound.
 */
uint8_t poom_mifare_classic_get_sector_count(void);

/**
 * @brief Get a cached (discovered) sector key.
 *
 * Keys are cached after a successful auth or after a discovery scan.
 *
 * @param[in] sector Sector index.
 * @param[in] key_type Key type (A or B).
 * @param[out] out_key 6-byte key output buffer.
 * @return true if key is available for the sector.
 */
bool poom_mifare_classic_get_sector_key(uint8_t sector,
                                       poom_mifare_key_type_t key_type,
                                       uint8_t out_key[6]);

/**
 * @brief Resolve which sector owns a given absolute block number.
 *
 * @param[in] block Absolute block number.
 * @return int Sector index, or -1 when no compatible card is currently bound or
 *         the block is out of range for the active card.
 */
int poom_mifare_classic_sector_for_block(uint8_t block);

/**
 * @brief Return the maximum valid absolute block number for the active card.
 *
 * @return uint16_t Maximum block index, or 0 when no card is currently bound.
 */
uint16_t poom_mifare_classic_get_max_block(void);

/**
 * @brief Scan all sectors using the default key dictionary and cache matches.
 *
 * This performs repeated AUTH attempts to discover Key A and (optionally) Key B
 * per sector. It does not read blocks (Crypto1 secure read/write is handled by
 * separate APIs).
 *
 * @param[in] try_key_b When true, try Key B discovery as well.
 * @return true when at least one key is discovered.
 */
bool poom_mifare_classic_discover_default_keys(bool try_key_b);

/**
 * @brief Scan sectors with the default keys while allowing cooperative cancellation.
 *
 * The callback is checked between authentication attempts. A NULL callback keeps
 * the same behavior as `poom_mifare_classic_discover_default_keys()`.
 *
 * @param[in] try_key_b When true, try Key B discovery as well.
 * @param[in] cancel_cb Optional predicate that requests cancellation.
 * @param[in] user_ctx Opaque context passed to cancel_cb.
 * @return true when at least one key is available and cancellation was not requested.
 */
bool poom_mifare_classic_discover_default_keys_cancelable(
    bool try_key_b, poom_mifare_cancel_cb_t cancel_cb, void* user_ctx);

/**
 * @brief Dump all Classic blocks and write a Flipper `.nfc` file to the SD card.
 *
 * The file is written under the provided directory (e.g. "/nfc") and uses a
 * name derived from card type + UID (e.g. "Classic1K_04-11-22-33.nfc").
 *
 * This is intended for authorized testing and development environments only.
 *
 * @param[in] out_dir Output directory on SD root (e.g. "/nfc").
 * @param[in] try_key_b When true, attempt Key B discovery as well.
 * @param[out] out_path Full relative output path written (may be NULL).
 * @param[in] out_path_len Length of out_path buffer.
 * @return true on success.
 */
bool poom_mifare_classic_dump_to_flipper_file(const char* out_dir,
                                              bool try_key_b,
                                              char* out_path,
                                              size_t out_path_len);

/**
 * @brief Dump all Classic blocks to a POOM memory image file on the SD card.
 *
 * The file is written under the provided directory (e.g. "/nfc") and uses a
 * name derived from card type + UID (e.g. "Classic1K_04-11-22-33_poom.nfc").
 *
 * The header is POOM-specific while the memory body keeps the block-oriented
 * layout used by MIFARE Classic dumps (`Block N: ...`).
 *
 * This is intended for authorized testing and development environments only.
 *
 * @param[in] out_dir Output directory on SD root (e.g. "/nfc").
 * @param[in] try_key_b When true, attempt Key B discovery as well.
 * @param[out] out_path Full relative output path written (may be NULL).
 * @param[in] out_path_len Length of out_path buffer.
 * @return true on success.
 */
bool poom_mifare_classic_dump_to_poom_memory_file(const char* out_dir,
                                                  bool try_key_b,
                                                  char* out_path,
                                                  size_t out_path_len);

#ifdef __cplusplus
}
#endif
