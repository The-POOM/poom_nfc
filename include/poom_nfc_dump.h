// SPDX-License-Identifier: MIT
// Copyright (c) 2026 THE POOM

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "poom_nfc_cards.h"

#ifdef __cplusplus
extern "C" {
#endif

#define POOM_NFC_DUMP_FORMAT_VERSION (1U)
#define POOM_NFC_DUMP_MAX_PAGES (256U)
#define POOM_NFC_DUMP_PAGE_SIZE (4U)

typedef enum
{
    POOM_NFC_DUMP_READ_ID_ONLY = 0,
    POOM_NFC_DUMP_READ_FULL,
} poom_nfc_dump_read_mode_t;

typedef struct
{
    poom_nfc_dump_read_mode_t read_mode;
    bool read_ok;

    poom_nfc_card_id_t id;

    bool has_version_bytes;
    uint8_t version_bytes[8];

    bool has_signature;
    uint8_t signature[32];

    uint16_t pages_total;
    uint16_t pages_read;
    uint8_t page_size;

    uint16_t user_mem_start_page;
    uint16_t user_mem_end_page;
    uint16_t lock_bytes_page;
    uint16_t dynamic_lock_bytes_page;
    uint16_t config_start_page;

    uint8_t pages[POOM_NFC_DUMP_MAX_PAGES][POOM_NFC_DUMP_PAGE_SIZE];
} poom_nfc_dump_t;

typedef enum
{
    POOM_NFC_T2T_PRODUCT_UNKNOWN = 0,
    POOM_NFC_T2T_PRODUCT_NTAG213,
    POOM_NFC_T2T_PRODUCT_NTAG215,
    POOM_NFC_T2T_PRODUCT_NTAG216,
} poom_nfc_t2t_product_t;

poom_nfc_t2t_product_t poom_nfc_dump_guess_t2t_product(const poom_nfc_dump_t *dump);
const char *poom_nfc_t2t_product_to_str(poom_nfc_t2t_product_t p);
bool poom_nfc_dump_get_t2t_total_bytes(const poom_nfc_dump_t *dump, uint16_t *out_total_bytes);
bool poom_nfc_dump_get_t2t_user_bytes(const poom_nfc_dump_t *dump, uint16_t *out_user_bytes);

/**
 * @brief Save NFC dump to SD card as a structured text file.
 *
 * Output path is relative (does not include SD_CARD_PATH).
 *
 * @param[in] dump Dump object.
 * @param[out] out_rel_path Optional output relative path (e.g. "/nfc_dumps/x.nfc").
 * @param[in] out_rel_path_len Output buffer length.
 * @return esp_err_t
 */
esp_err_t poom_nfc_dump_save_to_sd(const poom_nfc_dump_t *dump, char *out_rel_path, size_t out_rel_path_len);

/**
 * @brief Save MFUL/Type2 captures using the unified structured dump format (.nfc).
 *
 * This requires a full NFC-A Type 2 dump (read_mode=FULL with pages read) and
 * stores the file under `/nfc_dumps`.
 *
 * @param[in] dump Dump object captured from reader.
 * @param[out] out_rel_path Optional output relative path (e.g. "/nfc_dumps/x.nfc").
 * @param[in] out_rel_path_len Output buffer length.
 * @return ESP_OK on success, otherwise an ESP error code.
 */
esp_err_t poom_nfc_dump_save_mful_bin_to_sd(const poom_nfc_dump_t *dump,
                                           char *out_rel_path,
                                           size_t out_rel_path_len);

/**
 * @brief Load the card ID fields (UID/ATQA/SAK when present) from an SD dump file.
 *
 * @param[in] rel_path Dump file path relative to SD root (e.g. "/nfc_dumps/x.nfc").
 * @param[out] out_id Parsed card ID.
 * @return ESP_OK on success, otherwise an ESP error code.
 */
esp_err_t poom_nfc_dump_load_card_id_from_sd(const char *rel_path, poom_nfc_card_id_t *out_id);

#ifdef __cplusplus
}
#endif
