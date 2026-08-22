#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "esp_err.h"
#include "poom_nfc_cards.h"
#include "poom_nfc_dump.h"
#include "poom_nfc_tuning.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    POOM_NFC_CTRL_TECH_ALL = 0,
    POOM_NFC_CTRL_TECH_A,
    POOM_NFC_CTRL_TECH_B,
    POOM_NFC_CTRL_TECH_F,
    POOM_NFC_CTRL_TECH_V,
    POOM_NFC_CTRL_TECH_ST25TB,
} poom_nfc_ctrl_tech_t;

bool poom_nfc_controller_start(void);
bool poom_nfc_controller_scan_once(uint32_t timeout_ms);
bool poom_nfc_controller_scan_found_cards(uint32_t timeout_ms,
                                         poom_nfc_card_id_t* out_cards,
                                         size_t max_cards,
                                         size_t* out_count);

/**
 * @brief Scan a nearby NFC tag and capture a dump object in RAM (no SD write).
 *
 * This is the building block for "SCAN" UX: read and show tag info, then allow
 * user actions (save embedded / save to SD) without re-scanning.
 *
 * @param[in] timeout_ms Time to wait for tag activation.
 * @param[out] out_dump Dump object.
 * @return true on success, false otherwise.
 */
bool poom_nfc_controller_capture_dump(uint32_t timeout_ms, poom_nfc_dump_t *out_dump);

/**
 * @brief Capture a detailed dump of a nearby NFC tag and save it to SD card.
 *
 * @param[in] timeout_ms Time to wait for tag activation.
 * @param[out] out_rel_path Optional output relative path (e.g. "/nfc_dumps/x.nfc").
 * @param[in] out_rel_path_len Output buffer length.
 * @return ESP_OK on success, otherwise an ESP error code.
 */
esp_err_t poom_nfc_controller_dump_to_sd(uint32_t timeout_ms, char *out_rel_path, size_t out_rel_path_len);

/**
 * @brief Scan a nearby NFC tag and save an MFUL/Type2 structured `.nfc` dump to SD.
 *
 * Requires full readable NFC-A Type2 tag memory. Returns ESP_ERR_INVALID_STATE
 * if only ID-level data is available.
 *
 * @param[in] timeout_ms Time to wait for tag activation.
 * @param[out] out_rel_path Optional output relative path (e.g. "/nfc_dumps/x.nfc").
 * @param[in] out_rel_path_len Output buffer length.
 * @return ESP_OK on success, otherwise an ESP error code.
 */
esp_err_t poom_nfc_controller_mful_bin_to_sd(uint32_t timeout_ms, char *out_rel_path, size_t out_rel_path_len);

bool poom_nfc_controller_connect(void);
bool poom_nfc_controller_send_raw_hex(const char *hex_ascii);
void poom_nfc_controller_stop(void);
bool poom_nfc_controller_tune_auto(poom_nfc_tuning_result_t *out);
bool poom_nfc_controller_tune_set(uint8_t aat_a, uint8_t aat_b, poom_nfc_tuning_result_t *out);
bool poom_nfc_controller_tune_get(poom_nfc_tuning_result_t *out);

void poom_nfc_controller_set_technology(poom_nfc_ctrl_tech_t tech);
poom_nfc_ctrl_tech_t poom_nfc_controller_get_technology(void);
const char *poom_nfc_controller_technology_to_str(poom_nfc_ctrl_tech_t tech);

#ifdef __cplusplus
}
#endif
