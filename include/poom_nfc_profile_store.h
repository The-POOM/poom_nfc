#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#include "poom_nfc_profile.h"

#ifdef __cplusplus
extern "C" {
#endif

#define POOM_NFC_PROFILE_STORE_MAX (20U)
#define POOM_NFC_PROFILE_STORE_KEY_PROFILES "nfc_profiles"

typedef struct
{
    uint8_t count;
    poom_nfc_profile_t profiles[POOM_NFC_PROFILE_STORE_MAX];
} poom_nfc_profile_store_t;

/**
 * @brief Loads NFC profiles from persistent storage.
 *
 * @param[out] out_store Destination store buffer.
 * @return esp_err_t
 */
esp_err_t poom_nfc_profile_store_load(poom_nfc_profile_store_t* out_store);

/**
 * @brief Saves NFC profiles to persistent storage.
 *
 * @param[in] store Source store buffer.
 * @return esp_err_t
 */
esp_err_t poom_nfc_profile_store_save(const poom_nfc_profile_store_t* store);

/**
 * @brief Adds or updates one NFC profile in persistent storage.
 *
 * @param[in] profile Profile to add or update.
 * @param[out] out_added Set when a new profile was added.
 * @param[out] out_updated Set when an existing profile was updated.
 * @param[out] out_no_space Set when storage is full.
 * @return esp_err_t
 */
esp_err_t poom_nfc_profile_store_add(const poom_nfc_profile_t* profile,
                                    size_t* out_added,
                                    size_t* out_updated,
                                    size_t* out_no_space);

/**
 * @brief Removes one NFC profile by index.
 *
 * @param[in] index Profile index to remove.
 * @param[out] out_removed Set when the profile was removed.
 * @return esp_err_t
 */
esp_err_t poom_nfc_profile_store_remove_index(uint8_t index, bool* out_removed);

/**
 * @brief Clears all stored NFC profiles.
 *
 * @return esp_err_t
 */
esp_err_t poom_nfc_profile_store_clear(void);

#ifdef __cplusplus
}
#endif
