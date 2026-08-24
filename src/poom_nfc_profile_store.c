// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 THE POOM

#include "poom_nfc_profile_store.h"

#include <string.h>

#include "nvs.h"
#include "poom_secrets_store.h"

#define POOM_NFC_PROFILE_STORE_MAGIC (0x4E465031UL) /* NFP1 */
#define POOM_NFC_PROFILE_STORE_VERSION (1U)

typedef struct __attribute__((packed))
{
    uint32_t magic;
    uint8_t version;
    uint8_t count;
    uint16_t reserved;
    poom_nfc_profile_t profiles[POOM_NFC_PROFILE_STORE_MAX];
} poom_nfc_profile_store_blob_v1_t;

/**
 * @brief Internal helper for `poom_nfc_profile_store_zero`.
 *
 * @param[in] out_store Parameter passed to the function.
 * @return void
 */
static void poom_nfc_profile_store_zero_(poom_nfc_profile_store_t* out_store)
{
    if(out_store == NULL)
    {
        return;
    }
    (void)memset(out_store, 0, sizeof(*out_store));
}

/**
 * @brief Internal helper for `poom_nfc_profile_uid_equal`.
 *
 * @param[in] a Parameter passed to the function.
 * @param[in] b Parameter passed to the function.
 * @return bool
 */
static bool poom_nfc_profile_uid_equal_(const poom_nfc_profile_t* a,
                                       const poom_nfc_profile_t* b)
{
    if((a == NULL) || (b == NULL))
    {
        return false;
    }
    if((a->uid_len == 0U) || (a->uid_len != b->uid_len) || (a->uid_len > (uint8_t)sizeof(a->uid)))
    {
        return false;
    }
    return memcmp(a->uid, b->uid, a->uid_len) == 0;
}

esp_err_t poom_nfc_profile_store_load(poom_nfc_profile_store_t* out_store)
{
    esp_err_t status;
    poom_nfc_profile_store_blob_v1_t blob;
    size_t blob_len = sizeof(blob);

    poom_nfc_profile_store_zero_(out_store);

    status = poom_secrets_init();
    if(status != ESP_OK)
    {
        return status;
    }

    (void)memset(&blob, 0, sizeof(blob));
    status =
        poom_secrets_get_blob(POOM_NFC_PROFILE_STORE_KEY_PROFILES, &blob, &blob_len);
    if(status == ESP_ERR_NVS_NOT_FOUND)
    {
        return ESP_OK;
    }
    if(status != ESP_OK)
    {
        return status;
    }
    if(out_store == NULL)
    {
        return ESP_OK;
    }

    if((blob_len != sizeof(blob)) || (blob.magic != POOM_NFC_PROFILE_STORE_MAGIC) ||
       (blob.version != POOM_NFC_PROFILE_STORE_VERSION))
    {
        return ESP_OK;
    }

    out_store->count = blob.count;
    if(out_store->count > POOM_NFC_PROFILE_STORE_MAX)
    {
        out_store->count = POOM_NFC_PROFILE_STORE_MAX;
    }
    (void)memcpy(out_store->profiles, blob.profiles, sizeof(out_store->profiles));
    return ESP_OK;
}

esp_err_t poom_nfc_profile_store_save(const poom_nfc_profile_store_t* store)
{
    esp_err_t status = poom_secrets_init();
    if(status != ESP_OK)
    {
        return status;
    }

    poom_nfc_profile_store_blob_v1_t blob;
    (void)memset(&blob, 0, sizeof(blob));
    blob.magic = POOM_NFC_PROFILE_STORE_MAGIC;
    blob.version = POOM_NFC_PROFILE_STORE_VERSION;

    if(store != NULL)
    {
        blob.count = store->count;
        if(blob.count > POOM_NFC_PROFILE_STORE_MAX)
        {
            blob.count = POOM_NFC_PROFILE_STORE_MAX;
        }
        (void)memcpy(blob.profiles, store->profiles, sizeof(blob.profiles));
    }

    return poom_secrets_set_blob(POOM_NFC_PROFILE_STORE_KEY_PROFILES, &blob, sizeof(blob));
}

esp_err_t poom_nfc_profile_store_add(const poom_nfc_profile_t* profile,
                                    size_t* out_added,
                                    size_t* out_updated,
                                    size_t* out_no_space)
{
    if(out_added)
        *out_added = 0U;
    if(out_updated)
        *out_updated = 0U;
    if(out_no_space)
        *out_no_space = 0U;

    if((profile == NULL) || (profile->uid_len == 0U))
    {
        return ESP_ERR_INVALID_ARG;
    }

    poom_nfc_profile_store_t store;
    esp_err_t st = poom_nfc_profile_store_load(&store);
    if(st != ESP_OK)
    {
        return st;
    }

    for(uint8_t i = 0U; i < store.count; i++)
    {
        if(poom_nfc_profile_uid_equal_(&store.profiles[i], profile))
        {
            store.profiles[i] = *profile;
            st = poom_nfc_profile_store_save(&store);
            if(st == ESP_OK && out_updated)
                *out_updated = 1U;
            return st;
        }
    }

    if(store.count >= POOM_NFC_PROFILE_STORE_MAX)
    {
        if(out_no_space)
            *out_no_space = 1U;
        return ESP_OK;
    }

    store.profiles[store.count] = *profile;
    store.count++;
    st = poom_nfc_profile_store_save(&store);
    if(st == ESP_OK && out_added)
        *out_added = 1U;
    return st;
}

esp_err_t poom_nfc_profile_store_remove_index(uint8_t index, bool* out_removed)
{
    if(out_removed)
        *out_removed = false;

    poom_nfc_profile_store_t store;
    esp_err_t st = poom_nfc_profile_store_load(&store);
    if(st != ESP_OK)
    {
        return st;
    }

    if(index >= store.count)
    {
        return ESP_OK;
    }

    for(uint8_t i = index; i + 1U < store.count; i++)
    {
        store.profiles[i] = store.profiles[i + 1U];
    }
    store.count--;

    st = poom_nfc_profile_store_save(&store);
    if(st == ESP_OK && out_removed)
        *out_removed = true;
    return st;
}

esp_err_t poom_nfc_profile_store_clear(void)
{
    poom_nfc_profile_store_t empty;
    poom_nfc_profile_store_zero_(&empty);
    return poom_nfc_profile_store_save(&empty);
}
