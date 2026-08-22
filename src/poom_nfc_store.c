// SPDX-License-Identifier: MIT
// Copyright (c) 2026 THE POOM

#include "poom_nfc_store.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "esp_err.h"
#include "nvs.h"
#include "poom_secrets_store.h"

#define POOM_NFC_STORE_MAGIC (0x4E464331UL) /* NFC1 */
#define POOM_NFC_STORE_VERSION (2U)

typedef struct __attribute__((packed))
{
    uint8_t type;
    uint8_t uid_len;
    uint8_t uid[POOM_NFC_CARD_UID_MAX];
} poom_nfc_card_id_v1_t;

typedef struct __attribute__((packed))
{
    uint32_t magic;
    uint8_t version;
    uint8_t count;
    uint16_t reserved;
    poom_nfc_card_id_v1_t cards[POOM_NFC_STORE_MAX_CARDS];
} poom_nfc_store_blob_v1_t;

typedef struct __attribute__((packed))
{
    uint32_t magic;
    uint8_t version;
    uint8_t count;
    uint16_t reserved;
    poom_nfc_card_id_t cards[POOM_NFC_STORE_MAX_CARDS];
} poom_nfc_store_blob_v2_t;

/**
 * @brief Internal helper for `poom_nfc_store_zero`.
 *
 * @param[in] out_store Parameter passed to the function.
 * @return void
 */
static void poom_nfc_store_zero_(poom_nfc_store_t* out_store)
{
    if (out_store == NULL)
    {
        return;
    }

    (void)memset(out_store, 0, sizeof(*out_store));
}

esp_err_t poom_nfc_store_load(poom_nfc_store_t* out_store)
{
    esp_err_t status;
    poom_nfc_store_blob_v2_t blob;
    size_t blob_len;

    poom_nfc_store_zero_(out_store);

    status = poom_secrets_init();
    if (status != ESP_OK)
    {
        return status;
    }

    blob_len = sizeof(blob);
    status = poom_secrets_get_blob(POOM_NFC_STORE_KEY_CARDS, &blob, &blob_len);
    if (status == ESP_ERR_NVS_NOT_FOUND)
    {
        return ESP_OK;
    }
    if (status != ESP_OK)
    {
        return status;
    }
    if (out_store == NULL)
    {
        return ESP_OK;
    }

    if (blob_len == sizeof(poom_nfc_store_blob_v2_t))
    {
        if ((blob.magic != POOM_NFC_STORE_MAGIC) || (blob.version != POOM_NFC_STORE_VERSION))
        {
            return ESP_OK;
        }

        out_store->count = blob.count;
        if (out_store->count > POOM_NFC_STORE_MAX_CARDS)
        {
            out_store->count = POOM_NFC_STORE_MAX_CARDS;
        }

        (void)memcpy(out_store->cards, blob.cards, sizeof(out_store->cards));
        return ESP_OK;
    }

    if (blob_len == sizeof(poom_nfc_store_blob_v1_t))
    {
        poom_nfc_store_blob_v1_t v1;
        (void)memset(&v1, 0, sizeof(v1));
        (void)memcpy(&v1, &blob, sizeof(v1));
        if ((v1.magic != POOM_NFC_STORE_MAGIC) || (v1.version != 1U))
        {
            return ESP_OK;
        }

        out_store->count = v1.count;
        if (out_store->count > POOM_NFC_STORE_MAX_CARDS)
        {
            out_store->count = POOM_NFC_STORE_MAX_CARDS;
        }

        for (uint8_t i = 0U; i < out_store->count; i++)
        {
            (void)memset(&out_store->cards[i], 0, sizeof(out_store->cards[i]));
            out_store->cards[i].type = v1.cards[i].type;
            out_store->cards[i].uid_len = v1.cards[i].uid_len;
            (void)memcpy(out_store->cards[i].uid, v1.cards[i].uid, sizeof(out_store->cards[i].uid));
        }

        return ESP_OK;
    }

    return ESP_OK;
}

esp_err_t poom_nfc_store_save(const poom_nfc_store_t* store)
{
    esp_err_t status;
    poom_nfc_store_blob_v2_t blob;

    status = poom_secrets_init();
    if (status != ESP_OK)
    {
        return status;
    }

    (void)memset(&blob, 0, sizeof(blob));
    blob.magic = POOM_NFC_STORE_MAGIC;
    blob.version = POOM_NFC_STORE_VERSION;

    if (store != NULL)
    {
        blob.count = store->count;
        if (blob.count > POOM_NFC_STORE_MAX_CARDS)
        {
            blob.count = POOM_NFC_STORE_MAX_CARDS;
        }
        (void)memcpy(blob.cards, store->cards, sizeof(blob.cards));
    }

    return poom_secrets_set_blob(POOM_NFC_STORE_KEY_CARDS, &blob, sizeof(blob));
}

esp_err_t poom_nfc_store_add_cards(const poom_nfc_card_id_t* cards,
                                  size_t card_count,
                                  size_t* out_added,
                                  size_t* out_already_present,
                                  size_t* out_no_space)
{
    esp_err_t status;
    poom_nfc_store_t store;
    size_t added = 0U;
    size_t already = 0U;
    size_t no_space = 0U;
    size_t i;
    bool changed = false;

    status = poom_nfc_store_load(&store);
    if (status != ESP_OK)
    {
        return status;
    }

    for (i = 0U; i < card_count; i++)
    {
        const poom_nfc_card_id_t* id = &cards[i];
        if (!poom_nfc_card_id_is_valid(id))
        {
            continue;
        }

        int found_idx = -1;
        for (uint8_t j = 0U; j < store.count; j++)
        {
            if (poom_nfc_card_id_equal(&store.cards[j], id))
            {
                found_idx = (int)j;
                break;
            }
        }

        if (found_idx >= 0)
        {
            already++;

            poom_nfc_card_id_t* existing = &store.cards[(uint8_t)found_idx];

            if ((id->flags & POOM_NFC_CARD_FLAG_ATQA_SET) != 0U)
            {
                if (((existing->flags & POOM_NFC_CARD_FLAG_ATQA_SET) == 0U) ||
                    (existing->atqa[0] != id->atqa[0]) || (existing->atqa[1] != id->atqa[1]))
                {
                    existing->atqa[0] = id->atqa[0];
                    existing->atqa[1] = id->atqa[1];
                    existing->flags |= POOM_NFC_CARD_FLAG_ATQA_SET;
                    changed = true;
                }
            }

            if ((id->flags & POOM_NFC_CARD_FLAG_SAK_SET) != 0U)
            {
                if (((existing->flags & POOM_NFC_CARD_FLAG_SAK_SET) == 0U) ||
                    (existing->sak != id->sak))
                {
                    existing->sak = id->sak;
                    existing->flags |= POOM_NFC_CARD_FLAG_SAK_SET;
                    changed = true;
                }
            }

            continue;
        }

        if (store.count >= POOM_NFC_STORE_MAX_CARDS)
        {
            no_space++;
            continue;
        }

        store.cards[store.count] = *id;
        store.count++;
        added++;
        changed = true;
    }

    if (changed)
    {
        status = poom_nfc_store_save(&store);
        if (status != ESP_OK)
        {
            return status;
        }
    }

    if (out_added != NULL)
    {
        *out_added = added;
    }
    if (out_already_present != NULL)
    {
        *out_already_present = already;
    }
    if (out_no_space != NULL)
    {
        *out_no_space = no_space;
    }

    return ESP_OK;
}

esp_err_t poom_nfc_store_clear(void)
{
    esp_err_t status;

    status = poom_secrets_init();
    if (status != ESP_OK)
    {
        return status;
    }

    return poom_secrets_erase_key(POOM_NFC_STORE_KEY_CARDS);
}


/**
 * @brief Internal helper for `poom_nfc_store_remove_at`.
 *
 * @param[in] store Parameter passed to the function.
 * @param[in] index Parameter passed to the function.
 * @return void
 */
static void poom_nfc_store_remove_at_(poom_nfc_store_t* store, uint8_t index)
{
    if (store == NULL)
    {
        return;
    }

    if (index >= store->count)
    {
        return;
    }

    for (uint8_t i = index; (uint8_t)(i + 1U) < store->count; i++)
    {
        store->cards[i] = store->cards[i + 1U];
    }

    store->count--;
    (void)memset(&store->cards[store->count], 0, sizeof(store->cards[store->count]));
}

esp_err_t poom_nfc_store_remove_index(uint8_t index, bool* out_removed)
{
    esp_err_t status;
    poom_nfc_store_t store;

    if (out_removed != NULL)
    {
        *out_removed = false;
    }

    status = poom_nfc_store_load(&store);
    if (status != ESP_OK)
    {
        return status;
    }

    if (index >= store.count)
    {
        return ESP_OK;
    }

    poom_nfc_store_remove_at_(&store, index);

    status = poom_nfc_store_save(&store);
    if (status != ESP_OK)
    {
        return status;
    }

    if (out_removed != NULL)
    {
        *out_removed = true;
    }

    return ESP_OK;
}

esp_err_t poom_nfc_store_remove_card(const poom_nfc_card_id_t* card, bool* out_removed)
{
    esp_err_t status;
    poom_nfc_store_t store;

    if (out_removed != NULL)
    {
        *out_removed = false;
    }

    if (!poom_nfc_card_id_is_valid(card))
    {
        return ESP_OK;
    }

    status = poom_nfc_store_load(&store);
    if (status != ESP_OK)
    {
        return status;
    }

    for (uint8_t i = 0U; i < store.count; i++)
    {
        if (poom_nfc_card_id_equal(&store.cards[i], card))
        {
            poom_nfc_store_remove_at_(&store, i);
            status = poom_nfc_store_save(&store);
            if (status != ESP_OK)
            {
                return status;
            }
            if (out_removed != NULL)
            {
                *out_removed = true;
            }
            return ESP_OK;
        }
    }

    return ESP_OK;
}
