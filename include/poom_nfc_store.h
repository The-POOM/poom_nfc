// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 THE POOM

#pragma once

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

#include "poom_nfc_cards.h"

#ifdef __cplusplus
extern "C" {
#endif

#define POOM_NFC_STORE_MAX_CARDS (30U)
#define POOM_NFC_STORE_KEY_CARDS "nfc_cards"

typedef struct
{
    uint8_t count;
    poom_nfc_card_id_t cards[POOM_NFC_STORE_MAX_CARDS];
} poom_nfc_store_t;

esp_err_t poom_nfc_store_load(poom_nfc_store_t* out_store);

esp_err_t poom_nfc_store_save(const poom_nfc_store_t* store);

esp_err_t poom_nfc_store_add_cards(const poom_nfc_card_id_t* cards,
                                  size_t card_count,
                                  size_t* out_added,
                                  size_t* out_already_present,
                                  size_t* out_no_space);

esp_err_t poom_nfc_store_clear(void);

esp_err_t poom_nfc_store_remove_index(uint8_t index, bool* out_removed);

esp_err_t poom_nfc_store_remove_card(const poom_nfc_card_id_t* card, bool* out_removed);

#ifdef __cplusplus
}
#endif
