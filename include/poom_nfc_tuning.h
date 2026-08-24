// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 THE POOM

#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t aat_a;
    uint8_t aat_b;
    uint8_t phase_raw;
    uint8_t amplitude_raw;
    int phase_degree;
    int amplitude_mvpp;
    uint16_t measure_count;
} poom_nfc_tuning_result_t;

bool poom_nfc_tuning_auto(poom_nfc_tuning_result_t *out);
bool poom_nfc_tuning_set(uint8_t aat_a, uint8_t aat_b, poom_nfc_tuning_result_t *out);
bool poom_nfc_tuning_get(poom_nfc_tuning_result_t *out);

#ifdef __cplusplus
}
#endif
