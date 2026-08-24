// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 THE POOM

#include "poom_nfc_tuning.h"

#include <stdio.h>

#include "rfal_chip.h"
#include "rfal_platform.h"
#include "st25r3916.h"
#include "st25r3916_aat.h"

#ifndef ERR_NONE
#define ERR_NONE (0U)
#endif

enum {
    POOM_AAT_CAP_DELAY_MS = 10,
};

/**
 * @brief Internal helper for `poom_round_int`.
 *
 * @param[in] x Parameter passed to the function.
 * @return int
 */
static int poom_round_int(float x)
{
    return (int)(x + 0.5f);
}

/**
 * @brief Internal helper for `poom_phase_degree`.
 *
 * @param[in] phase_raw Parameter passed to the function.
 * @return int
 */
static int poom_phase_degree(uint8_t phase_raw)
{
    return poom_round_int(17.0f + (((1.0f - ((float)phase_raw / 255.0f)) * 146.0f)));
}

/**
 * @brief Internal helper for `poom_amplitude_mvpp`.
 *
 * @param[in] amplitude_raw Parameter passed to the function.
 * @return int
 */
static int poom_amplitude_mvpp(uint8_t amplitude_raw)
{
    return poom_round_int(13.02f * (float)amplitude_raw);
}

/**
 * @brief Internal helper for `poom_fill_runtime_measurements`.
 *
 * @param[in] out Parameter passed to the function.
 * @param[in] keep_measure_count Parameter passed to the function.
 * @return bool
 */
static bool poom_fill_runtime_measurements(
    poom_nfc_tuning_result_t *out,
    bool keep_measure_count
)
{
    ReturnCode err;

    if (out == NULL) {
        return false;
    }

    err = rfalChipMeasureAmplitude(&out->amplitude_raw);
    if (err != ERR_NONE) {
        printf("nfc-tuning: rfalChipMeasureAmplitude error=%d\r\n", err);
        return false;
    }

    err = rfalChipMeasurePhase(&out->phase_raw);
    if (err != ERR_NONE) {
        printf("nfc-tuning: rfalChipMeasurePhase error=%d\r\n", err);
        return false;
    }

    err = st25r3916ReadRegister(ST25R3916_REG_ANT_TUNE_A, &out->aat_a);
    if (err != ERR_NONE) {
        printf("nfc-tuning: read AAT_A error=%d\r\n", err);
        return false;
    }

    err = st25r3916ReadRegister(ST25R3916_REG_ANT_TUNE_B, &out->aat_b);
    if (err != ERR_NONE) {
        printf("nfc-tuning: read AAT_B error=%d\r\n", err);
        return false;
    }

    out->phase_degree = poom_phase_degree(out->phase_raw);
    out->amplitude_mvpp = poom_amplitude_mvpp(out->amplitude_raw);
    if (!keep_measure_count) {
        out->measure_count = 0;
    }

    return true;
}

bool poom_nfc_tuning_auto(poom_nfc_tuning_result_t *out)
{
    ReturnCode err;
    struct st25r3916AatTuneResult tune;

    if (out == NULL) {
        return false;
    }

    err = st25r3916AatTune(NULL, &tune);
    if (err != ERR_NONE) {
        printf("nfc-tuning: st25r3916AatTune error=%d\r\n", err);
        return false;
    }

    out->aat_a = tune.aat_a;
    out->aat_b = tune.aat_b;
    out->phase_raw = tune.pha;
    out->amplitude_raw = tune.amp;
    out->measure_count = tune.measureCnt;
    out->phase_degree = poom_phase_degree(out->phase_raw);
    out->amplitude_mvpp = poom_amplitude_mvpp(out->amplitude_raw);

    return poom_fill_runtime_measurements(out, true);
}

bool poom_nfc_tuning_set(uint8_t aat_a, uint8_t aat_b, poom_nfc_tuning_result_t *out)
{
    ReturnCode err;

    if (out == NULL) {
        return false;
    }

    err = st25r3916WriteRegister(ST25R3916_REG_ANT_TUNE_A, aat_a);
    if (err != ERR_NONE) {
        printf("nfc-tuning: write AAT_A error=%d\r\n", err);
        return false;
    }

    err = st25r3916WriteRegister(ST25R3916_REG_ANT_TUNE_B, aat_b);
    if (err != ERR_NONE) {
        printf("nfc-tuning: write AAT_B error=%d\r\n", err);
        return false;
    }

    platformDelay(POOM_AAT_CAP_DELAY_MS);
    return poom_fill_runtime_measurements(out, false);
}

bool poom_nfc_tuning_get(poom_nfc_tuning_result_t *out)
{
    return poom_fill_runtime_measurements(out, false);
}
