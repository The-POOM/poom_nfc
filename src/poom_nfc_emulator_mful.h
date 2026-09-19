// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 THE POOM

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "poom_nfc_emulator.h"

typedef struct poom_nfc_emu_mful poom_nfc_emu_mful_t;

poom_nfc_emu_mful_t* poom_nfc_emu_mful_alloc(const char* path,
                                               poom_nfc_emu_cfg_t* cfg);
void poom_nfc_emu_mful_free(poom_nfc_emu_mful_t* instance);
void poom_nfc_emu_mful_reset(poom_nfc_emu_mful_t* instance);
bool poom_nfc_emu_mful_is_amiibo(const poom_nfc_emu_mful_t* instance);
uint16_t poom_nfc_emu_mful_process(poom_nfc_emu_mful_t* instance,
                                    const uint8_t* cmd,
                                    uint16_t cmd_len,
                                    uint8_t* rsp,
                                    uint16_t rsp_max,
                                    bool* restart);
