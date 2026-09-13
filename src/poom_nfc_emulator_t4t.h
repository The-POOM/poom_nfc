// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 THE POOM

#pragma once

#include <stddef.h>
#include <stdint.h>

typedef struct poom_nfc_emu_t4t poom_nfc_emu_t4t_t;

poom_nfc_emu_t4t_t* poom_nfc_emu_t4t_alloc(const char* uri);
void poom_nfc_emu_t4t_free(poom_nfc_emu_t4t_t* instance);
void poom_nfc_emu_t4t_reset(poom_nfc_emu_t4t_t* instance);

uint16_t poom_nfc_emu_t4t_process(poom_nfc_emu_t4t_t* instance,
                                  const uint8_t* cmd,
                                  uint16_t cmd_len,
                                  uint8_t* rsp,
                                  uint16_t rsp_max);

