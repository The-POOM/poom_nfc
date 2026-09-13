// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 THE POOM

#include "poom_nfc_emulator_t4t.h"

#include <stdbool.h>
#include <string.h>

#include "esp_heap_caps.h"

#define POOM_NFC_EMU_DEFAULT_URI "https://poom.stellar-iot.com/"

enum
{
    POOM_T4T_CLA_00 = 0x00,
    POOM_T4T_INS_SELECT = 0xA4,
    POOM_T4T_INS_READ = 0xB0,
    POOM_T4T_INS_UPDATE = 0xD6,
    POOM_T4T_FID_CC_H = 0xE1,
    POOM_T4T_FID_CC_L = 0x03,
    POOM_T4T_FID_NDEF_H = 0x00,
    POOM_T4T_FID_NDEF_L = 0x01,
    POOM_T4T_FILE_COUNT = 2,
    POOM_T4T_FILE_IDX_CC = 0,
    POOM_T4T_FILE_IDX_NDEF = 1,
    POOM_T4T_FILE_NONE = -1,
    POOM_T4T_CC_FILE_LEN = 15,
    POOM_T4T_CC_NDEF_MSB_IDX = 11,
    POOM_T4T_CC_NDEF_LSB_IDX = 12,
    POOM_T4T_URI_MAX_LEN = 240,
    POOM_T4T_NDEF_MAX = 1024,
    POOM_T4T_NDEF_HDR_LEN = 2,
    POOM_T4T_NDEF_REC_MIN_LEN = 5,
    POOM_T4T_NDEF_URI_TYPE = 0x55,
    POOM_T4T_NDEF_MB_ME_SR_TNF_WELLKNOWN = 0xD1,
    POOM_T4T_NDEF_TYPE_LEN_URI = 0x01,
    POOM_T4T_NDEF_URI_PREFIX_NONE = 0x00,
    POOM_T4T_APDU_MIN_LEN = 5,
    POOM_T4T_APDU_SW_LEN = 2,
    POOM_T4T_SW1_OK = 0x90,
    POOM_T4T_SW2_OK = 0x00,
    POOM_T4T_SW1_FUNC_NOT_SUPP = 0x68,
    POOM_T4T_SW1_WRONG_LEN = 0x67,
    POOM_T4T_SW1_NOT_FOUND = 0x6A,
    POOM_T4T_SW2_NOT_FOUND = 0x82,
    POOM_T4T_SW1_WARN = 0x62,
    POOM_T4T_SW1_TECHNICAL = 0x6F,
    POOM_T4T_CMD_FIND_LIMIT = 20,
};

typedef enum
{
    POOM_T4T_STATE_IDLE = 0,
    POOM_T4T_STATE_APP_SELECTED,
    POOM_T4T_STATE_CC_SELECTED,
    POOM_T4T_STATE_FID_SELECTED,
} poom_t4t_state_t;

struct poom_nfc_emu_t4t
{
    poom_t4t_state_t state;
    int selected_idx;
    uint8_t cc_file[POOM_T4T_CC_FILE_LEN];
    uint32_t file_size[POOM_T4T_FILE_COUNT];
    uint8_t ndef_file[POOM_T4T_NDEF_MAX];
};

static const uint8_t s_cc_file_template[POOM_T4T_CC_FILE_LEN] = {
    0x00, 0x0F, 0x20, 0x00, 0x7F, 0x00, 0x7F, 0x04, 0x06, POOM_T4T_FID_NDEF_H,
    POOM_T4T_FID_NDEF_L, 0x00, 0x00, 0x00, 0x00,
};

static uint16_t poom_nfc_emu_t4t_put_sw_(uint8_t* rsp,
                                         uint16_t rsp_max,
                                         uint8_t sw1,
                                         uint8_t sw2)
{
    if((rsp == NULL) || (rsp_max < POOM_T4T_APDU_SW_LEN))
    {
        return 0U;
    }
    rsp[0] = sw1;
    rsp[1] = sw2;
    return POOM_T4T_APDU_SW_LEN;
}

static bool poom_nfc_emu_t4t_cmd_find_(const uint8_t* cmd,
                                       uint16_t cmd_len,
                                       const uint8_t* needle,
                                       uint16_t needle_len)
{
    uint16_t limit;

    if((cmd == NULL) || (needle == NULL) || (cmd_len == 0U) || (needle_len == 0U) ||
       (needle_len > cmd_len))
    {
        return false;
    }

    limit = (cmd_len > POOM_T4T_CMD_FIND_LIMIT) ? POOM_T4T_CMD_FIND_LIMIT : cmd_len;
    for(uint16_t i = 0U; (uint16_t)(i + needle_len) <= limit; i++)
    {
        if(memcmp(&cmd[i], needle, needle_len) == 0)
        {
            return true;
        }
    }
    return false;
}

static void poom_nfc_emu_t4t_rebuild_cc_(poom_nfc_emu_t4t_t* instance)
{
    uint16_t ndef_size =
        (instance->file_size[POOM_T4T_FILE_IDX_NDEF] > 0xFFFFU) ?
            0xFFFFU : (uint16_t)instance->file_size[POOM_T4T_FILE_IDX_NDEF];

    memcpy(instance->cc_file, s_cc_file_template, sizeof(instance->cc_file));
    instance->cc_file[POOM_T4T_CC_NDEF_MSB_IDX] = (uint8_t)(ndef_size >> 8);
    instance->cc_file[POOM_T4T_CC_NDEF_LSB_IDX] = (uint8_t)ndef_size;
}

static void poom_nfc_emu_t4t_build_ndef_(poom_nfc_emu_t4t_t* instance, const char* uri)
{
    size_t uri_len;
    size_t payload_len;
    size_t record_len;
    uint8_t* p;

    if((uri == NULL) || (uri[0] == '\0'))
    {
        uri = POOM_NFC_EMU_DEFAULT_URI;
    }
    uri_len = strlen(uri);
    if(uri_len > POOM_T4T_URI_MAX_LEN)
    {
        uri_len = POOM_T4T_URI_MAX_LEN;
    }

    payload_len = 1U + uri_len;
    record_len = POOM_T4T_NDEF_REC_MIN_LEN + uri_len;
    if((POOM_T4T_NDEF_HDR_LEN + record_len) > sizeof(instance->ndef_file))
    {
        record_len = sizeof(instance->ndef_file) - POOM_T4T_NDEF_HDR_LEN;
        uri_len = record_len - POOM_T4T_NDEF_REC_MIN_LEN;
        payload_len = 1U + uri_len;
    }

    p = instance->ndef_file;
    p[0] = (uint8_t)(record_len >> 8);
    p[1] = (uint8_t)record_len;
    p[2] = POOM_T4T_NDEF_MB_ME_SR_TNF_WELLKNOWN;
    p[3] = POOM_T4T_NDEF_TYPE_LEN_URI;
    p[4] = (uint8_t)payload_len;
    p[5] = POOM_T4T_NDEF_URI_TYPE;
    p[6] = POOM_T4T_NDEF_URI_PREFIX_NONE;
    memcpy(&p[7], uri, uri_len);

    instance->file_size[POOM_T4T_FILE_IDX_CC] = sizeof(instance->cc_file);
    instance->file_size[POOM_T4T_FILE_IDX_NDEF] =
        (uint32_t)(POOM_T4T_NDEF_HDR_LEN + record_len);
    poom_nfc_emu_t4t_rebuild_cc_(instance);
}

poom_nfc_emu_t4t_t* poom_nfc_emu_t4t_alloc(const char* uri)
{
    poom_nfc_emu_t4t_t* instance = heap_caps_calloc(
        1U, sizeof(poom_nfc_emu_t4t_t), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if(instance != NULL)
    {
        poom_nfc_emu_t4t_build_ndef_(instance, uri);
        poom_nfc_emu_t4t_reset(instance);
    }
    return instance;
}

void poom_nfc_emu_t4t_free(poom_nfc_emu_t4t_t* instance)
{
    heap_caps_free(instance);
}

void poom_nfc_emu_t4t_reset(poom_nfc_emu_t4t_t* instance)
{
    if(instance != NULL)
    {
        instance->state = POOM_T4T_STATE_IDLE;
        instance->selected_idx = POOM_T4T_FILE_NONE;
    }
}

static uint16_t poom_nfc_emu_t4t_select_(poom_nfc_emu_t4t_t* instance,
                                         const uint8_t* cmd,
                                         uint16_t cmd_len,
                                         uint8_t* rsp,
                                         uint16_t rsp_max)
{
    static const uint8_t aid[] = {0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01};
    static const uint8_t fid_cc[] = {POOM_T4T_FID_CC_H, POOM_T4T_FID_CC_L};
    static const uint8_t fid_ndef[] = {POOM_T4T_FID_NDEF_H, POOM_T4T_FID_NDEF_L};
    static const uint8_t select_file_id[] = {0xA4, 0x00, 0x0C, 0x02, 0x00, 0x01};
    bool selected = false;

    if(poom_nfc_emu_t4t_cmd_find_(cmd, cmd_len, aid, sizeof(aid)))
    {
        instance->state = POOM_T4T_STATE_APP_SELECTED;
        selected = true;
    }
    else if((instance->state >= POOM_T4T_STATE_APP_SELECTED) &&
            poom_nfc_emu_t4t_cmd_find_(cmd, cmd_len, fid_cc, sizeof(fid_cc)))
    {
        instance->state = POOM_T4T_STATE_CC_SELECTED;
        instance->selected_idx = POOM_T4T_FILE_IDX_CC;
        selected = true;
    }
    else if((instance->state >= POOM_T4T_STATE_APP_SELECTED) &&
            (poom_nfc_emu_t4t_cmd_find_(cmd, cmd_len, fid_ndef, sizeof(fid_ndef)) ||
             poom_nfc_emu_t4t_cmd_find_(cmd, cmd_len, select_file_id, sizeof(select_file_id))))
    {
        instance->state = POOM_T4T_STATE_FID_SELECTED;
        instance->selected_idx = POOM_T4T_FILE_IDX_NDEF;
        selected = true;
    }
    else
    {
        poom_nfc_emu_t4t_reset(instance);
    }

    return selected ? poom_nfc_emu_t4t_put_sw_(rsp, rsp_max, POOM_T4T_SW1_OK, POOM_T4T_SW2_OK) :
                      poom_nfc_emu_t4t_put_sw_(rsp, rsp_max, POOM_T4T_SW1_NOT_FOUND,
                                              POOM_T4T_SW2_NOT_FOUND);
}

static uint16_t poom_nfc_emu_t4t_read_(poom_nfc_emu_t4t_t* instance,
                                       const uint8_t* cmd,
                                       uint16_t cmd_len,
                                       uint8_t* rsp,
                                       uint16_t rsp_max)
{
    uint16_t offset;
    uint16_t to_read;
    const uint8_t* source;
    uint32_t file_len;

    if((cmd_len < POOM_T4T_APDU_MIN_LEN) || (rsp_max < POOM_T4T_APDU_SW_LEN) ||
       (instance->selected_idx < 0) || (instance->selected_idx >= POOM_T4T_FILE_COUNT))
    {
        return poom_nfc_emu_t4t_put_sw_(rsp, rsp_max, POOM_T4T_SW1_NOT_FOUND,
                                        POOM_T4T_SW2_NOT_FOUND);
    }

    offset = (uint16_t)(((uint16_t)cmd[2] << 8) | cmd[3]);
    to_read = cmd[4];
    file_len = instance->file_size[instance->selected_idx];
    if(offset >= file_len)
    {
        to_read = 0U;
    }
    else if(((uint32_t)offset + to_read) > file_len)
    {
        to_read = (uint16_t)(file_len - offset);
    }
    if(((uint32_t)to_read + POOM_T4T_APDU_SW_LEN) > rsp_max)
    {
        return poom_nfc_emu_t4t_put_sw_(rsp, rsp_max, POOM_T4T_SW1_TECHNICAL,
                                        POOM_T4T_SW2_OK);
    }

    source = (instance->selected_idx == POOM_T4T_FILE_IDX_CC) ?
                 instance->cc_file : instance->ndef_file;
    memcpy(rsp, &source[offset], to_read);
    rsp[to_read] = POOM_T4T_SW1_OK;
    rsp[to_read + 1U] = POOM_T4T_SW2_OK;
    return (uint16_t)(to_read + POOM_T4T_APDU_SW_LEN);
}

static uint16_t poom_nfc_emu_t4t_update_(poom_nfc_emu_t4t_t* instance,
                                         const uint8_t* cmd,
                                         uint16_t cmd_len,
                                         uint8_t* rsp,
                                         uint16_t rsp_max)
{
    uint16_t offset;
    uint16_t length;

    if((cmd_len < POOM_T4T_APDU_MIN_LEN) ||
       (instance->selected_idx != POOM_T4T_FILE_IDX_NDEF))
    {
        return poom_nfc_emu_t4t_put_sw_(rsp, rsp_max, POOM_T4T_SW1_NOT_FOUND,
                                        POOM_T4T_SW2_NOT_FOUND);
    }
    offset = (uint16_t)(((uint16_t)cmd[2] << 8) | cmd[3]);
    length = cmd[4];
    if((uint16_t)(POOM_T4T_APDU_MIN_LEN + length) > cmd_len)
    {
        return poom_nfc_emu_t4t_put_sw_(rsp, rsp_max, POOM_T4T_SW1_WRONG_LEN,
                                        POOM_T4T_SW2_OK);
    }
    if(((uint32_t)offset + length) > instance->file_size[POOM_T4T_FILE_IDX_NDEF])
    {
        return poom_nfc_emu_t4t_put_sw_(rsp, rsp_max, POOM_T4T_SW1_WARN,
                                        POOM_T4T_SW2_NOT_FOUND);
    }

    memcpy(&instance->ndef_file[offset], &cmd[5], length);
    return poom_nfc_emu_t4t_put_sw_(rsp, rsp_max, POOM_T4T_SW1_OK, POOM_T4T_SW2_OK);
}

uint16_t poom_nfc_emu_t4t_process(poom_nfc_emu_t4t_t* instance,
                                  const uint8_t* cmd,
                                  uint16_t cmd_len,
                                  uint8_t* rsp,
                                  uint16_t rsp_max)
{
    if((instance == NULL) || (cmd == NULL) || (rsp == NULL) ||
       (cmd_len < POOM_T4T_APDU_SW_LEN) || (rsp_max < POOM_T4T_APDU_SW_LEN))
    {
        return 0U;
    }
    if(cmd[0] == POOM_T4T_CLA_00)
    {
        switch(cmd[1])
        {
            case POOM_T4T_INS_SELECT:
                return poom_nfc_emu_t4t_select_(instance, cmd, cmd_len, rsp, rsp_max);
            case POOM_T4T_INS_READ:
                return poom_nfc_emu_t4t_read_(instance, cmd, cmd_len, rsp, rsp_max);
            case POOM_T4T_INS_UPDATE:
                return poom_nfc_emu_t4t_update_(instance, cmd, cmd_len, rsp, rsp_max);
            default:
                break;
        }
    }
    return poom_nfc_emu_t4t_put_sw_(rsp, rsp_max, POOM_T4T_SW1_FUNC_NOT_SUPP,
                                    POOM_T4T_SW2_OK);
}

