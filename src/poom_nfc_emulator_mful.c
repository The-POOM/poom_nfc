// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 THE POOM

#include "poom_nfc_emulator_mful.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_heap_caps.h"
#include "rfal_rf.h"
#include "sd_card.h"

enum
{
    MFUL_PAGE_SIZE = 4,
    MFUL_PAGE_MAX = 231,
    MFUL_READ_LEN = 16,
    MFUL_ACK_BITS = 4,
    MFUL_ACK = 0x0A,
    MFUL_NAK = 0x00,
    MFUL_READ = 0x30,
    MFUL_FAST_READ = 0x3A,
    MFUL_WRITE = 0xA2,
    MFUL_COMPAT_WRITE = 0xA0,
    MFUL_PWD_AUTH = 0x1B,
    MFUL_READ_CNT = 0x39,
    MFUL_READ_SIG = 0x3C,
    MFUL_GET_VERSION = 0x60,
};

struct poom_nfc_emu_mful
{
    uint8_t image[MFUL_PAGE_MAX * MFUL_PAGE_SIZE];
    uint8_t signature[32];
    uint8_t version[8];
    uint16_t pages;
    uint8_t user_last;
    uint8_t dyn_lock_page;
    uint8_t cfg0_page;
    uint8_t cfg1_page;
    uint8_t pwd_page;
    uint8_t pack_page;
    uint8_t compat_page;
    bool compat_pending;
    bool auth_ok;
};

static const uint8_t s_factory[16] = {
    0x04, 0x3B, 0x99, 0x2E, 0x0A, 0x9D, 0x32, 0x80,
    0x25, 0x48, 0x0F, 0xE0, 0xF1, 0x10, 0xFF, 0xEE,
};

static void mful_variant_(poom_nfc_emu_mful_t* m, uint16_t pages)
{
    if(pages == 45U)
    {
        static const uint8_t version[8] = {0x00,0x04,0x04,0x02,0x01,0x00,0x0F,0x03};
        m->pages = 45U; m->user_last = 0x27; m->dyn_lock_page = 0x28;
        m->cfg0_page = 0x29; m->cfg1_page = 0x2A; m->pwd_page = 0x2B; m->pack_page = 0x2C;
        memcpy(m->version, version, sizeof(version));
    }
    else if(pages == 231U)
    {
        static const uint8_t version[8] = {0x00,0x04,0x04,0x02,0x01,0x00,0x13,0x03};
        m->pages = 231U; m->user_last = 0xE1; m->dyn_lock_page = 0xE2;
        m->cfg0_page = 0xE3; m->cfg1_page = 0xE4; m->pwd_page = 0xE5; m->pack_page = 0xE6;
        memcpy(m->version, version, sizeof(version));
    }
    else
    {
        static const uint8_t version[8] = {0x00,0x04,0x04,0x02,0x01,0x00,0x11,0x03};
        m->pages = 135U; m->user_last = 0x81; m->dyn_lock_page = 0x82;
        m->cfg0_page = 0x83; m->cfg1_page = 0x84; m->pwd_page = 0x85; m->pack_page = 0x86;
        memcpy(m->version, version, sizeof(version));
    }
}

static void mful_factory_(poom_nfc_emu_mful_t* m, poom_nfc_emu_cfg_t* cfg)
{
    memset(m->image, 0, sizeof(m->image));
    memcpy(m->image, s_factory, sizeof(s_factory));
    mful_variant_(m, 135U);
    if(cfg->uid_len == 7U)
    {
        m->image[0] = cfg->uid[0]; m->image[1] = cfg->uid[1]; m->image[2] = cfg->uid[2];
        m->image[4] = cfg->uid[3]; m->image[5] = cfg->uid[4]; m->image[6] = cfg->uid[5]; m->image[7] = cfg->uid[6];
        m->image[3] = (uint8_t)(0x88U ^ cfg->uid[0] ^ cfg->uid[1] ^ cfg->uid[2]);
        m->image[8] = (uint8_t)(cfg->uid[3] ^ cfg->uid[4] ^ cfg->uid[5] ^ cfg->uid[6]);
    }
}

static bool mful_hex_(char* text, uint8_t* out, size_t count)
{
    char* save = NULL;
    char* token = strtok_r(text, " \t\r\n", &save);
    size_t i = 0U;
    while(token != NULL && i < count)
    {
        char* end = NULL;
        unsigned long value;
        if(!isxdigit((unsigned char)token[0])) return false;
        value = strtoul(token, &end, 16);
        if(end == token || value > 0xFFU) return false;
        out[i++] = (uint8_t)value;
        token = strtok_r(NULL, " \t\r\n", &save);
    }
    return i == count;
}

static bool mful_load_text_(poom_nfc_emu_mful_t* m, FILE* f, poom_nfc_emu_cfg_t* cfg)
{
    char line[320];
    uint16_t pages = 0U;
    bool is_mful = false;
    bool any_page = false;
    rewind(f);
    while(fgets(line, sizeof(line), f) != NULL)
    {
        char* value = strchr(line, ':');
        if(strstr(line, "Mifare Ultralight") != NULL || strstr(line, "NTAG21") != NULL) is_mful = true;
        if(value == NULL) continue;
        *value++ = '\0';
        while(isspace((unsigned char)*value)) value++;
        if(strcmp(line, "Pages total") == 0)
            pages = (uint16_t)strtoul(value, NULL, 10);
        else if(strcmp(line, "UID") == 0)
        {
            char copy[96];
            strncpy(copy, value, sizeof(copy) - 1U); copy[sizeof(copy) - 1U] = '\0';
            if(mful_hex_(copy, cfg->uid, 7U)) cfg->uid_len = 7U;
        }
        else if(strcmp(line, "ATQA") == 0)
        {
            char copy[32]; strncpy(copy, value, sizeof(copy) - 1U); copy[sizeof(copy) - 1U] = '\0';
            if(mful_hex_(copy, cfg->atqa, 2U)) cfg->atqa_set = true;
        }
        else if(strcmp(line, "SAK") == 0)
        {
            char copy[16]; strncpy(copy, value, sizeof(copy) - 1U); copy[sizeof(copy) - 1U] = '\0';
            if(mful_hex_(copy, &cfg->sak, 1U)) cfg->sak_set = true;
        }
        else if(strcmp(line, "Signature") == 0)
        {
            char copy[256]; strncpy(copy, value, sizeof(copy) - 1U); copy[sizeof(copy) - 1U] = '\0';
            (void)mful_hex_(copy, m->signature, sizeof(m->signature));
        }
        else if(strcmp(line, "Mifare version") == 0 || strcmp(line, "Version bytes") == 0)
        {
            char copy[96]; strncpy(copy, value, sizeof(copy) - 1U); copy[sizeof(copy) - 1U] = '\0';
            (void)mful_hex_(copy, m->version, sizeof(m->version));
        }
        else if(strncmp(line, "Page ", 5U) == 0)
        {
            const unsigned long page = strtoul(&line[5], NULL, 10);
            char copy[48];
            if(page >= MFUL_PAGE_MAX) continue;
            strncpy(copy, value, sizeof(copy) - 1U); copy[sizeof(copy) - 1U] = '\0';
            if(mful_hex_(copy, &m->image[page * MFUL_PAGE_SIZE], MFUL_PAGE_SIZE))
            {
                any_page = true;
                if(page + 1U > pages) pages = (uint16_t)(page + 1U);
            }
        }
    }
    if(!is_mful || !any_page) return false;
    mful_variant_(m, pages <= 45U ? 45U : (pages <= 135U ? 135U : 231U));
    return cfg->uid_len == 7U;
}

static bool mful_load_(poom_nfc_emu_mful_t* m, const char* path, poom_nfc_emu_cfg_t* cfg)
{
    FILE* f;
    long size;
    if(!sd_card_is_mounted() && sd_card_mount() != ESP_OK) return false;
    f = fopen(path, "rb");
    if(f == NULL) return false;
    if(fseek(f, 0, SEEK_END) != 0) { fclose(f); return false; }
    size = ftell(f);
    rewind(f);
    if(size == 180L || size == 540L || size == 924L)
    {
        const uint16_t pages = (uint16_t)(size / MFUL_PAGE_SIZE);
        mful_variant_(m, pages);
        if(fread(m->image, 1U, (size_t)size, f) != (size_t)size) { fclose(f); return false; }
        memcpy(cfg->uid, (uint8_t[]){m->image[0],m->image[1],m->image[2],m->image[4],m->image[5],m->image[6],m->image[7]}, 7U);
        cfg->uid_len = 7U;
        fclose(f);
        return true;
    }
    const bool ok = mful_load_text_(m, f, cfg);
    fclose(f);
    return ok;
}

static bool mful_locked_(const poom_nfc_emu_mful_t* m, uint8_t page)
{
    const uint16_t locks = (uint16_t)m->image[10] | ((uint16_t)m->image[11] << 8);
    if(page < 3U) return true;
    if(page <= 15U)
    {
        const uint8_t bit = (page <= 7U) ? (uint8_t)(page - 3U) : (uint8_t)(page - 2U);
        return (locks & (1U << bit)) != 0U;
    }
    return false;
}

static bool mful_requires_auth_(const poom_nfc_emu_mful_t* m, uint8_t page, bool write)
{
    const uint8_t auth0 = m->image[(uint16_t)m->cfg0_page * 4U + 3U];
    const bool prot = (m->image[(uint16_t)m->cfg1_page * 4U] & 0x80U) != 0U;
    return auth0 <= page && (write || prot) && !m->auth_ok;
}

static uint16_t mful_nak_(uint8_t* rsp, bool* restart)
{
    rsp[0] = MFUL_NAK;
    if(restart != NULL) *restart = true;
    return MFUL_ACK_BITS;
}

poom_nfc_emu_mful_t* poom_nfc_emu_mful_alloc(const char* path, poom_nfc_emu_cfg_t* cfg)
{
    poom_nfc_emu_mful_t* m;
    if(cfg == NULL) return NULL;
    m = heap_caps_calloc(1U, sizeof(*m), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if(m == NULL) return NULL;
    mful_factory_(m, cfg);
    if(path != NULL && path[0] != '\0' && !mful_load_(m, path, cfg))
    {
        heap_caps_free(m);
        return NULL;
    }
    return m;
}

void poom_nfc_emu_mful_free(poom_nfc_emu_mful_t* instance)
{
    heap_caps_free(instance);
}

void poom_nfc_emu_mful_reset(poom_nfc_emu_mful_t* instance)
{
    if(instance == NULL) return;
    instance->auth_ok = false;
    instance->compat_pending = false;
}

uint16_t poom_nfc_emu_mful_process(poom_nfc_emu_mful_t* m, const uint8_t* cmd,
                                    uint16_t cmd_len, uint8_t* rsp, uint16_t rsp_max,
                                    bool* restart)
{
    uint8_t page;
    if(restart != NULL) *restart = false;
    if(m == NULL || cmd == NULL || rsp == NULL || cmd_len == 0U) return 0U;
    if(m->compat_pending)
    {
        m->compat_pending = false;
        if(cmd_len != 16U || mful_locked_(m, m->compat_page) || mful_requires_auth_(m, m->compat_page, true))
            return mful_nak_(rsp, restart);
        memcpy(&m->image[(uint16_t)m->compat_page * 4U], cmd, 4U);
        rsp[0] = MFUL_ACK;
        return MFUL_ACK_BITS;
    }
    page = cmd_len > 1U ? cmd[1] : 0U;
    switch(cmd[0])
    {
        case MFUL_READ:
            if(cmd_len != 2U || page >= m->pages || rsp_max < MFUL_READ_LEN || mful_requires_auth_(m, page, false))
                return mful_nak_(rsp, restart);
            for(uint8_t i = 0U; i < MFUL_READ_LEN; i++)
                rsp[i] = m->image[(((uint16_t)page * 4U + i) % ((uint16_t)m->pages * 4U))];
            return rfalConvBytesToBits(MFUL_READ_LEN);
        case MFUL_FAST_READ:
            if(cmd_len != 3U || page > cmd[2] || cmd[2] >= m->pages ||
               (uint16_t)(cmd[2] - page + 1U) * 4U > rsp_max || mful_requires_auth_(m, page, false))
                return mful_nak_(rsp, restart);
            memcpy(rsp, &m->image[(uint16_t)page * 4U], (size_t)(cmd[2] - page + 1U) * 4U);
            return rfalConvBytesToBits((uint16_t)(cmd[2] - page + 1U) * 4U);
        case MFUL_WRITE:
            if(cmd_len != 6U || page >= m->pages || mful_locked_(m, page) || mful_requires_auth_(m, page, true))
                return mful_nak_(rsp, restart);
            if(page == 2U || page == 3U)
                for(uint8_t i = 0U; i < 4U; i++) m->image[(uint16_t)page * 4U + i] |= cmd[2U + i];
            else
                memcpy(&m->image[(uint16_t)page * 4U], &cmd[2], 4U);
            rsp[0] = MFUL_ACK;
            return MFUL_ACK_BITS;
        case MFUL_COMPAT_WRITE:
            if(cmd_len != 2U || page >= m->pages || mful_locked_(m, page) || mful_requires_auth_(m, page, true))
                return mful_nak_(rsp, restart);
            m->compat_page = page; m->compat_pending = true; rsp[0] = MFUL_ACK;
            return MFUL_ACK_BITS;
        case MFUL_PWD_AUTH:
            if(cmd_len != 5U || memcmp(&cmd[1], &m->image[(uint16_t)m->pwd_page * 4U], 4U) != 0)
                return mful_nak_(rsp, restart);
            if(rsp_max < 2U) return 0U;
            m->auth_ok = true;
            memcpy(rsp, &m->image[(uint16_t)m->pack_page * 4U], 2U);
            return 16U;
        case MFUL_GET_VERSION:
            if(cmd_len != 1U || rsp_max < sizeof(m->version)) return mful_nak_(rsp, restart);
            memcpy(rsp, m->version, sizeof(m->version)); return 64U;
        case MFUL_READ_CNT:
            if(cmd_len != 2U || page > 2U || rsp_max < 3U) return mful_nak_(rsp, restart);
            memset(rsp, 0, 3U); return 24U;
        case MFUL_READ_SIG:
            if(cmd_len != 2U || page != 0U || rsp_max < sizeof(m->signature)) return mful_nak_(rsp, restart);
            memcpy(rsp, m->signature, sizeof(m->signature)); return 256U;
        case 0x50:
            if(cmd_len == 2U && page == 0U) { if(restart != NULL) *restart = true; return 0U; }
            break;
        default:
            break;
    }
    return mful_nak_(rsp, restart);
}

