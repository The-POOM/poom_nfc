// SPDX-License-Identifier: MIT
// Copyright (c) 2026 THE POOM

#include "poom_nfc_dump.h"

#include <errno.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "esp_timer.h"
#include "poom_nfc_card_ident.h"
#include "sd_card.h"

#define POOM_NFC_DUMP_DIR "/nfc_dumps"

poom_nfc_t2t_product_t poom_nfc_dump_guess_t2t_product(const poom_nfc_dump_t *dump)
{
    if(dump == NULL)
    {
        return POOM_NFC_T2T_PRODUCT_UNKNOWN;
    }
    if(dump->read_mode != POOM_NFC_DUMP_READ_FULL)
    {
        return POOM_NFC_T2T_PRODUCT_UNKNOWN;
    }

    if(dump->has_version_bytes)
    {
        const uint8_t *v = dump->version_bytes;
        if((v[0] == 0x00U) && (v[1] == 0x04U) && (v[2] == 0x04U) && (v[3] == 0x02U) &&
           (v[4] == 0x01U) && (v[5] == 0x00U))
        {
            if(v[6] == 0x0FU) return POOM_NFC_T2T_PRODUCT_NTAG213;
            if(v[6] == 0x11U) return POOM_NFC_T2T_PRODUCT_NTAG215;
            if(v[6] == 0x13U) return POOM_NFC_T2T_PRODUCT_NTAG216;
        }
    }

    if(dump->pages_total == 45U)  return POOM_NFC_T2T_PRODUCT_NTAG213;
    if(dump->pages_total == 135U) return POOM_NFC_T2T_PRODUCT_NTAG215;
    if(dump->pages_total == 231U) return POOM_NFC_T2T_PRODUCT_NTAG216;
    return POOM_NFC_T2T_PRODUCT_UNKNOWN;
}

const char *poom_nfc_t2t_product_to_str(poom_nfc_t2t_product_t p)
{
    switch(p)
    {
        case POOM_NFC_T2T_PRODUCT_NTAG213: return "NTAG213";
        case POOM_NFC_T2T_PRODUCT_NTAG215: return "NTAG215";
        case POOM_NFC_T2T_PRODUCT_NTAG216: return "NTAG216";
        default:                           return "T2T";
    }
}

bool poom_nfc_dump_get_t2t_total_bytes(const poom_nfc_dump_t *dump, uint16_t *out_total_bytes)
{
    if(out_total_bytes == NULL)
    {
        return false;
    }
    *out_total_bytes = 0U;

    if((dump == NULL) || (dump->read_mode != POOM_NFC_DUMP_READ_FULL) || (dump->page_size == 0U))
    {
        return false;
    }
    if(dump->pages_total == 0U)
    {
        return false;
    }

    *out_total_bytes = (uint16_t)(dump->pages_total * (uint16_t)dump->page_size);
    return true;
}

bool poom_nfc_dump_get_t2t_user_bytes(const poom_nfc_dump_t *dump, uint16_t *out_user_bytes)
{
    if(out_user_bytes == NULL)
    {
        return false;
    }
    *out_user_bytes = 0U;

    if((dump == NULL) || (dump->read_mode != POOM_NFC_DUMP_READ_FULL) || (dump->page_size == 0U))
    {
        return false;
    }
    if(dump->user_mem_end_page < dump->user_mem_start_page)
    {
        return false;
    }

    const uint16_t pages = (uint16_t)(dump->user_mem_end_page - dump->user_mem_start_page + 1U);
    *out_user_bytes = (uint16_t)(pages * (uint16_t)dump->page_size);
    return true;
}

/**
 * @brief Internal helper for `poom_nfc_dump_path_exists`.
 *
 * @param[in] path Parameter passed to the function.
 * @return bool
 */
static bool poom_nfc_dump_path_exists_(const char *path)
{
    struct stat st;
    return (path != NULL) && (stat(path, &st) == 0);
}

/**
 * @brief Internal helper for `poom_nfc_dump_uid_hex`.
 *
 * @param[in] id Parameter passed to the function.
 * @param[in] out Parameter passed to the function.
 * @param[in] out_len Parameter passed to the function.
 * @return void
 */
static void poom_nfc_dump_uid_hex_(const poom_nfc_card_id_t *id, char *out, size_t out_len)
{
    if((out == NULL) || (out_len == 0U))
    {
        return;
    }

    out[0] = '\0';
    if(!poom_nfc_card_id_is_valid(id))
    {
        return;
    }

    size_t w = 0U;
    for(uint8_t i = 0U; (i < id->uid_len) && (w + 2U < out_len); i++)
    {
        w += (size_t)snprintf(&out[w], out_len - w, "%02X", id->uid[i]);
    }
}

/**
 * @brief Internal helper for `poom_nfc_dump_fprint_hex_bytes`.
 *
 * @param[in] f Parameter passed to the function.
 * @param[in] data Parameter passed to the function.
 * @param[in] len Parameter passed to the function.
 * @return void
 */
static void poom_nfc_dump_fprint_hex_bytes_(FILE *f, const uint8_t *data, size_t len)
{
    if((f == NULL) || (data == NULL))
    {
        return;
    }

    for(size_t i = 0U; i < len; i++)
    {
        (void)fprintf(f, "%02X%s", (unsigned)data[i], (i + 1U < len) ? " " : "");
    }
}

/**
 * @brief Internal helper for `poom_nfc_dump_fprint_uid_line`.
 *
 * @param[in] f Parameter passed to the function.
 * @param[in] id Parameter passed to the function.
 * @return void
 */
static void poom_nfc_dump_fprint_uid_line_(FILE *f, const poom_nfc_card_id_t *id)
{
    if((f == NULL) || (id == NULL))
    {
        return;
    }

    (void)fprintf(f, "UID length: %u\n", (unsigned)id->uid_len);
    (void)fprintf(f, "UID: ");
    poom_nfc_dump_fprint_hex_bytes_(f, id->uid, id->uid_len);
    (void)fprintf(f, "\n");
}

/**
 * @brief Returns the text representation for the current state.
 *
 * @param[in] listen_type Parameter passed to the function.
 * @return const char *
 */
static const char *poom_nfc_dump_protocol_str_(uint8_t listen_type)
{
    switch(listen_type)
    {
        case 0U:  /* RFAL_NFC_LISTEN_TYPE_NFCA */
        case 10U: /* RFAL_NFC_POLL_TYPE_NFCA */
            return "ISO14443A";
        case 1U:
        case 11U:
            return "ISO14443B";
        case 2U:
        case 12U:
            return "NFCF";
        case 3U:
        case 13U:
            return "NFCV";
        default:
            return "UNKNOWN";
    }
}

/**
 * @brief Internal helper for `poom_nfc_dump_device_type_guess`.
 *
 * @param[in] dump Parameter passed to the function.
 * @return const char *
 */
static const char *poom_nfc_dump_device_type_guess_(const poom_nfc_dump_t *dump)
{
    if(dump == NULL)
    {
        return "UNKNOWN";
    }

    if(dump->read_mode != POOM_NFC_DUMP_READ_FULL)
    {
        return "UNKNOWN";
    }

    const poom_nfc_t2t_product_t p = poom_nfc_dump_guess_t2t_product(dump);
    if(p != POOM_NFC_T2T_PRODUCT_UNKNOWN)
    {
        return poom_nfc_t2t_product_to_str(p);
    }

    return "T2T";
}

/**
 * @brief Internal helper for `poom_nfc_dump_build_abs_path`.
 *
 * @param[in] rel_path Parameter passed to the function.
 * @param[in] out_abs_path Parameter passed to the function.
 * @param[in] out_abs_path_len Parameter passed to the function.
 * @return esp_err_t
 */
static esp_err_t poom_nfc_dump_build_abs_path_(const char *rel_path, char *out_abs_path, size_t out_abs_path_len)
{
    if((rel_path == NULL) || (out_abs_path == NULL) || (out_abs_path_len == 0U))
    {
        return ESP_ERR_INVALID_ARG;
    }

    int written;
    if(rel_path[0] == '/')
    {
        written = snprintf(out_abs_path, out_abs_path_len, "%s%s", SD_CARD_PATH, rel_path);
    }
    else
    {
        written = snprintf(out_abs_path, out_abs_path_len, "%s/%s", SD_CARD_PATH, rel_path);
    }

    if((written < 0) || ((size_t)written >= out_abs_path_len))
    {
        return ESP_ERR_NO_MEM;
    }

    return ESP_OK;
}

/**
 * @brief Parses input data for this module.
 *
 * @param[in] s Parameter passed to the function.
 * @param[in] out Parameter passed to the function.
 * @param[in] out_max Parameter passed to the function.
 * @param[in] out_len Parameter passed to the function.
 * @return bool
 */
static bool poom_nfc_dump_parse_hex_bytes_(const char *s, uint8_t *out, size_t out_max, size_t *out_len)
{
    if(out_len == NULL)
    {
        return false;
    }
    *out_len = 0U;

    if((s == NULL) || (out == NULL) || (out_max == 0U))
    {
        return false;
    }

    while((*out_len) < out_max)
    {
        while((*s != '\0') && isspace((unsigned char)*s))
        {
            s++;
        }

        if(!isxdigit((unsigned char)s[0]))
        {
            break;
        }

        char *end = NULL;
        const unsigned long v = strtoul(s, &end, 16);
        if((end == NULL) || (end == s) || (v > 0xFFUL))
        {
            return false;
        }

        out[*out_len] = (uint8_t)v;
        (*out_len)++;
        s = end;
    }

    return (*out_len) > 0U;
}

/**
 * @brief Internal helper for `poom_nfc_dump_build_unique_rel_path`.
 *
 * @param[in] dump Parameter passed to the function.
 * @param[in] out_rel_path Parameter passed to the function.
 * @param[in] out_rel_path_len Parameter passed to the function.
 * @return esp_err_t
 */
static esp_err_t poom_nfc_dump_build_unique_rel_path_(const poom_nfc_dump_t *dump,
                                                     char *out_rel_path,
                                                     size_t out_rel_path_len)
{
    char uid_hex[POOM_NFC_CARD_UID_MAX * 2U + 1U];
    uint64_t ts_ms;
    char abs_path[192];

    if((dump == NULL) || (out_rel_path == NULL) || (out_rel_path_len == 0U))
    {
        return ESP_ERR_INVALID_ARG;
    }

    poom_nfc_dump_uid_hex_(&dump->id, uid_hex, sizeof(uid_hex));
    if(uid_hex[0] == '\0')
    {
        (void)snprintf(uid_hex, sizeof(uid_hex), "no_uid");
    }

    ts_ms = (uint64_t)esp_timer_get_time() / 1000U;

    for(int i = 0; i < 1000; i++)
    {
        int written = snprintf(out_rel_path, out_rel_path_len, "%s/nfc_%s_%llu_%d.nfc", POOM_NFC_DUMP_DIR, uid_hex,
                               (unsigned long long)ts_ms, i);
        if((written < 0) || ((size_t)written >= out_rel_path_len))
        {
            return ESP_ERR_NO_MEM;
        }

        if(poom_nfc_dump_build_abs_path_(out_rel_path, abs_path, sizeof(abs_path)) != ESP_OK)
        {
            return ESP_ERR_NO_MEM;
        }

        if(!poom_nfc_dump_path_exists_(abs_path))
        {
            return ESP_OK;
        }
    }

    return ESP_FAIL;
}

/**
 * @brief Internal helper for `poom_nfc_dump_is_mful_full`.
 *
 * @param[in] dump Parameter passed to the function.
 * @return bool
 */
static bool poom_nfc_dump_is_mful_full_(const poom_nfc_dump_t *dump)
{
    if(dump == NULL)
    {
        return false;
    }

    if(!dump->read_ok || (dump->read_mode != POOM_NFC_DUMP_READ_FULL))
    {
        return false;
    }

    if((dump->page_size != POOM_NFC_DUMP_PAGE_SIZE) || (dump->pages_read == 0U))
    {
        return false;
    }

    if(dump->pages_read > POOM_NFC_DUMP_MAX_PAGES)
    {
        return false;
    }

    if((dump->id.type != 0U) && (dump->id.type != 10U))
    {
        return false;
    }

    return true;
}

/**
 * @brief Internal helper for `poom_nfc_dump_mful_type`.
 *
 * @param[in] dump Parameter passed to the function.
 * @return const char *
 */
static const char *poom_nfc_dump_mful_type_(const poom_nfc_dump_t *dump)
{
    if(dump == NULL)
    {
        return "Mifare Ultralight";
    }

    const poom_nfc_t2t_product_t p = poom_nfc_dump_guess_t2t_product(dump);
    if(p != POOM_NFC_T2T_PRODUCT_UNKNOWN)
    {
        return poom_nfc_t2t_product_to_str(p);
    }

    return "Mifare Ultralight";
}

/**
 * @brief Saves internal data used by this module.
 *
 * @param[in] dump Parameter passed to the function.
 * @param[in] out_rel_path Parameter passed to the function.
 * @param[in] out_rel_path_len Parameter passed to the function.
 * @return esp_err_t
 */
static esp_err_t poom_nfc_dump_save_mful_flipper_to_sd_(const poom_nfc_dump_t *dump,
                                                       char *out_rel_path,
                                                       size_t out_rel_path_len)
{
    esp_err_t err;
    char rel_path_local[128];
    char abs_path[192];
    FILE *f = NULL;

    if((dump == NULL) || !poom_nfc_dump_is_mful_full_(dump))
    {
        return ESP_ERR_INVALID_ARG;
    }

    if(sd_card_is_not_mounted())
    {
        sd_card_begin();
        err = sd_card_mount();
        if(err != ESP_OK)
        {
            return err;
        }
    }

    err = sd_card_create_dir(POOM_NFC_DUMP_DIR);
    if(err != ESP_OK)
    {
        return err;
    }

    err = poom_nfc_dump_build_unique_rel_path_(dump, rel_path_local, sizeof(rel_path_local));
    if(err != ESP_OK)
    {
        return err;
    }

    if((out_rel_path != NULL) && (out_rel_path_len > 0U))
    {
        (void)snprintf(out_rel_path, out_rel_path_len, "%s", rel_path_local);
    }

    err = poom_nfc_dump_build_abs_path_(rel_path_local, abs_path, sizeof(abs_path));
    if(err != ESP_OK)
    {
        return err;
    }

    f = fopen(abs_path, "w");
    if(f == NULL)
    {
        return ESP_ERR_FILE_OPEN_FAILED;
    }

    (void)fprintf(f, "Filetype: Flipper NFC device\n");
    (void)fprintf(f, "Version: 2\n");
    (void)fprintf(f, "# Nfc device type can be UID, Mifare Ultralight, Bank card\n");
    (void)fprintf(f, "Device type: %s\n", poom_nfc_dump_mful_type_(dump));
    (void)fprintf(f, "# UID, ATQA and SAK are common for all formats\n");
    (void)fprintf(f, "UID: ");
    poom_nfc_dump_fprint_hex_bytes_(f, dump->id.uid, dump->id.uid_len);
    (void)fprintf(f, "\n");

    if((dump->id.flags & POOM_NFC_CARD_FLAG_ATQA_SET) != 0U)
    {
        (void)fprintf(f, "ATQA: %02X %02X\n", (unsigned)dump->id.atqa[0], (unsigned)dump->id.atqa[1]);
    }
    else
    {
        (void)fprintf(f, "ATQA: 44 00\n");
    }
    if((dump->id.flags & POOM_NFC_CARD_FLAG_SAK_SET) != 0U)
    {
        (void)fprintf(f, "SAK: %02X\n", (unsigned)dump->id.sak);
    }
    else
    {
        (void)fprintf(f, "SAK: 00\n");
    }

    (void)fprintf(f, "# Mifare Ultralight specific data\n");

    (void)fprintf(f, "Signature: ");
    if(dump->has_signature)
    {
        poom_nfc_dump_fprint_hex_bytes_(f, dump->signature, sizeof(dump->signature));
    }
    else
    {
        for(size_t i = 0U; i < 32U; i++)
        {
            (void)fprintf(f, "%s00", (i == 0U) ? "" : " ");
        }
    }
    (void)fprintf(f, "\n");

    (void)fprintf(f, "Mifare version: ");
    if(dump->has_version_bytes)
    {
        poom_nfc_dump_fprint_hex_bytes_(f, dump->version_bytes, sizeof(dump->version_bytes));
    }
    else
    {
        const uint8_t *v = NULL;
        uint8_t tmp[8] = {0};

        if(dump->pages_total == 45U)
        {
            static const uint8_t v213[8] = {0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x0F, 0x03};
            v = v213;
        }
        else if(dump->pages_total == 135U)
        {
            static const uint8_t v215[8] = {0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x11, 0x03};
            v = v215;
        }
        else if(dump->pages_total == 231U)
        {
            static const uint8_t v216[8] = {0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x13, 0x03};
            v = v216;
        }
        else
        {
            static const uint8_t v215[8] = {0x00, 0x04, 0x04, 0x02, 0x01, 0x00, 0x11, 0x03};
            v = v215;
        }

        (void)memcpy(tmp, v, sizeof(tmp));
        poom_nfc_dump_fprint_hex_bytes_(f, tmp, sizeof(tmp));
    }
    (void)fprintf(f, "\n");

    (void)fprintf(f, "Counter 0: 0\n");
    (void)fprintf(f, "Tearing 0: 00\n");
    (void)fprintf(f, "Counter 1: 0\n");
    (void)fprintf(f, "Tearing 1: 00\n");
    (void)fprintf(f, "Counter 2: 0\n");
    (void)fprintf(f, "Tearing 2: 00\n");
    (void)fprintf(f, "Pages total: %u\n", (unsigned)dump->pages_total);
    for(uint16_t page = 0U; page < dump->pages_read; page++)
    {
        (void)fprintf(f, "Page %u: ", (unsigned)page);
        poom_nfc_dump_fprint_hex_bytes_(f, dump->pages[page], POOM_NFC_DUMP_PAGE_SIZE);
        (void)fprintf(f, "\n");
    }

    (void)fclose(f);
    return ESP_OK;
}

esp_err_t poom_nfc_dump_save_mful_bin_to_sd(const poom_nfc_dump_t *dump,
                                           char *out_rel_path,
                                           size_t out_rel_path_len)
{
    if(dump == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    if(!poom_nfc_dump_is_mful_full_(dump))
    {
        return ESP_ERR_INVALID_STATE;
    }

    return poom_nfc_dump_save_mful_flipper_to_sd_(dump, out_rel_path, out_rel_path_len);
}

esp_err_t poom_nfc_dump_save_to_sd(const poom_nfc_dump_t *dump, char *out_rel_path, size_t out_rel_path_len)
{
    esp_err_t err;
    char rel_path_local[128];
    char abs_path[192];
    FILE *f = NULL;

    if(dump == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    if(sd_card_is_not_mounted())
    {
        sd_card_begin();
        err = sd_card_mount();
        if(err != ESP_OK)
        {
            return err;
        }
    }

    err = sd_card_create_dir(POOM_NFC_DUMP_DIR);
    if(err != ESP_OK)
    {
        return err;
    }

    err = poom_nfc_dump_build_unique_rel_path_(dump, rel_path_local, sizeof(rel_path_local));
    if(err != ESP_OK)
    {
        return err;
    }

    if((out_rel_path != NULL) && (out_rel_path_len > 0U))
    {
        (void)snprintf(out_rel_path, out_rel_path_len, "%s", rel_path_local);
    }

    err = poom_nfc_dump_build_abs_path_(rel_path_local, abs_path, sizeof(abs_path));
    if(err != ESP_OK)
    {
        return err;
    }

    f = fopen(abs_path, "w");
    if(f == NULL)
    {
        (void)errno;
        return ESP_ERR_FILE_OPEN_FAILED;
    }

    (void)fprintf(f, "Filetype: POOM NFC device\n");
    (void)fprintf(f, "Version: %u\n\n", (unsigned)POOM_NFC_DUMP_FORMAT_VERSION);

    (void)fprintf(f, "# Capture metadata\n");
    (void)fprintf(f, "Reader: ST25R3916\n");
    (void)fprintf(f, "Read mode: %s\n", (dump->read_mode == POOM_NFC_DUMP_READ_FULL) ? "Full dump" : "ID only");
    (void)fprintf(f, "Read status: %s\n\n", dump->read_ok ? "OK" : "FAIL");

    (void)fprintf(f, "# Tag identification\n");
    (void)fprintf(f, "Protocol: %s\n", poom_nfc_dump_protocol_str_(dump->id.type));
    (void)fprintf(f, "Device type: %s\n", poom_nfc_dump_device_type_guess_(dump));
    poom_nfc_dump_fprint_uid_line_(f, &dump->id);

    if((dump->id.flags & POOM_NFC_CARD_FLAG_ATQA_SET) != 0U)
    {
        (void)fprintf(f, "ATQA: %02X %02X\n", (unsigned)dump->id.atqa[0], (unsigned)dump->id.atqa[1]);
    }
    if((dump->id.flags & POOM_NFC_CARD_FLAG_SAK_SET) != 0U)
    {
        (void)fprintf(f, "SAK: %02X\n", (unsigned)dump->id.sak);
    }
    (void)fprintf(f, "\n");

    (void)fprintf(f, "# Technology-specific information\n");
    (void)fprintf(f, "Data format version: %u\n", (unsigned)POOM_NFC_DUMP_FORMAT_VERSION);
    const char *manufacturer = "Unknown";
    if(poom_nfc_card_id_is_valid(&dump->id) && (dump->id.uid_len > 0U))
    {
        manufacturer = nfc_ident_nfca_manufacturer(dump->id.uid[0]);
    }
    (void)fprintf(f, "Manufacturer: %s\n", manufacturer ? manufacturer : "Unknown");
    (void)fprintf(f, "Product subtype: %s\n", poom_nfc_dump_device_type_guess_(dump));

    if(dump->has_signature)
    {
        (void)fprintf(f, "Signature: ");
        poom_nfc_dump_fprint_hex_bytes_(f, dump->signature, sizeof(dump->signature));
        (void)fprintf(f, "\n");
    }
    else
    {
        (void)fprintf(f, "Signature: N/A\n");
    }

    if(dump->has_version_bytes)
    {
        (void)fprintf(f, "Version bytes: ");
        poom_nfc_dump_fprint_hex_bytes_(f, dump->version_bytes, sizeof(dump->version_bytes));
        (void)fprintf(f, "\n");
    }
    else
    {
        (void)fprintf(f, "Version bytes: N/A\n");
    }
    (void)fprintf(f, "\n");

    (void)fprintf(f, "# Counters and tearing status\n");
    (void)fprintf(f, "Counters: N/A\n\n");

    (void)fprintf(f, "# Memory layout\n");
    (void)fprintf(f, "Page size: %u\n", (unsigned)dump->page_size);
    (void)fprintf(f, "Pages total: %u\n", (unsigned)dump->pages_total);
    (void)fprintf(f, "Pages read: %u\n", (unsigned)dump->pages_read);
    (void)fprintf(f, "User memory start page: %u\n", (unsigned)dump->user_mem_start_page);
    (void)fprintf(f, "User memory end page: %u\n\n", (unsigned)dump->user_mem_end_page);

    (void)fprintf(f, "# Security / access\n");
    (void)fprintf(f, "Authentication supported: %s\n", (dump->read_mode == POOM_NFC_DUMP_READ_FULL) ? "Yes" : "Unknown");
    (void)fprintf(f, "Authentication required: Unknown\n");
    (void)fprintf(f, "Password present: Unknown\n");
    (void)fprintf(f, "PACK present: Unknown\n");
    (void)fprintf(f, "Failed authentication attempts: Unknown\n");
    (void)fprintf(f, "Lock bytes page: %u\n", (unsigned)dump->lock_bytes_page);
    (void)fprintf(f, "Dynamic lock bytes page: %u\n", (unsigned)dump->dynamic_lock_bytes_page);
    (void)fprintf(f, "Config start page: %u\n\n", (unsigned)dump->config_start_page);

    (void)fprintf(f, "# Raw memory dump\n");
    if(dump->read_mode == POOM_NFC_DUMP_READ_FULL)
    {
        for(uint16_t page = 0U; page < dump->pages_read; page++)
        {
            (void)fprintf(f, "Page %u: ", (unsigned)page);
            poom_nfc_dump_fprint_hex_bytes_(f, dump->pages[page], POOM_NFC_DUMP_PAGE_SIZE);
            (void)fprintf(f, "\n");
        }
    }
    else
    {
        (void)fprintf(f, "N/A\n");
    }

    (void)fprintf(f, "\n# Notes\n");
    (void)fprintf(f, "Comment: Dump captured with ST25R reader and exported by POOM firmware\n");

    (void)fclose(f);

    return ESP_OK;
}

esp_err_t poom_nfc_dump_load_card_id_from_sd(const char *rel_path, poom_nfc_card_id_t *out_id)
{
    esp_err_t err;
    char abs_path[192];
    FILE *f = NULL;
    char line[160];

    bool uid_len_set = false;
    uint8_t uid_len = 0U;
    uint8_t uid[POOM_NFC_CARD_UID_MAX];
    size_t uid_parsed = 0U;
    bool uid_set = false;

    bool atqa_set = false;
    uint8_t atqa1 = 0U;
    uint8_t atqa0 = 0U;

    bool sak_set = false;
    uint8_t sak = 0U;

    if((rel_path == NULL) || (out_id == NULL))
    {
        return ESP_ERR_INVALID_ARG;
    }

    (void)memset(out_id, 0, sizeof(*out_id));

    if(sd_card_is_not_mounted())
    {
        sd_card_begin();
        err = sd_card_mount();
        if(err != ESP_OK)
        {
            return err;
        }
    }

    err = poom_nfc_dump_build_abs_path_(rel_path, abs_path, sizeof(abs_path));
    if(err != ESP_OK)
    {
        return err;
    }

    f = fopen(abs_path, "r");
    if(f == NULL)
    {
        (void)errno;
        return ESP_ERR_FILE_OPEN_FAILED;
    }

    while(fgets(line, sizeof(line), f) != NULL)
    {
        if(sscanf(line, "UID length: %hhu", &uid_len) == 1)
        {
            uid_len_set = true;
            continue;
        }

        if(strncmp(line, "UID:", 4) == 0)
        {
            const char *p = &line[4];
            if(!poom_nfc_dump_parse_hex_bytes_(p, uid, sizeof(uid), &uid_parsed))
            {
                continue;
            }
            uid_set = true;
            continue;
        }

        if(sscanf(line, "ATQA: %hhx %hhx", &atqa1, &atqa0) == 2)
        {
            atqa_set = true;
            continue;
        }

        {
            unsigned int sak_u = 0U;
            if(sscanf(line, "SAK: %x", &sak_u) == 1)
            {
                sak = (uint8_t)(sak_u & 0xFFU);
                sak_set = true;
                continue;
            }
        }
    }

    (void)fclose(f);

    if(!uid_set)
    {
        return ESP_FAIL;
    }

    if(uid_len_set && (uid_parsed != (size_t)uid_len))
    {
        return ESP_FAIL;
    }

    if((uid_parsed == 0U) || (uid_parsed > POOM_NFC_CARD_UID_MAX))
    {
        return ESP_FAIL;
    }

    out_id->type = 0U; /* RFAL_NFC_LISTEN_TYPE_NFCA */
    out_id->uid_len = (uint8_t)uid_parsed;
    (void)memcpy(out_id->uid, uid, uid_parsed);

    if(atqa_set)
    {
        out_id->atqa[1] = atqa1;
        out_id->atqa[0] = atqa0;
        out_id->flags |= POOM_NFC_CARD_FLAG_ATQA_SET;
    }

    if(sak_set)
    {
        out_id->sak = sak;
        out_id->flags |= POOM_NFC_CARD_FLAG_SAK_SET;
    }

    return poom_nfc_card_id_is_valid(out_id) ? ESP_OK : ESP_FAIL;
}
