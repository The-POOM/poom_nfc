// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 THE POOM

#include "poom_nfc_controller.h"

#include <string.h>

#include "poom_nfc_core.h"
#include "poom_nfc_emulator.h"
#include "poom_nfc_iso14443_4.h"
#include "poom_nfc_dump.h"
#include "poom_nfc_reader.h"

#include "rfal_nfc.h"

#include "poom_nfc_cards.h"

static bool s_started = false;
static poom_nfc_ctrl_tech_t s_tech = POOM_NFC_CTRL_TECH_ALL;

/**
 * @brief Internal helper for `map_to_reader_tech`.
 *
 * @param[in] tech Parameter passed to the function.
 * @return poom_nfc_reader_tech_t
 */
static poom_nfc_reader_tech_t map_to_reader_tech(poom_nfc_ctrl_tech_t tech)
{
    switch (tech) {
        case POOM_NFC_CTRL_TECH_A:      return POOM_NFC_READER_TECH_A;
        case POOM_NFC_CTRL_TECH_B:      return POOM_NFC_READER_TECH_B;
        case POOM_NFC_CTRL_TECH_F:      return POOM_NFC_READER_TECH_F;
        case POOM_NFC_CTRL_TECH_V:      return POOM_NFC_READER_TECH_V;
        case POOM_NFC_CTRL_TECH_ST25TB: return POOM_NFC_READER_TECH_ST25TB;
        case POOM_NFC_CTRL_TECH_ALL:
        default:                        return POOM_NFC_READER_TECH_ALL;
    }
}

bool poom_nfc_controller_start(void)
{
    if (!s_started) {
        if (!poom_nfc_core_init()) {
            return false;
        }
        poom_nfc_emulator_init();
        s_started = true;
    }

    poom_nfc_reader_set_technology(map_to_reader_tech(s_tech));
    return true;
}

bool poom_nfc_controller_scan_once(uint32_t timeout_ms)
{
    if (!poom_nfc_controller_start()) {
        return false;
    }
    return poom_nfc_core_read_once(timeout_ms);
}


/**
 * @brief Internal helper for `poom_nfc_controller_extract_uid`.
 *
 * @param[in] dev Parameter passed to the function.
 * @param[in] uid_out Parameter passed to the function.
 * @param[in] uid_len_out Parameter passed to the function.
 * @return bool
 */
static bool poom_nfc_controller_extract_uid_(const rfalNfcDevice* dev, const uint8_t** uid_out, uint8_t* uid_len_out)
{
    if ((dev == NULL) || (uid_out == NULL) || (uid_len_out == NULL))
    {
        return false;
    }

    *uid_out = NULL;
    *uid_len_out = 0U;

    if (dev->type == RFAL_NFC_LISTEN_TYPE_NFCA)
    {
        const uint8_t* uid = dev->dev.nfca.nfcId1;
        uint8_t uid_len = dev->dev.nfca.nfcId1Len;

        if ((uid_len == 0U) && (dev->nfcidLen > 0U))
        {
            uid = dev->nfcid;
            uid_len = dev->nfcidLen;
        }

        *uid_out = uid;
        *uid_len_out = uid_len;
        return (uid_len > 0U);
    }

    if (dev->nfcidLen > 0U)
    {
        *uid_out = dev->nfcid;
        *uid_len_out = dev->nfcidLen;
        return true;
    }

    return false;
}

/**
 * @brief Internal helper for `poom_nfc_controller_extract_nfca_params`.
 *
 * @param[in] dev Parameter passed to the function.
 * @param[in] out_id Parameter passed to the function.
 * @return void
 */
static void poom_nfc_controller_extract_nfca_params_(const rfalNfcDevice* dev, poom_nfc_card_id_t* out_id)
{
    if ((dev == NULL) || (out_id == NULL))
    {
        return;
    }

    if (dev->type != RFAL_NFC_LISTEN_TYPE_NFCA)
    {
        return;
    }

    out_id->atqa[0] = dev->dev.nfca.sensRes.anticollisionInfo;
    out_id->atqa[1] = dev->dev.nfca.sensRes.platformInfo;
    out_id->flags |= POOM_NFC_CARD_FLAG_ATQA_SET;

    out_id->sak = dev->dev.nfca.selRes.sak;
    out_id->flags |= POOM_NFC_CARD_FLAG_SAK_SET;
}

bool poom_nfc_controller_scan_found_cards(uint32_t timeout_ms,
                                         poom_nfc_card_id_t* out_cards,
                                         size_t max_cards,
                                         size_t* out_count)
{
    rfalNfcDevice* dev_list = NULL;
    uint8_t dev_cnt = 0U;
    size_t out_cnt = 0U;

    if (out_count != NULL)
    {
        *out_count = 0U;
    }

    if ((out_cards == NULL) || (max_cards == 0U))
    {
        return false;
    }

    if (!poom_nfc_controller_start())
    {
        return false;
    }

    rfalNfcDevice* active = NULL;
    (void)poom_nfc_reader_scan_once(&active, timeout_ms);

    rfalNfcGetDevicesFound(&dev_list, &dev_cnt);

    for (uint8_t i = 0U; i < dev_cnt; i++)
    {
        const rfalNfcDevice* d = &dev_list[i];
        const uint8_t* uid = NULL;
        uint8_t uid_len = 0U;

        if (!poom_nfc_controller_extract_uid_(d, &uid, &uid_len))
        {
            continue;
        }

        if (uid_len > POOM_NFC_CARD_UID_MAX)
        {
            continue;
        }

        poom_nfc_card_id_t id;
        (void)memset(&id, 0, sizeof(id));
        id.type = d->type;
        id.uid_len = uid_len;
        (void)memcpy(id.uid, uid, uid_len);
        poom_nfc_controller_extract_nfca_params_(d, &id);

        bool dup = false;
        for (size_t j = 0U; j < out_cnt; j++)
        {
            if (poom_nfc_card_id_equal(&out_cards[j], &id))
            {
                dup = true;
                break;
            }
        }
        if (dup)
        {
            continue;
        }

        if (out_cnt >= max_cards)
        {
            break;
        }

        out_cards[out_cnt] = id;
        out_cnt++;
    }

    rfalNfcDeactivate(RFAL_NFC_DEACTIVATE_IDLE);
    rfalFieldOff();

    if (out_count != NULL)
    {
        *out_count = out_cnt;
    }

    return true;
}

bool poom_nfc_controller_capture_dump(uint32_t timeout_ms, poom_nfc_dump_t *out_dump)
{
    rfalNfcDevice *active = NULL;

    if(out_dump == NULL)
    {
        return false;
    }

    if(!poom_nfc_controller_start())
    {
        return false;
    }

    if(!poom_nfc_reader_scan_once(&active, timeout_ms) || (active == NULL))
    {
        rfalNfcDeactivate(RFAL_NFC_DEACTIVATE_IDLE);
        rfalFieldOff();
        return false;
    }

    (void)memset(out_dump, 0, sizeof(*out_dump));
    const bool ok = poom_nfc_reader_create_dump(active, out_dump);

    rfalNfcDeactivate(RFAL_NFC_DEACTIVATE_IDLE);
    rfalFieldOff();

    return ok;
}

esp_err_t poom_nfc_controller_dump_to_sd(uint32_t timeout_ms, char *out_rel_path, size_t out_rel_path_len)
{
    rfalNfcDevice *active = NULL;
    poom_nfc_dump_t dump;

    if(!poom_nfc_controller_start())
    {
        return ESP_FAIL;
    }

    if(!poom_nfc_reader_scan_once(&active, timeout_ms) || (active == NULL))
    {
        rfalNfcDeactivate(RFAL_NFC_DEACTIVATE_IDLE);
        rfalFieldOff();
        return ESP_ERR_TIMEOUT;
    }

    (void)memset(&dump, 0, sizeof(dump));
    if(!poom_nfc_reader_create_dump(active, &dump))
    {
        rfalNfcDeactivate(RFAL_NFC_DEACTIVATE_IDLE);
        rfalFieldOff();
        return ESP_FAIL;
    }

    esp_err_t err = poom_nfc_dump_save_to_sd(&dump, out_rel_path, out_rel_path_len);

    rfalNfcDeactivate(RFAL_NFC_DEACTIVATE_IDLE);
    rfalFieldOff();

    return err;
}

esp_err_t poom_nfc_controller_mful_bin_to_sd(uint32_t timeout_ms, char *out_rel_path, size_t out_rel_path_len)
{
    rfalNfcDevice *active = NULL;
    poom_nfc_dump_t dump;

    if(!poom_nfc_controller_start())
    {
        return ESP_FAIL;
    }

    if(!poom_nfc_reader_scan_once(&active, timeout_ms) || (active == NULL))
    {
        rfalNfcDeactivate(RFAL_NFC_DEACTIVATE_IDLE);
        rfalFieldOff();
        return ESP_ERR_TIMEOUT;
    }

    (void)memset(&dump, 0, sizeof(dump));
    if(!poom_nfc_reader_create_dump(active, &dump))
    {
        rfalNfcDeactivate(RFAL_NFC_DEACTIVATE_IDLE);
        rfalFieldOff();
        return ESP_FAIL;
    }

    esp_err_t err = poom_nfc_dump_save_mful_bin_to_sd(&dump, out_rel_path, out_rel_path_len);

    rfalNfcDeactivate(RFAL_NFC_DEACTIVATE_IDLE);
    rfalFieldOff();

    return err;
}

bool poom_nfc_controller_connect(void)
{
    if (!poom_nfc_controller_start()) {
        return false;
    }
    return poom_reader_connect_card();
}

bool poom_nfc_controller_send_raw_hex(const char *hex_ascii)
{
    if (!poom_nfc_controller_start()) {
        return false;
    }
    return poom_reader_send_raw_hex(hex_ascii);
}

bool poom_nfc_controller_tune_auto(poom_nfc_tuning_result_t *out)
{
    if (!poom_nfc_controller_start()) {
        return false;
    }
    return poom_nfc_tuning_auto(out);
}

bool poom_nfc_controller_tune_set(uint8_t aat_a, uint8_t aat_b, poom_nfc_tuning_result_t *out)
{
    if (!poom_nfc_controller_start()) {
        return false;
    }
    return poom_nfc_tuning_set(aat_a, aat_b, out);
}

bool poom_nfc_controller_tune_get(poom_nfc_tuning_result_t *out)
{
    if (!poom_nfc_controller_start()) {
        return false;
    }
    return poom_nfc_tuning_get(out);
}

void poom_nfc_controller_stop(void)
{
    if (!s_started) {
        return;
    }

    poom_nfc_emulator_stop();
    poom_nfc_core_deinit();
    s_started = false;
}

void poom_nfc_controller_set_technology(poom_nfc_ctrl_tech_t tech)
{
    s_tech = tech;
    if (s_started) {
        poom_nfc_reader_set_technology(map_to_reader_tech(s_tech));
    }
}

poom_nfc_ctrl_tech_t poom_nfc_controller_get_technology(void)
{
    return s_tech;
}

const char *poom_nfc_controller_technology_to_str(poom_nfc_ctrl_tech_t tech)
{
    switch (tech) {
        case POOM_NFC_CTRL_TECH_A:      return "NFC-A";
        case POOM_NFC_CTRL_TECH_B:      return "NFC-B";
        case POOM_NFC_CTRL_TECH_F:      return "NFC-F";
        case POOM_NFC_CTRL_TECH_V:      return "NFC-V";
        case POOM_NFC_CTRL_TECH_ST25TB: return "ST25TB";
        case POOM_NFC_CTRL_TECH_ALL:
        default:                        return "NFC-ALL";
    }
}
