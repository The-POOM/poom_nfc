/*
 * poom_nfc_reader.c
 *
 * Public entry points:
 *   - poom_nfc_reader_scan_once()
 *   - poom_nfc_reader_active()
 *
 * Keeps multi-technology support: A/B/F/V/ST25TB.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

/* FreeRTOS */
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

/* NFC-A card identification helpers */
#include "poom_nfc_reader.h"
#include "poom_nfc_card_ident.h"

/* =========================
 * Logging helpers
 * ========================= */
//#define CONSOLE
//#define DEBUG

#ifdef DEBUG
    #define printf_log(fmt, ...) \
      printf("Line: [%d], Function: [%s]: " fmt "\n", __LINE__, __func__, ##__VA_ARGS__)

    #define PRINTF_HEX(buffer, len) do { \
        printf("> "); \
        for (size_t i = 0; i < (size_t)(len); i++) { \
            printf("%02x ", ((const uint8_t *)(buffer))[i]); \
            if ((i + 1) % 16 == 0) printf("\n"); \
        } \
        printf("\n"); \
    } while(0)
#else
    #define printf_log(fmt, ...)
    #define PRINTF_HEX(buffer, len) do {} while(0)
#endif

/* =========================
 * Defines / helpers
 * ========================= */
#ifndef ERR_NONE
  #define ERR_NONE  (0U)
#endif
#ifndef ERR_BUSY
  #define ERR_BUSY  (2U)
#endif

#define DEMO_DEV_LIMIT  4
#define DEMO_NFCV_BLOCK_LEN 4

/* Reverse bytes helper for NFC-V UIDs. */
#define REVERSE_BYTES(pData, nDataSize) \
  {unsigned char swap, *lo = ((unsigned char *)(pData)), *hi = ((unsigned char *)(pData)) + (nDataSize) - 1; \
  while (lo < hi) { swap = *lo; *lo++ = *hi; *hi-- = swap; }}

/* =========================
 * Global discovery parameters
 * ========================= */
static rfalNfcDiscoverParam s_discParam;
static bool s_inited = false;
static poom_nfc_reader_tech_t s_selected_tech = POOM_NFC_READER_TECH_ALL;
/* =========================
 * Forward declarations
 * ========================= */
static void print_found_devices(const rfalNfcDevice *active_dev);
static uint8_t pick_preferred_device(void);
static uint32_t build_tech_mask(poom_nfc_reader_tech_t tech);
static void apply_tech_filter(void);

static bool nfc_link_transceive(
    const uint8_t *tx, size_t tx_len,
    uint8_t *rx, size_t rx_max,
    size_t *rx_len_out,
    void *user_ctx);

/**
 * @brief Internal helper for `poom_nfc_reader_is_nfca_type`.
 *
 * @param[in] type Parameter passed to the function.
 * @return bool
 */
static bool poom_nfc_reader_is_nfca_type_(uint8_t type)
{
    return (type == RFAL_NFC_LISTEN_TYPE_NFCA) || (type == RFAL_NFC_POLL_TYPE_NFCA);
}

/**
 * @brief Internal helper for `poom_nfc_reader_same_device`.
 *
 * @param[in] a Parameter passed to the function.
 * @param[in] b Parameter passed to the function.
 * @return bool
 */
static bool poom_nfc_reader_same_device_(const rfalNfcDevice *a, const rfalNfcDevice *b)
{
    if(a == b)
    {
        return true;
    }
    if((a == NULL) || (b == NULL) || (a->type != b->type))
    {
        return false;
    }

    if(poom_nfc_reader_is_nfca_type_(a->type) && poom_nfc_reader_is_nfca_type_(b->type))
    {
        if((a->dev.nfca.nfcId1Len == b->dev.nfca.nfcId1Len) &&
           (a->dev.nfca.nfcId1Len > 0U) &&
           (memcmp(a->dev.nfca.nfcId1, b->dev.nfca.nfcId1, a->dev.nfca.nfcId1Len) == 0) &&
           (a->dev.nfca.selRes.sak == b->dev.nfca.selRes.sak) &&
           (a->dev.nfca.sensRes.platformInfo == b->dev.nfca.sensRes.platformInfo) &&
           (a->dev.nfca.sensRes.anticollisionInfo == b->dev.nfca.sensRes.anticollisionInfo))
        {
            return true;
        }
    }

    if((a->nfcidLen == b->nfcidLen) && (a->nfcidLen > 0U) &&
       (a->nfcid != NULL) && (b->nfcid != NULL) &&
       (memcmp(a->nfcid, b->nfcid, a->nfcidLen) == 0))
    {
        return true;
    }

    return false;
}

/* Demo readers built on top of the same transport flow. */
static void demoAPDU(void);
static void demoNfcv(rfalNfcvListenDevice *nfcvDev);
static void demoNfcf(rfalNfcfListenDevice *nfcfDev);

/* RFAL blocking exchange */
ReturnCode demoTransceiveBlocking(uint8_t *txBuf, uint16_t txBufSize,
                                  uint8_t **rxData, uint16_t **rcvLen,
                                  uint32_t fwt);

/**
 * @brief Internal helper for `poom_nfc_reader_extract_card_id`.
 *
 * @param[in] dev Parameter passed to the function.
 * @param[in] out_id Parameter passed to the function.
 * @return bool
 */
static bool poom_nfc_reader_extract_card_id_(const rfalNfcDevice *dev, poom_nfc_card_id_t *out_id)
{
    const uint8_t *uid = NULL;
    uint8_t uid_len = 0U;

    if((dev == NULL) || (out_id == NULL))
    {
        return false;
    }

    (void)memset(out_id, 0, sizeof(*out_id));
    out_id->type = dev->type;

    if(poom_nfc_reader_is_nfca_type_(dev->type))
    {
        uid = dev->dev.nfca.nfcId1;
        uid_len = dev->dev.nfca.nfcId1Len;

        if((uid_len == 0U) && (dev->nfcidLen > 0U))
        {
            uid = dev->nfcid;
            uid_len = dev->nfcidLen;
        }

        out_id->atqa[0] = dev->dev.nfca.sensRes.anticollisionInfo;
        out_id->atqa[1] = dev->dev.nfca.sensRes.platformInfo;
        out_id->flags |= POOM_NFC_CARD_FLAG_ATQA_SET;

        out_id->sak = dev->dev.nfca.selRes.sak;
        out_id->flags |= POOM_NFC_CARD_FLAG_SAK_SET;
    }
    else if(dev->nfcidLen > 0U)
    {
        uid = dev->nfcid;
        uid_len = dev->nfcidLen;
    }

    if((uid == NULL) || (uid_len == 0U) || (uid_len > POOM_NFC_CARD_UID_MAX))
    {
        return false;
    }

    out_id->uid_len = uid_len;
    (void)memcpy(out_id->uid, uid, uid_len);
    return true;
}

/**
 * @brief Internal helper for `poom_nfc_reader_t2t_read_4pages`.
 *
 * @param[in] start_page Parameter passed to the function.
 * @param[in] out16 Parameter passed to the function.
 * @return bool
 */
static bool poom_nfc_reader_t2t_read_4pages_(uint8_t start_page, uint8_t out16[16])
{
    uint8_t cmd[2] = {0x30U, start_page};
    uint16_t rx_len = 0U;

    if(out16 == NULL)
    {
        return false;
    }

    if(rfalTransceiveBlockingTxRx(cmd,
                                  sizeof(cmd),
                                  out16,
                                  16U,
                                  &rx_len,
                                  RFAL_TXRX_FLAGS_DEFAULT,
                                  RFAL_FWT_NONE) == ERR_NONE)
    {
        if(rx_len >= 16U)
        {
            return true;
        }
    }

    {
        uint8_t rx[32];
        size_t rx_len_fallback = 0U;

        if(!nfc_link_transceive(cmd, sizeof(cmd), rx, sizeof(rx), &rx_len_fallback, NULL))
        {
            return false;
        }

        if(rx_len_fallback < 16U)
        {
            return false;
        }

        (void)memcpy(out16, rx, 16U);
    }

    return true;
}

/**
 * @brief Internal helper for `poom_nfc_reader_t2t_read_signature`.
 *
 * @param[in] out32 Parameter passed to the function.
 * @return bool
 */
static bool poom_nfc_reader_t2t_read_signature_(uint8_t out32[32])
{
    uint8_t cmd[2] = {0x3CU, 0x00U};
    uint8_t rx[64];
    size_t rx_len = 0U;

    if(out32 == NULL)
    {
        return false;
    }

    if(!nfc_link_transceive(cmd, sizeof(cmd), rx, sizeof(rx), &rx_len, NULL))
    {
        return false;
    }

    if(rx_len < 32U)
    {
        return false;
    }

    (void)memcpy(out32, rx, 32U);
    return true;
}

bool poom_nfc_reader_init(void)
{
    ReturnCode err;

    platformIrqST25R3916PinInitialize();
    err = rfalNfcInitialize();

    if(err != ERR_NONE) {
        printf_log("rfalNfcInitialize err=%d", err);
        s_inited = false;
        return false;
    }

    rfalNfcDefaultDiscParams(&s_discParam);
    s_discParam.devLimit      = DEMO_DEV_LIMIT;
    s_discParam.totalDuration = 1000U;

    apply_tech_filter();

    s_inited = true;
    return true;
}

void poom_nfc_reader_set_technology(poom_nfc_reader_tech_t tech)
{
    s_selected_tech = tech;
    if (s_inited) {
        apply_tech_filter();
    }
}

poom_nfc_reader_tech_t poom_nfc_reader_get_technology(void)
{
    return s_selected_tech;
}

const char *poom_nfc_reader_technology_to_str(poom_nfc_reader_tech_t tech)
{
    switch (tech) {
        case POOM_NFC_READER_TECH_A:      return "NFC-A";
        case POOM_NFC_READER_TECH_B:      return "NFC-B";
        case POOM_NFC_READER_TECH_F:      return "NFC-F";
        case POOM_NFC_READER_TECH_V:      return "NFC-V";
        case POOM_NFC_READER_TECH_ST25TB: return "ST25TB";
        case POOM_NFC_READER_TECH_ALL:
        default:                          return "NFC-ALL";
    }
}

bool poom_nfc_reader_create_dump(const rfalNfcDevice *dev, poom_nfc_dump_t *out_dump)
{
    poom_nfc_card_id_t id;

    if((dev == NULL) || (out_dump == NULL))
    {
        return false;
    }

    (void)memset(out_dump, 0, sizeof(*out_dump));
    out_dump->page_size = POOM_NFC_DUMP_PAGE_SIZE;
    out_dump->read_mode = POOM_NFC_DUMP_READ_ID_ONLY;
    out_dump->read_ok = false;

    if(!poom_nfc_reader_extract_card_id_(dev, &id))
    {
        return false;
    }
    out_dump->id = id;

    if(!poom_nfc_reader_is_nfca_type_(dev->type))
    {
        out_dump->read_ok = true;
        return true;
    }

    uint16_t atqa = ((uint16_t)id.atqa[1] << 8) | (uint16_t)id.atqa[0];
    uint8_t sak = id.sak;
    nfc_card_type_t detected = nfc_ident_detect_nfca(atqa, sak);

    if((detected != NFC_CARD_ULTRALIGHT_OR_NTAG) && (detected != NFC_CARD_NTAG424DNA))
    {
        out_dump->read_ok = true;
        return true;
    }

    out_dump->read_mode = POOM_NFC_DUMP_READ_FULL;

    uint16_t pages_total = 0U;
    uint16_t pages_read = 0U;

    uint8_t buf16[16];
    if(!poom_nfc_reader_t2t_read_4pages_(0U, buf16))
    {
        out_dump->pages_read = 0U;
        out_dump->pages_total = 0U;
        out_dump->read_ok = false;
        return true;
    }

    for(uint8_t i = 0U; i < 4U; i++)
    {
        (void)memcpy(out_dump->pages[i], &buf16[i * 4U], 4U);
    }
    pages_read = 4U;

    {
        nfc_get_version_info_t gv;
        if(nfc_ident_try_get_version(detected, nfc_link_transceive, nfc_link_transceive, NULL, &gv) &&
           (gv.kind == NFC_GV_T2T_UL_NTAG) && gv.u.t2t.valid)
        {
            out_dump->has_version_bytes = true;
            (void)memcpy(out_dump->version_bytes, gv.u.t2t.raw, sizeof(out_dump->version_bytes));
        }
    }

    if(poom_nfc_reader_t2t_read_signature_(out_dump->signature))
    {
        out_dump->has_signature = true;
    }

    const uint8_t *cc = out_dump->pages[3];
    if((cc[0] == 0xE1U) && (cc[2] != 0U))
    {
        const uint16_t user_pages = (uint16_t)cc[2] * 2U; /* 8-byte blocks => 2 pages per block */
        uint16_t user_end = (user_pages > 0U) ? (uint16_t)(4U + user_pages - 1U) : 0U;
        uint16_t total = (user_end > 0U) ? (uint16_t)(user_end + 6U) : 0U; /* NTAG21x layout: user_end + 6 pages */

        if(total > POOM_NFC_DUMP_MAX_PAGES)
        {
            total = POOM_NFC_DUMP_MAX_PAGES;
        }

        pages_total = total;
        if((pages_total > 0U) && (user_end >= pages_total))
        {
            user_end = (uint16_t)(pages_total - 1U);
        }

        out_dump->lock_bytes_page = 2U;
        out_dump->dynamic_lock_bytes_page = (pages_total >= 5U) ? (uint16_t)(pages_total - 5U) : 0U;
        out_dump->config_start_page = (pages_total >= 4U) ? (uint16_t)(pages_total - 4U) : 0U;
        out_dump->user_mem_start_page = 4U;
        out_dump->user_mem_end_page = user_end;
    }

    if(pages_total >= 4U)
    {
        for(uint16_t page = 4U; page < pages_total; page = (uint16_t)(page + 4U))
        {
            uint16_t start = page;
            if((start + 4U) > pages_total)
            {
                start = (uint16_t)(pages_total - 4U);
            }

            if(!poom_nfc_reader_t2t_read_4pages_((uint8_t)start, buf16))
            {
                break;
            }

            for(uint8_t i = 0U; i < 4U; i++)
            {
                const uint16_t idx = (uint16_t)(start + i);
                if(idx >= pages_total)
                {
                    break;
                }
                (void)memcpy(out_dump->pages[idx], &buf16[i * 4U], 4U);
            }

            if((uint16_t)(start + 4U) > pages_read)
            {
                pages_read = (uint16_t)(start + 4U);
            }
            if(pages_read >= pages_total)
            {
                pages_read = pages_total;
                break;
            }
        }

        out_dump->pages_total = pages_total;
        out_dump->pages_read = (pages_read > pages_total) ? pages_total : pages_read;
    }
    else
    {
        for(uint16_t page = 4U; (page + 3U) < POOM_NFC_DUMP_MAX_PAGES; page = (uint16_t)(page + 4U))
        {
            if(!poom_nfc_reader_t2t_read_4pages_((uint8_t)page, buf16))
            {
                break;
            }

            for(uint8_t i = 0U; i < 4U; i++)
            {
                (void)memcpy(out_dump->pages[page + i], &buf16[i * 4U], 4U);
            }

            pages_read = (uint16_t)(page + 4U);
        }

        out_dump->pages_read = pages_read;
        out_dump->pages_total = pages_read;

        if(pages_read >= 8U)
        {
            out_dump->lock_bytes_page = 2U;
            out_dump->dynamic_lock_bytes_page = (uint16_t)(pages_read - 5U);
            out_dump->config_start_page = (uint16_t)(pages_read - 4U);
            out_dump->user_mem_start_page = 4U;
            out_dump->user_mem_end_page = (uint16_t)(pages_read - 6U);
        }
    }

    out_dump->read_ok = (out_dump->pages_read > 0U);
    return true;
}

bool poom_nfc_reader_scan_once(rfalNfcDevice **activeDevOut, uint32_t timeout_ms)
{
    if(activeDevOut) *activeDevOut = NULL;

    if(!s_inited) {
        printf_log("poom_nfc_reader_scan_once: not initialized. Call poom_nfc_reader_init() first.");
        return false;
    }

    rfalNfcState st = rfalNfcGetState();
    if(st != RFAL_NFC_STATE_IDLE) {
        ReturnCode de = rfalNfcDeactivate(RFAL_NFC_DEACTIVATE_IDLE);
        if(de != ERR_NONE) {
            printf_log("rfalNfcDeactivate(IDLE) err=%d state=%d", de, st);
            return false;
        }
    }

    ReturnCode err = rfalNfcDiscover(&s_discParam);
    if(err != ERR_NONE) {
        printf_log("rfalNfcDiscover err=%d state=%d", err, rfalNfcGetState());
        return false;
    }

    uint32_t t0 = (uint32_t)(xTaskGetTickCount() * portTICK_PERIOD_MS);

    while(1)
    {
        rfalNfcWorker();

        if(rfalNfcIsDevActivated(rfalNfcGetState()))
        {
            rfalNfcDevice *active = NULL;

            rfalNfcGetActiveDevice(&active);

            if(active == NULL) {
                uint8_t idx = pick_preferred_device();
                if(rfalNfcSelect(idx) == ERR_NONE) {
                    vTaskDelay(pdMS_TO_TICKS(20));
                    rfalNfcWorker();
                    rfalNfcGetActiveDevice(&active);
                }
            }

            print_found_devices(active);

            if(activeDevOut) *activeDevOut = active;
            return (active != NULL);
        }

        uint32_t now = (uint32_t)(xTaskGetTickCount() * portTICK_PERIOD_MS);
        if((now - t0) >= timeout_ms) {
            rfalNfcDeactivate(RFAL_NFC_DEACTIVATE_DISCOVERY);
            return false;
        }

        vTaskDelay(pdMS_TO_TICKS(5));
    }
}

bool poom_nfc_reader_active(rfalNfcDevice *dev)
{
    if(!dev) return false;

    printf_log("Active type=%u rfInterface=%u nfcidLen=%u",
               dev->type, dev->rfInterface, dev->nfcidLen);

    if(dev->nfcidLen) {
        printf_log("UID/NFCID:");
        PRINTF_HEX(dev->nfcid, dev->nfcidLen);
    }

    switch(dev->type)
    {
        case RFAL_NFC_LISTEN_TYPE_NFCA:
        case RFAL_NFC_POLL_TYPE_NFCA:
        {
            uint16_t atqa = ((uint16_t)dev->dev.nfca.sensRes.platformInfo << 8) |
                            ((uint16_t)dev->dev.nfca.sensRes.anticollisionInfo);
            uint8_t sak = dev->dev.nfca.selRes.sak;

            printf_log("NFCA ATQA=0x%04X SAK=0x%02X", atqa, sak);

            if(dev->nfcidLen > 0) {
                printf_log("Manufacturer(hint): %s (UID0=0x%02X)",
                           nfc_ident_nfca_manufacturer(dev->nfcid[0]),
                           dev->nfcid[0]);
            }

            nfc_card_type_t ct = nfc_ident_detect_nfca(atqa, sak);
            printf_log("Detected: %s", nfc_ident_card_type_to_str(ct));

            nfc_get_version_info_t gv;
            if(nfc_ident_try_get_version(ct, nfc_link_transceive, nfc_link_transceive, NULL, &gv)) {
                printf_log("GET_VERSION: OK");
            } else {
                printf_log("GET_VERSION: not available/failed");
            }

            return true;
        }

        case RFAL_NFC_LISTEN_TYPE_NFCB:
        case RFAL_NFC_POLL_TYPE_NFCB:
        {
            printf_log("NFC-B");

#if RFAL_FEATURE_ISO_DEP_POLL
            if(rfalNfcbIsIsoDepSupported(&dev->dev.nfcb)) {
                printf_log("NFC-B ISO-DEP supported -> demoAPDU()");
                demoAPDU();
            } else {
                printf_log("NFC-B (no ISO-DEP)");
            }
#else
            printf_log("ISO-DEP not compiled");
#endif
            return true;
        }

        case RFAL_NFC_LISTEN_TYPE_NFCF:
        case RFAL_NFC_POLL_TYPE_NFCF:
        {
            printf_log("NFC-F");

#if RFAL_FEATURE_NFCF
            if(!rfalNfcfIsNfcDepSupported(&dev->dev.nfcf)) {
                demoNfcf(&dev->dev.nfcf);
            } else {
                printf_log("NFC-F NFC-DEP (P2P) detected (no P2P demo here)");
            }
#else
            printf_log("NFC-F not compiled");
#endif
            return true;
        }

        case RFAL_NFC_LISTEN_TYPE_NFCV:
        case RFAL_NFC_POLL_TYPE_NFCV:
        {
            printf_log("NFC-V");

#if RFAL_FEATURE_NFCV
            demoNfcv(&dev->dev.nfcv);
#else
            printf_log("NFC-V not compiled");
#endif
            return true;
        }

        case RFAL_NFC_LISTEN_TYPE_ST25TB:
        {
            printf_log("ST25TB (UID printed above)");
            return true;
        }

        default:
            printf_log("Unsupported/Other type=%u", dev->type);
            return false;
    }
}

/* =========================================================
 * Internal helpers
 * ========================================================= */

/**
 * @brief Returns the text representation for the current state.
 *
 * @param[in] rfIf Parameter passed to the function.
 * @return const char*
 */
static const char* rf_if_to_str(uint8_t rfIf)
{
    switch(rfIf) {
        case RFAL_NFC_INTERFACE_RF:     return "RF";
        case RFAL_NFC_INTERFACE_ISODEP: return "ISO-DEP";
        case RFAL_NFC_INTERFACE_NFCDEP: return "NFC-DEP";
        default: return "?";
    }
}

/**
 * @brief Returns the text representation for the current state.
 *
 * @param[in] t Parameter passed to the function.
 * @return const char*
 */
static const char* type_to_str(uint8_t t)
{
    switch(t) {
        case RFAL_NFC_LISTEN_TYPE_NFCA:   return "NFCA";
        case RFAL_NFC_LISTEN_TYPE_NFCB:   return "NFCB";
        case RFAL_NFC_LISTEN_TYPE_NFCF:   return "NFCF";
        case RFAL_NFC_LISTEN_TYPE_NFCV:   return "NFCV";
        case RFAL_NFC_LISTEN_TYPE_ST25TB: return "ST25TB";
        case RFAL_NFC_LISTEN_TYPE_AP2P:   return "AP2P";
        case RFAL_NFC_POLL_TYPE_NFCA:     return "NFCA";
        case RFAL_NFC_POLL_TYPE_NFCB:     return "NFCB";
        case RFAL_NFC_POLL_TYPE_NFCF:     return "NFCF";
        case RFAL_NFC_POLL_TYPE_NFCV:     return "NFCV";
        case RFAL_NFC_POLL_TYPE_AP2P:     return "AP2P";
        default: return "UNKNOWN";
    }
}

/**
 * @brief Internal helper for `print_uid_line`.
 *
 * @param[in] label Parameter passed to the function.
 * @param[in] uid Parameter passed to the function.
 * @param[in] uidLen Parameter passed to the function.
 * @return void
 */
static void print_uid_line(const char *label, const uint8_t *uid, uint8_t uidLen)
{
    printf(" %s:", label);
    if(uid && uidLen) {
        for(uint8_t i=0;i<uidLen;i++) printf("%02X", uid[i]);
        printf(" (%u bytes)", uidLen);
    } else {
        printf(" <not available>");
    }
}

/**
 * @brief Internal helper for `print_hex_compact`.
 *
 * @param[in] data Parameter passed to the function.
 * @param[in] len Parameter passed to the function.
 * @return void
 */
static void print_hex_compact_(const uint8_t *data, size_t len)
{
    if((data == NULL) || (len == 0U))
    {
        return;
    }

    for(size_t i = 0; i < len; i++)
    {
        printf("%02X", data[i]);
    }
}

/**
 * @brief Internal helper for `print_iso_dep_details`.
 *
 * @param[in] dev Parameter passed to the function.
 * @return void
 */
static void print_iso_dep_details_(const rfalNfcDevice *dev)
{
    if((dev == NULL) || (dev->rfInterface != RFAL_NFC_INTERFACE_ISODEP))
    {
        return;
    }

    printf("\n      ISO-DEP:");

    if(poom_nfc_reader_is_nfca_type_(dev->type))
    {
        const rfalIsoDepDevice *iso = &dev->proto.isoDep;
        const rfalIsoDepAts *ats = &iso->activation.A.Listener.ATS;
        uint8_t ats_len = iso->activation.A.Listener.ATSLen;
        uint8_t hb_len = 0U;

        printf(" ATS=");
        if(ats_len >= 2U)
        {
            uint8_t consumed = 2U;

            printf("%02X%02X", ats->TL, ats->T0);
            if((ats->T0 & RFAL_ISODEP_ATS_T0_TA_PRESENCE_MASK) != 0U)
            {
                printf("%02X", ats->TA);
                consumed++;
            }
            if((ats->T0 & RFAL_ISODEP_ATS_T0_TB_PRESENCE_MASK) != 0U)
            {
                printf("%02X", ats->TB);
                consumed++;
            }
            if((ats->T0 & RFAL_ISODEP_ATS_T0_TC_PRESENCE_MASK) != 0U)
            {
                printf("%02X", ats->TC);
                consumed++;
            }
            if(ats_len > consumed)
            {
                hb_len = (uint8_t)(ats_len - consumed);
                for(uint8_t i = 0; i < hb_len; i++)
                {
                    printf("%02X", ats->HB[i]);
                }
            }
        }
        else
        {
            printf("<n/a>");
        }

        printf(" || FSC=%u FWI=%u SFGI=%lu DID=%u",
               (unsigned)iso->info.FSx,
               (unsigned)iso->info.FWI,
               (unsigned long)iso->info.SFGI,
               (unsigned)iso->info.DID);

        if(hb_len > 0U)
        {
            printf(" || HB=");
            print_hex_compact_(ats->HB, hb_len);
        }
    }
    else
    {
        printf(" FSC=%u FWI=%u SFGI=%lu DID=%u",
               (unsigned)dev->proto.isoDep.info.FSx,
               (unsigned)dev->proto.isoDep.info.FWI,
               (unsigned long)dev->proto.isoDep.info.SFGI,
               (unsigned)dev->proto.isoDep.info.DID);
    }
}

/**
 * @brief Internal helper for `print_get_version_details`.
 *
 * @param[in] detected_type Parameter passed to the function.
 * @return void
 */
static void print_get_version_details_(nfc_card_type_t detected_type)
{
    nfc_get_version_info_t gv;

    if(!nfc_ident_try_get_version(detected_type, nfc_link_transceive, nfc_link_transceive, NULL, &gv))
    {
        return;
    }

    printf("\n      GET_VERSION:");

    if((gv.kind == NFC_GV_T2T_UL_NTAG) && gv.u.t2t.valid)
    {
        printf(" raw=");
        print_hex_compact_(gv.u.t2t.raw, sizeof(gv.u.t2t.raw));
        printf(" || vendor=0x%02X prod=0x%02X/%02X ver=%u.%u size=0x%02X proto=0x%02X",
               gv.u.t2t.vendor_id,
               gv.u.t2t.product_type,
               gv.u.t2t.product_subtype,
               (unsigned)gv.u.t2t.major_version,
               (unsigned)gv.u.t2t.minor_version,
               gv.u.t2t.storage_size,
               gv.u.t2t.protocol_type);
        return;
    }

    if((gv.kind == NFC_GV_DESFIRE_APDU) && gv.u.df.valid)
    {
        size_t preview_len = gv.u.df.raw_len;
        if(preview_len > 16U)
        {
            preview_len = 16U;
        }

        printf(" sw=%02X%02X raw=", gv.u.df.sw1, gv.u.df.sw2);
        print_hex_compact_(gv.u.df.raw, preview_len);
        if(gv.u.df.raw_len > preview_len)
        {
            printf("...");
        }
        printf(" || len=%u", (unsigned)gv.u.df.raw_len);
    }
}

/**
 * @brief Internal helper for `print_found_devices`.
 *
 * @param[in] active_dev Parameter passed to the function.
 * @return void
 */
static void print_found_devices(const rfalNfcDevice *active_dev)
{
    rfalNfcDevice *devList = NULL;
    uint8_t devCnt = 0;

    rfalNfcGetDevicesFound(&devList, &devCnt);


    for(uint8_t i=0; i<devCnt; i++)
    {
        rfalNfcDevice *d = &devList[i];

        printf("  [%u] %s  rfIf=%s ",
               i, type_to_str(d->type), rf_if_to_str(d->rfInterface));

        if(poom_nfc_reader_is_nfca_type_(d->type))
        {
            uint16_t atqa = ((uint16_t)d->dev.nfca.sensRes.platformInfo << 8) |
                            ((uint16_t)d->dev.nfca.sensRes.anticollisionInfo);
            uint8_t sak = d->dev.nfca.selRes.sak;

            printf(" || ATQA=0x%04X SAK=0x%02X", atqa, sak);

            const uint8_t *uid = NULL;
            uint8_t uidLen = 0;

            uid    = d->dev.nfca.nfcId1;
            uidLen = d->dev.nfca.nfcId1Len;

            if((uidLen == 0) && (d->nfcidLen > 0)) {
                uid = d->nfcid;
                uidLen = d->nfcidLen;
            }

            print_uid_line(" || UID", uid, uidLen);

            if(uidLen > 0) {
                printf(" || Manufacturer(hint): %s (UID0=0x%02X) ",
                       nfc_ident_nfca_manufacturer(uid[0]), uid[0]);
            }

            nfc_card_type_t ct = nfc_ident_detect_nfca(atqa, sak);
            printf(" || Detected: %s", nfc_ident_card_type_to_str(ct));

            if(d->rfInterface == RFAL_NFC_INTERFACE_ISODEP)
            {
                print_iso_dep_details_(d);
            }

            if((active_dev != NULL) && poom_nfc_reader_same_device_(d, active_dev))
            {
                print_get_version_details_(ct);
            }

            printf("\r\n");
        }
        else
        {
            if(d->nfcidLen > 0) {
                print_uid_line("ID", d->nfcid, d->nfcidLen);
            }
            if((d->rfInterface == RFAL_NFC_INTERFACE_ISODEP) &&
               (active_dev != NULL) &&
               poom_nfc_reader_same_device_(d, active_dev))
            {
                print_iso_dep_details_(d);
            }
            printf("\r\n");
        }
    }
}


/**
 * @brief Internal helper for `pick_preferred_device`.
 *
 * @return uint8_t
 */
static uint8_t pick_preferred_device(void)
{
    rfalNfcDevice *devList = NULL;
    uint8_t devCnt = 0;

    rfalNfcGetDevicesFound(&devList, &devCnt);
    if(devCnt == 0 || devList == NULL) return 0;

    for(uint8_t i = 0; i < devCnt; i++)
        if(devList[i].rfInterface == RFAL_NFC_INTERFACE_ISODEP) return i;

    for(uint8_t i = 0; i < devCnt; i++)
        if(poom_nfc_reader_is_nfca_type_(devList[i].type)) return i;

    return 0;
}

/* Generic transceive helper for raw T2T and ISO-DEP-backed exchanges. */

/**
 * @brief Internal helper for `nfc_link_transceive`.
 *
 * @param[in] tx Parameter passed to the function.
 * @param[in] tx_len Parameter passed to the function.
 * @param[in] rx Parameter passed to the function.
 * @param[in] rx_max Parameter passed to the function.
 * @param[in] rx_len_out Parameter passed to the function.
 * @param[in] user_ctx Parameter passed to the function.
 * @return bool
 */
static bool nfc_link_transceive(
    const uint8_t *tx, size_t tx_len,
    uint8_t *rx, size_t rx_max,
    size_t *rx_len_out,
    void *user_ctx)
{
    (void)user_ctx;

    rfalNfcDevice *active = NULL;
    uint8_t  *rxData = NULL;
    uint16_t *rcvLen = NULL;
    bool rf_interface = false;
    uint16_t tx_units = 0U;
    uint16_t rx_units = 0U;
    size_t src_len = 0U;

    if(!rx || !rx_len_out) return false;
    *rx_len_out = 0;

    rfalNfcGetActiveDevice(&active);
    rf_interface = (active != NULL) && (active->rfInterface == RFAL_NFC_INTERFACE_RF);

    if(rf_interface)
    {
        const uint32_t tx_bits = rfalConvBytesToBits((uint16_t)tx_len);
        if(tx_bits > 0xFFFFU)
        {
            return false;
        }
        tx_units = (uint16_t)tx_bits;
    }
    else
    {
        if(tx_len > 0xFFFFU)
        {
            return false;
        }
        tx_units = (uint16_t)tx_len;
    }

    if(tx && tx_len) {
        printf_log("[TX] %u bytes", (unsigned)tx_len);
        PRINTF_HEX(tx, tx_len);
    }

    ReturnCode err = demoTransceiveBlocking((uint8_t*)tx, tx_units,
                                           &rxData, &rcvLen, RFAL_FWT_NONE);

    if(err != ERR_NONE || !rxData || !rcvLen) {
        printf_log("[RX] error=%d", err);
        return false;
    }

    rx_units = *rcvLen;
    src_len = rf_interface ? (size_t)rfalConvBitsToBytes(rx_units) : (size_t)rx_units;
    size_t copy_len = (src_len < rx_max) ? src_len : rx_max;
    memcpy(rx, rxData, copy_len);
    *rx_len_out = copy_len;

    printf_log("[RX] %u bytes", (unsigned)copy_len);
    PRINTF_HEX(rx, copy_len);

    return true;
}

/* =========================================================
 * Demo readers (B/F/V)
 * ========================================================= */

/* ---- APDUs (ISO-DEP) ---- */
#if RFAL_FEATURE_ISO_DEP_POLL
static uint8_t ndefSelectApp[] = { 0x00, 0xA4, 0x04, 0x00, 0x07, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01, 0x00 };
static uint8_t ccSelectFile[]  = { 0x00, 0xA4, 0x00, 0x0C, 0x02, 0xE1, 0x03 };
static uint8_t readBinary[]    = { 0x00, 0xB0, 0x00, 0x00, 0x0F };
#endif

/**
 * @brief Internal helper for `demoAPDU`.
 *
 * @return void
 */
static void demoAPDU(void)
{
#if RFAL_FEATURE_ISO_DEP_POLL
    ReturnCode err;
    uint16_t   *rxLen;
    uint8_t    *rxData;

    err = demoTransceiveBlocking(ndefSelectApp, sizeof(ndefSelectApp), &rxData, &rxLen, RFAL_FWT_NONE);
    printf_log("Select NDEF Application:");
    if(err != ERR_NONE) {
        printf_log("  FAIL");
        return;
    }
    printf_log("  OK:");
    PRINTF_HEX(rxData, *rxLen);

    if((*rxLen >= 2) && (rxData[0] == 0x90U) && (rxData[1] == 0x00U))
    {
        err = demoTransceiveBlocking(ccSelectFile, sizeof(ccSelectFile), &rxData, &rxLen, RFAL_FWT_NONE);
        printf_log("Select CC:");
        if(err != ERR_NONE) { printf_log("  FAIL"); return; }
        printf_log("  OK:");
        PRINTF_HEX(rxData, *rxLen);

        err = demoTransceiveBlocking(readBinary, sizeof(readBinary), &rxData, &rxLen, RFAL_FWT_NONE);
        printf_log("Read CC:");
        if(err != ERR_NONE) { printf_log("  FAIL"); return; }
        printf_log("  OK:");
        PRINTF_HEX(rxData, *rxLen);
    }
#else
    printf_log("demoAPDU: ISO-DEP not compiled");
#endif
}

/* ---- NFC-V ---- */

/**
 * @brief Internal helper for `demoNfcv`.
 *
 * @param[in] nfcvDev Parameter passed to the function.
 * @return void
 */
static void demoNfcv(rfalNfcvListenDevice *nfcvDev)
{
#if RFAL_FEATURE_NFCV
    ReturnCode err;
    uint16_t rcvLen;
    uint8_t  blockNum = 1;

    uint8_t rxBuf[1 + DEMO_NFCV_BLOCK_LEN + RFAL_CRC_LEN];

    uint8_t *uid  = nfcvDev->InvRes.UID;
    uint8_t reqFlag = RFAL_NFCV_REQ_FLAG_DEFAULT;

    err = rfalNfcvPollerReadSingleBlock(reqFlag, uid, blockNum, rxBuf, sizeof(rxBuf), &rcvLen);
    if(err != ERR_NONE) {
        printf_log("NFC-V Read Block: FAIL err=%d", err);
        return;
    }

    printf_log("NFC-V Read Block OK (block=%u) data:", blockNum);
    PRINTF_HEX(&rxBuf[1], DEMO_NFCV_BLOCK_LEN);
#else
    (void)nfcvDev;
#endif
}

/* ---- NFC-F (Felica) ---- */

/**
 * @brief Internal helper for `demoNfcf`.
 *
 * @param[in] nfcfDev Parameter passed to the function.
 * @return void
 */
static void demoNfcf(rfalNfcfListenDevice *nfcfDev)
{
#if RFAL_FEATURE_NFCF
    ReturnCode err;
    uint8_t  buf[(RFAL_NFCF_NFCID2_LEN + RFAL_NFCF_CMD_LEN + (3 * RFAL_NFCF_BLOCK_LEN))];
    uint16_t rcvLen;

    rfalNfcfServ srv = RFAL_NFCF_SERVICECODE_RDWR;
    rfalNfcfBlockListElem bl[3];
    rfalNfcfServBlockListParam servBlock;

    servBlock.numServ   = 1;
    servBlock.servList  = &srv;
    servBlock.numBlock  = 1;
    servBlock.blockList = bl;

    bl[0].conf     = RFAL_NFCF_BLOCKLISTELEM_LEN_BIT;
    bl[0].blockNum = 0x0001;

    err = rfalNfcfPollerCheck(nfcfDev->sensfRes.NFCID2, &servBlock, buf, sizeof(buf), &rcvLen);
    if(err != ERR_NONE) {
        printf_log("NFC-F Check Block: FAIL err=%d", err);
        return;
    }

    printf_log("NFC-F Check Block OK data:");
    PRINTF_HEX(&buf[1], RFAL_NFCF_BLOCK_LEN);
#else
    (void)nfcfDev;
#endif
}

/* =========================================================
 * RFAL blocking data exchange
 * ========================================================= */
ReturnCode demoTransceiveBlocking(uint8_t *txBuf, uint16_t txBufSize,
                                  uint8_t **rxData, uint16_t **rcvLen,
                                  uint32_t fwt)
{
    ReturnCode err;

    err = rfalNfcDataExchangeStart(txBuf, txBufSize, rxData, rcvLen, fwt);
    if(err == ERR_NONE)
    {
        do {
            rfalNfcWorker();
            err = rfalNfcDataExchangeGetStatus();
        } while(err == ERR_BUSY);
    }
    return err;
}

/**
 * @brief Internal helper for `build_tech_mask`.
 *
 * @param[in] tech Parameter passed to the function.
 * @return uint32_t
 */
static uint32_t build_tech_mask(poom_nfc_reader_tech_t tech)
{
    uint32_t mask = RFAL_NFC_TECH_NONE;

    switch (tech) {
        case POOM_NFC_READER_TECH_A:
#if RFAL_FEATURE_NFCA
            mask |= RFAL_NFC_POLL_TECH_A;
#endif
            break;
        case POOM_NFC_READER_TECH_B:
#if RFAL_FEATURE_NFCB
            mask |= RFAL_NFC_POLL_TECH_B;
#endif
            break;
        case POOM_NFC_READER_TECH_F:
#if RFAL_FEATURE_NFCF
            mask |= RFAL_NFC_POLL_TECH_F;
#endif
            break;
        case POOM_NFC_READER_TECH_V:
#if RFAL_FEATURE_NFCV
            mask |= RFAL_NFC_POLL_TECH_V;
#endif
            break;
        case POOM_NFC_READER_TECH_ST25TB:
#if RFAL_FEATURE_ST25TB
            mask |= RFAL_NFC_POLL_TECH_ST25TB;
#endif
            break;
        case POOM_NFC_READER_TECH_ALL:
        default:
#if RFAL_FEATURE_NFCA
            mask |= RFAL_NFC_POLL_TECH_A;
#endif
#if RFAL_FEATURE_NFCB
            mask |= RFAL_NFC_POLL_TECH_B;
#endif
#if RFAL_FEATURE_NFCF
            mask |= RFAL_NFC_POLL_TECH_F;
#endif
#if RFAL_FEATURE_NFCV
            mask |= RFAL_NFC_POLL_TECH_V;
#endif
#if RFAL_FEATURE_ST25TB
            mask |= RFAL_NFC_POLL_TECH_ST25TB;
#endif
            break;
    }

    return mask;
}

/**
 * @brief Internal helper for `apply_tech_filter`.
 *
 * @return void
 */
static void apply_tech_filter(void)
{
    s_discParam.techs2Find = build_tech_mask(s_selected_tech);

    if (s_discParam.techs2Find == RFAL_NFC_TECH_NONE) {
        s_discParam.techs2Find = build_tech_mask(POOM_NFC_READER_TECH_ALL);
    }
}
