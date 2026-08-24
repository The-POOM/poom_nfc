// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 THE POOM

/* RFAL */
#include "rfal_nfc.h"
#include "rfal_t2t.h"

#include "poom_nfc_dump.h"

typedef enum {
    POOM_NFC_READER_TECH_ALL = 0,
    POOM_NFC_READER_TECH_A,
    POOM_NFC_READER_TECH_B,
    POOM_NFC_READER_TECH_F,
    POOM_NFC_READER_TECH_V,
    POOM_NFC_READER_TECH_ST25TB,
} poom_nfc_reader_tech_t;

/**
 * @brief Initialize the NFC reader layer.
 *
 * @return true on success, false otherwise.
 */
bool poom_nfc_reader_init(void);

/**
 * @brief Run one discovery pass and select a preferred device.
 *
 * @param[out] activeDevOut Optional pointer to the activated device.
 * @param[in] timeout_ms Discovery timeout in milliseconds.
 * @return true if a device was activated, false otherwise.
 */
bool poom_nfc_reader_scan_once(rfalNfcDevice **activeDevOut, uint32_t timeout_ms);

/**
 * @brief Process an already activated device.
 *
 * Prints or probes additional information depending on tag type.
 *
 * @param[in] dev Active RFAL device.
 * @return true if the device type was handled, false otherwise.
 */
bool poom_nfc_reader_active(rfalNfcDevice *dev);

/**
 * @brief Set the technology filter used for discovery.
 *
 * @param[in] tech Technology selection.
 */
void poom_nfc_reader_set_technology(poom_nfc_reader_tech_t tech);

/**
 * @brief Return the current technology filter.
 *
 * @return Current technology selection.
 */
poom_nfc_reader_tech_t poom_nfc_reader_get_technology(void);

/**
 * @brief Convert a technology filter value to a printable string.
 *
 * @param[in] tech Technology selection.
 * @return Static technology string.
 */
const char *poom_nfc_reader_technology_to_str(poom_nfc_reader_tech_t tech);

/**
 * @brief Creates an NFC dump object from an already-activated device.
 *
 * For supported tags (NTAG / Type 2), reads memory pages and metadata.
 * For other tags, fills ID-only dump.
 */
bool poom_nfc_reader_create_dump(const rfalNfcDevice *dev, poom_nfc_dump_t *out_dump);
