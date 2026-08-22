#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ==========================
 * NFC-A ATQA/SAK enums
 * ========================== */

typedef enum {
    NFC_SAK_ULTRALIGHT_CL2      = 0x00,
    NFC_SAK_TNP3XXX             = 0x01,
    NFC_SAK_MIFARE_CL1_NO_DF    = 0x04,
    NFC_SAK_MIFARE_CLASSIC_1K   = 0x08,
    NFC_SAK_MIFARE_MINI         = 0x09,
    NFC_SAK_MIFARE_PLUS_2K      = 0x10,
    NFC_SAK_MIFARE_PLUS_4K      = 0x11,
    NFC_SAK_MIFARE_4K           = 0x18,
    NFC_SAK_MIFARE_PLUS_OR_DF   = 0x20,
    NFC_SAK_DESFIRE_CL1         = 0x24,
    NFC_SAK_DESFIRE_OR_JCOP     = 0x28,
    NFC_SAK_NOKIA_CLASSIC_4K    = 0x38,
    NFC_SAK_INFINEON_CLASSIC    = 0x88,
    NFC_SAK_GEMPLUS_MPCOS       = 0x98,
} nfc_nfca_sak_t;

typedef enum {
    NFC_ATQA_MIFARE_MINI        = 0x0004,
    NFC_ATQA_CLASSIC_4K         = 0x0002,

    NFC_ATQA_ULTRALIGHT         = 0x0044,
    NFC_ATQA_PLUS_4K_CL2        = 0x0042,

    NFC_ATQA_JCOP               = 0x0048,

    NFC_ATQA_NTAG424DNA_RID     = 0x0304,
    NFC_ATQA_DESFIRE_EV1        = 0x0344,

    NFC_ATQA_JEWEL              = 0x0C00,
} nfc_nfca_atqa_t;

/* ==========================
 * High-level card type
 * ========================== */

typedef enum {
    NFC_CARD_UNKNOWN = 0,

    NFC_CARD_ULTRALIGHT_OR_NTAG,   /* T2T (Ultralight/NTAG...) - GET_VERSION required for accuracy */
    NFC_CARD_MIFARE_MINI,
    NFC_CARD_MIFARE_CLASSIC_1K,
    NFC_CARD_MIFARE_CLASSIC_4K,
    NFC_CARD_MIFARE_PLUS,
    NFC_CARD_MIFARE_DESFIRE,       /* ISO-DEP */
    NFC_CARD_NTAG424DNA,
    NFC_CARD_JCOP,
    NFC_CARD_JEWEL,
    NFC_CARD_OTHER,
} nfc_card_type_t;

/* ==========================
 * GET_VERSION parsing
 * ========================== */

typedef enum {
    NFC_GV_NONE = 0,
    NFC_GV_T2T_UL_NTAG,   /* 8-byte response (MIFARE Ultralight EV1 / NTAG / etc.) */
    NFC_GV_DESFIRE_APDU,  /* Chained APDU response (multiple frames) */
} nfc_get_version_kind_t;

/* Decoded Ultralight EV1 / NTAG response (GET_VERSION = 0x60). */
typedef struct {
    uint8_t raw[8];
    bool    valid;

    /* Common GET_VERSION fields (8 bytes) */
    uint8_t vendor_id;
    uint8_t product_type;
    uint8_t product_subtype;
    uint8_t major_version;
    uint8_t minor_version;
    uint8_t storage_size;
    uint8_t protocol_type;
} nfc_t2t_get_version_t;

/* Raw DESFire response including trailing SW1/SW2 bytes. */
typedef struct {
    uint8_t raw[64];
    size_t  raw_len;
    bool    valid;

    /* Final APDU status words */
    uint8_t sw1;
    uint8_t sw2;
} nfc_desfire_get_version_t;

typedef struct {
    nfc_get_version_kind_t kind;
    union {
        nfc_t2t_get_version_t      t2t;
        nfc_desfire_get_version_t  df;
    } u;
} nfc_get_version_info_t;

/* ==========================
 * Public API
 * ========================== */

/**
 * @brief Return a manufacturer hint from NFC-A UID0.
 *
 * This is a best-effort lookup and should not be treated as authoritative.
 *
 * @param[in] uid0 First byte of the NFC-A UID.
 * @return Static manufacturer string.
 */
const char* nfc_ident_nfca_manufacturer(uint8_t uid0);

/**
 * @brief Heuristically identify an NFC-A card from ATQA and SAK.
 *
 * @param[in] atqa NFC-A ATQA value.
 * @param[in] sak NFC-A SAK value.
 * @return Detected card type.
 */
nfc_card_type_t nfc_ident_detect_nfca(uint16_t atqa, uint8_t sak);

/**
 * @brief Convert a card type to a printable string.
 *
 * @param[in] t Card type.
 * @return Static card type string.
 */
const char*     nfc_ident_card_type_to_str(nfc_card_type_t t);


/* ==========================
 * Transceive callbacks
 * ========================== */

/**
 * @brief Raw T2T / NFC-A transceive callback.
 *
 * Used for commands such as GET_VERSION (`0x60`) on Ultralight/NTAG tags.
 *
 * @param[in] tx Bytes to send.
 * @param[in] tx_len Number of bytes to send.
 * @param[out] rx Response buffer.
 * @param[in] rx_max Response buffer capacity.
 * @param[out] rx_len_out Number of bytes received.
 * @param[in] user_ctx Opaque caller context.
 * @return true if the exchange succeeded, false otherwise.
 */
typedef bool (*nfc_t2t_transceive_cb)(
    const uint8_t *tx, size_t tx_len,
    uint8_t *rx, size_t rx_max,
    size_t *rx_len_out,
    void *user_ctx
);

/**
 * @brief ISO-DEP APDU transceive callback.
 *
 * Used for DESFire GET_VERSION APDUs and follow-up additional-frame requests.
 *
 * @param[in] tx APDU bytes to send.
 * @param[in] tx_len Number of APDU bytes to send.
 * @param[out] rx Response buffer.
 * @param[in] rx_max Response buffer capacity.
 * @param[out] rx_len_out Number of bytes received.
 * @param[in] user_ctx Opaque caller context.
 * @return true if the link-level exchange succeeded, false otherwise.
 */
typedef bool (*nfc_isodep_transceive_cb)(
    const uint8_t *tx, size_t tx_len,
    uint8_t *rx, size_t rx_max,
    size_t *rx_len_out,
    void *user_ctx
);

/* ==========================
 * Automatic GET_VERSION
 * ========================== */

/**
 * @brief Attempt GET_VERSION using the appropriate transport for the tag type.
 *
 * Uses `t2t_cb` for Ultralight/NTAG-style tags and `isodep_cb` for DESFire.
 *
 * @param[in] detected_type Previously detected card type.
 * @param[in] t2t_cb Raw T2T callback.
 * @param[in] isodep_cb ISO-DEP APDU callback.
 * @param[in] user_ctx Opaque caller context passed to callbacks.
 * @param[out] out_info Parsed GET_VERSION result.
 * @return true if a valid GET_VERSION response was obtained and parsed.
 */
bool nfc_ident_try_get_version(
    nfc_card_type_t detected_type,
    nfc_t2t_transceive_cb t2t_cb,
    nfc_isodep_transceive_cb isodep_cb,
    void *user_ctx,
    nfc_get_version_info_t *out_info
);

#ifdef __cplusplus
}
#endif
