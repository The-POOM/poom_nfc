// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 THE POOM

/* MIFARE Classic / Mini support. */
#include "poom_nfc_mifare_classic.h"
#include "poom_nfc_mifare_test_dict.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_random.h"
#include "esp_system.h"
#include "sd_card.h"

#include "poom_nfc_iso14443_4.h"
#include "rfal_nfc.h"
#include "rfal_nfca.h"
#include "rfal_rf.h"

#ifndef ERR_NONE
#define ERR_NONE (0U)
#endif

#ifndef POOM_MIFARE_TRACE
#define POOM_MIFARE_TRACE 0
#endif

#ifndef POOM_MIFARE_USE_TEST_DICTIONARY
#define POOM_MIFARE_USE_TEST_DICTIONARY 1
#endif

enum
{
    POOM_MIFARE_UID_MAX            = 10,
    POOM_MIFARE_KEY_SIZE           = 6,
    POOM_MIFARE_AUTH_RESP_LEN      = 4,
    POOM_MIFARE_AUTH_STEP2_TX_LEN  = 8,
    POOM_MIFARE_TXRX_TIMEOUT_TICKS = (216960U + 71680U + 71680U),
    POOM_NFCA_SEL_CL1              = 0x93,
    POOM_NFCA_ANTICOLLISION        = 0x20,
    POOM_NFCA_SELECT               = 0x70,
    POOM_NFCA_UID_BCC_LEN          = 5,
    POOM_MIFARE_AUTH_BITS_PER_BYTE = 9,
    POOM_MIFARE_TXRX_BITS_BUF_MAX  = 64,
    POOM_MIFARE_SECTOR_MAX         = 40,
    POOM_MIFARE_BLOCK_MAX          = 256,
    POOM_MIFARE_CMD_READ           = 0x30,
    POOM_MIFARE_CMD_WRITE          = 0xA0,
};

typedef struct
{
    bool active;
    nfc_card_type_t card_type;
    uint8_t uid[POOM_MIFARE_UID_MAX];
    uint8_t uid_len;
    bool atqa_sak_set;
    uint16_t atqa;
    uint8_t sak;
    bool last_auth_attempted;
    bool auth_step1_ok;
    uint8_t last_block;
    poom_mifare_key_type_t last_key_type;
    uint8_t last_nonce[POOM_MIFARE_AUTH_RESP_LEN];
    bool last_auth_partial_ok;
    bool last_auth_full_ok;
} poom_mifare_ctx_t;

typedef struct
{
    uint8_t key[POOM_MIFARE_KEY_SIZE];
    uint8_t uid[POOM_MIFARE_UID_MAX];
    uint8_t uid_len;
    uint8_t block;
    poom_mifare_key_type_t key_type;
    uint8_t nt[4];
    uint8_t nr[4];
    uint8_t ar[4];
} poom_mifare_crypto1_session_t;

typedef struct
{
    uint8_t* data;
    uint8_t* valid_bits;
    uint16_t block_count;
} poom_mifare_block_cache_t;

static uint16_t poom_mifare_max_block_for_type(nfc_card_type_t card_type);

static poom_mifare_ctx_t s_mf_ctx;
static poom_mifare_block_cache_t s_block_cache;
static bool s_crypto1_link_limit = false;
static bool s_mifare_discover_quiet = false;

static uint8_t s_last_key_a[POOM_MIFARE_KEY_SIZE];
static bool s_last_key_a_valid = false;
static uint8_t s_last_key_b[POOM_MIFARE_KEY_SIZE];
static bool s_last_key_b_valid = false;

static uint8_t s_sector_key_a[POOM_MIFARE_SECTOR_MAX][POOM_MIFARE_KEY_SIZE];
static uint8_t s_sector_key_b[POOM_MIFARE_SECTOR_MAX][POOM_MIFARE_KEY_SIZE];
static uint8_t s_sector_key_a_valid[(POOM_MIFARE_SECTOR_MAX + 7U) / 8U];
static uint8_t s_sector_key_b_valid[(POOM_MIFARE_SECTOR_MAX + 7U) / 8U];

#define POOM_BITSET_SET(arr, idx)   ((arr)[(idx) >> 3] |= (uint8_t)(1u << ((idx) & 7)))
#define POOM_BITSET_TEST(arr, idx)  ((((arr)[(idx) >> 3]) & (uint8_t)(1u << ((idx) & 7))) != 0U)

static size_t poom_mifare_block_cache_bits_len_(uint16_t block_count)
{
    return (size_t)((block_count + 7U) / 8U);
}

static void poom_mifare_block_cache_release_(void)
{
    free(s_block_cache.data);
    free(s_block_cache.valid_bits);
    s_block_cache.data = NULL;
    s_block_cache.valid_bits = NULL;
    s_block_cache.block_count = 0U;
}

static bool poom_mifare_block_cache_ensure_(nfc_card_type_t card_type)
{
    const uint16_t block_count = (uint16_t)(poom_mifare_max_block_for_type(card_type) + 1U);
    const size_t bits_len = poom_mifare_block_cache_bits_len_(block_count);
    uint8_t* data;
    uint8_t* valid_bits;

    if(block_count == 0U)
    {
        return false;
    }
    if((s_block_cache.data != NULL) && (s_block_cache.valid_bits != NULL) &&
       (s_block_cache.block_count == block_count))
    {
        return true;
    }

    poom_mifare_block_cache_release_();

    data = (uint8_t*)calloc((size_t)block_count, 16U);
    valid_bits = (uint8_t*)calloc(bits_len, 1U);
    if((data == NULL) || (valid_bits == NULL))
    {
        free(data);
        free(valid_bits);
        printf("  mifare cache: alloc failed for %u blocks\r\n", (unsigned)block_count);
        return false;
    }

    s_block_cache.data = data;
    s_block_cache.valid_bits = valid_bits;
    s_block_cache.block_count = block_count;
    return true;
}

static bool poom_mifare_block_cache_has_any_(void)
{
    if((s_block_cache.valid_bits == NULL) || (s_block_cache.block_count == 0U))
    {
        return false;
    }

    for(size_t i = 0; i < poom_mifare_block_cache_bits_len_(s_block_cache.block_count); i++)
    {
        if(s_block_cache.valid_bits[i] != 0U)
        {
            return true;
        }
    }

    return false;
}

static bool poom_mifare_block_cache_has_all_(uint16_t block_count)
{
    if((s_block_cache.valid_bits == NULL) || (block_count == 0U) ||
       (s_block_cache.block_count < block_count))
    {
        return false;
    }

    for(uint16_t block = 0U; block < block_count; block++)
    {
        if(!POOM_BITSET_TEST(s_block_cache.valid_bits, block))
        {
            return false;
        }
    }

    return true;
}

/* Typical factory/test keys; order is intentional (most common first). */
#if !POOM_MIFARE_USE_TEST_DICTIONARY
static const uint8_t s_default_keys[][POOM_MIFARE_KEY_SIZE] = {
    {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
    {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5},
    {0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
};
#endif

static const uint8_t s_priority_keys[][POOM_MIFARE_KEY_SIZE] = {
    {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
    {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5},
    {0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7},
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
};

/**
 * @brief Internal helper for `poom_mifare_full_crypto1_ready`.
 *
 * @return bool
 */
static bool poom_mifare_full_crypto1_ready(void)
{
    return true;
}

/**
 * @brief Internal helper for `poom_mifare_sector_count_for_type`.
 *
 * @param[in] card_type Parameter passed to the function.
 * @return uint8_t
 */
static uint8_t poom_mifare_sector_count_for_type(nfc_card_type_t card_type)
{
    switch(card_type)
    {
        case NFC_CARD_MIFARE_MINI:
            return 5U;
        case NFC_CARD_MIFARE_CLASSIC_1K:
            return 16U;
        case NFC_CARD_MIFARE_CLASSIC_4K:
            return 40U;
        default:
            return 0U;
    }
}

/**
 * @brief Internal helper for `poom_mifare_first_block_of_sector`.
 *
 * @param[in] card_type Parameter passed to the function.
 * @param[in] sector Parameter passed to the function.
 * @return uint16_t
 */
static uint16_t poom_mifare_first_block_of_sector(nfc_card_type_t card_type, uint8_t sector)
{
    if(card_type == NFC_CARD_MIFARE_CLASSIC_4K)
    {
        if(sector < 32U)
        {
            return (uint16_t)(sector * 4U);
        }
        if(sector < 40U)
        {
            return (uint16_t)(32U * 4U + (uint16_t)(sector - 32U) * 16U);
        }
        return 0U;
    }

    return (uint16_t)(sector * 4U);
}

/**
 * @brief Internal helper for `poom_mifare_blocks_in_sector`.
 *
 * @param[in] card_type Parameter passed to the function.
 * @param[in] sector Parameter passed to the function.
 * @return uint8_t
 */
static uint8_t poom_mifare_blocks_in_sector(nfc_card_type_t card_type, uint8_t sector)
{
    if(card_type == NFC_CARD_MIFARE_CLASSIC_4K)
    {
        return (sector < 32U) ? 4U : 16U;
    }

    (void)sector;
    return 4U;
}

/**
 * @brief Internal helper for `poom_mifare_auth_target_block`.
 *
 * @param[in] card_type Parameter passed to the function.
 * @param[in] sector Parameter passed to the function.
 * @return uint8_t
 */
static uint8_t poom_mifare_auth_target_block(nfc_card_type_t card_type, uint8_t sector)
{
    uint16_t first = poom_mifare_first_block_of_sector(card_type, sector);
    uint8_t blocks = poom_mifare_blocks_in_sector(card_type, sector);
    uint16_t trailer = (uint16_t)(first + (uint16_t)blocks - 1U);
    uint16_t target = first;

    if(sector == 0U)
    {
        target = (uint16_t)(first + 1U);
    }

    if(target >= trailer)
    {
        target = first;
        if(sector == 0U)
        {
            target = (uint16_t)(first + 1U);
        }
    }

    return (uint8_t)target;
}

/**
 * @brief Internal helper for `poom_mifare_sector_of_block`.
 *
 * @param[in] card_type Parameter passed to the function.
 * @param[in] block Parameter passed to the function.
 * @return int
 */
static int poom_mifare_sector_of_block(nfc_card_type_t card_type, uint8_t block)
{
    uint8_t sectors = poom_mifare_sector_count_for_type(card_type);

    if(sectors == 0U)
    {
        return -1;
    }

    for(uint8_t s = 0U; s < sectors; s++)
    {
        uint16_t first = poom_mifare_first_block_of_sector(card_type, s);
        uint8_t blocks = poom_mifare_blocks_in_sector(card_type, s);
        uint16_t last_excl = (uint16_t)(first + blocks);
        if(((uint16_t)block >= first) && ((uint16_t)block < last_excl))
        {
            return (int)s;
        }
    }

    return -1;
}

/**
 * @brief Internal helper for `poom_mifare_record_working_key`.
 *
 * @param[in] key Parameter passed to the function.
 * @param[in] key_type Parameter passed to the function.
 * @return void
 */
static void poom_mifare_record_working_key_(const uint8_t key[POOM_MIFARE_KEY_SIZE],
                                            poom_mifare_key_type_t key_type)
{
    if(key == NULL)
    {
        return;
    }

    if(key_type == POOM_MIFARE_KEY_A)
    {
        memcpy(s_last_key_a, key, POOM_MIFARE_KEY_SIZE);
        s_last_key_a_valid = true;
    }
    else if(key_type == POOM_MIFARE_KEY_B)
    {
        memcpy(s_last_key_b, key, POOM_MIFARE_KEY_SIZE);
        s_last_key_b_valid = true;
    }
}

/**
 * @brief Internal helper for `poom_mifare_cache_record_sector_key`.
 *
 * @param[in] sector Parameter passed to the function.
 * @param[in] key_type Parameter passed to the function.
 * @param[in] key Parameter passed to the function.
 * @return void
 */
static void poom_mifare_cache_record_sector_key_(uint8_t sector,
                                                 poom_mifare_key_type_t key_type,
                                                 const uint8_t key[POOM_MIFARE_KEY_SIZE])
{
    if(key == NULL || sector >= POOM_MIFARE_SECTOR_MAX)
    {
        return;
    }

    if(key_type == POOM_MIFARE_KEY_A)
    {
        memcpy(s_sector_key_a[sector], key, POOM_MIFARE_KEY_SIZE);
        POOM_BITSET_SET(s_sector_key_a_valid, sector);
    }
    else if(key_type == POOM_MIFARE_KEY_B)
    {
        memcpy(s_sector_key_b[sector], key, POOM_MIFARE_KEY_SIZE);
        POOM_BITSET_SET(s_sector_key_b_valid, sector);
    }
}

/**
 * @brief Internal helper for `poom_mifare_sector_key_known`.
 *
 * @param[in] sector Parameter passed to the function.
 * @param[in] key_type Parameter passed to the function.
 * @return bool
 */
static bool poom_mifare_sector_key_known_(uint8_t sector, poom_mifare_key_type_t key_type)
{
    if(sector >= POOM_MIFARE_SECTOR_MAX)
    {
        return false;
    }

    if(key_type == POOM_MIFARE_KEY_A)
    {
        return POOM_BITSET_TEST(s_sector_key_a_valid, sector);
    }
    if(key_type == POOM_MIFARE_KEY_B)
    {
        return POOM_BITSET_TEST(s_sector_key_b_valid, sector);
    }
    return false;
}

/**
 * @brief Internal helper for `poom_mifare_get_sector_key_ptr`.
 *
 * @param[in] sector Parameter passed to the function.
 * @param[in] key_type Parameter passed to the function.
 * @return const uint8_t*
 */
static const uint8_t* poom_mifare_get_sector_key_ptr_(uint8_t sector, poom_mifare_key_type_t key_type)
{
    if(!poom_mifare_sector_key_known_(sector, key_type))
    {
        return NULL;
    }

    return (key_type == POOM_MIFARE_KEY_A) ? s_sector_key_a[sector] : s_sector_key_b[sector];
}

/**
 * @brief Clears the internal state used by this module.
 *
 * @return void
 */
static void poom_mifare_block_cache_clear_(void)
{
    if((s_block_cache.valid_bits != NULL) && (s_block_cache.block_count != 0U))
    {
        memset(s_block_cache.valid_bits, 0, poom_mifare_block_cache_bits_len_(s_block_cache.block_count));
    }
}

/**
 * @brief Internal helper for `poom_mifare_block_cache_store`.
 *
 * @param[in] block Parameter passed to the function.
 * @param[in] data Parameter passed to the function.
 * @return void
 */
static void poom_mifare_block_cache_store_(uint16_t block, const uint8_t data[16])
{
    if((data == NULL) || !s_mf_ctx.active)
    {
        return;
    }
    if(!poom_mifare_block_cache_ensure_(s_mf_ctx.card_type))
    {
        return;
    }
    if(block >= s_block_cache.block_count)
    {
        return;
    }

    memcpy(&s_block_cache.data[(size_t)block * 16U], data, 16U);
    POOM_BITSET_SET(s_block_cache.valid_bits, block);
}

/**
 * @brief Loads internal data used by this module.
 *
 * @param[in] block Parameter passed to the function.
 * @param[in] out16 Parameter passed to the function.
 * @return bool
 */
static bool poom_mifare_block_cache_load_(uint16_t block, uint8_t out16[16])
{
    if((out16 == NULL) || (s_block_cache.data == NULL) || (s_block_cache.valid_bits == NULL) ||
       (block >= s_block_cache.block_count) ||
       !POOM_BITSET_TEST(s_block_cache.valid_bits, block))
    {
        return false;
    }

    memcpy(out16, &s_block_cache.data[(size_t)block * 16U], 16U);
    return true;
}

/**
 * @brief Internal helper for `poom_trace_hex`.
 *
 * @param[in] label Parameter passed to the function.
 * @param[in] buf Parameter passed to the function.
 * @param[in] len Parameter passed to the function.
 * @return void
 */
static void poom_trace_hex(const char* label, const uint8_t* buf, uint16_t len)
{
#if POOM_MIFARE_TRACE
    if(label != NULL)
    {
        printf("  [mf-trace] %s:", label);
    }
    if(buf == NULL || len == 0U)
    {
        printf(" <empty>\r\n");
        return;
    }
    for(uint16_t i = 0; i < len; i++)
    {
        printf(" %02X", buf[i]);
    }
    printf("\r\n");
#else
    (void)label;
    (void)buf;
    (void)len;
#endif
}

/**
 * @brief Internal helper for `poom_trace_bits`.
 *
 * @param[in] label Parameter passed to the function.
 * @param[in] buf Parameter passed to the function.
 * @param[in] bit_len Parameter passed to the function.
 * @return void
 */
static void poom_trace_bits(const char* label, const uint8_t* buf, uint16_t bit_len)
{
#if POOM_MIFARE_TRACE
    uint16_t byte_len = (uint16_t)rfalConvBitsToBytes(bit_len);
    if(label != NULL)
    {
        printf("  [mf-trace] %s: bits=%u bytes=%u\r\n", label, bit_len, byte_len);
    }
    poom_trace_hex("bits-raw", buf, byte_len);
#else
    (void)label;
    (void)buf;
    (void)bit_len;
#endif
}

/**
 * @brief Internal helper for `poom_bits_set`.
 *
 * @param[in] buf Parameter passed to the function.
 * @param[in] bit_pos Parameter passed to the function.
 * @param[in] bit Parameter passed to the function.
 * @return void
 */
static void poom_bits_set(uint8_t* buf, uint16_t bit_pos, uint8_t bit)
{
    uint16_t byte_idx = (uint16_t)(bit_pos >> 3);
    uint8_t bit_idx   = (uint8_t)(bit_pos & 0x7U);
    uint8_t mask      = (uint8_t)(1U << bit_idx);

    if(bit != 0U)
    {
        buf[byte_idx] |= mask;
    }
    else
    {
        buf[byte_idx] &= (uint8_t)~mask;
    }
}

/**
 * @brief Internal helper for `poom_bits_get`.
 *
 * @param[in] buf Parameter passed to the function.
 * @param[in] bit_pos Parameter passed to the function.
 * @return uint8_t
 */
static uint8_t poom_bits_get(const uint8_t* buf, uint16_t bit_pos)
{
    uint16_t byte_idx = (uint16_t)(bit_pos >> 3);
    uint8_t bit_idx   = (uint8_t)(bit_pos & 0x7U);
    return (uint8_t)((buf[byte_idx] >> bit_idx) & 0x01U);
}

/**
 * @brief Internal helper for `poom_bswap32`.
 *
 * @param[in] x Parameter passed to the function.
 * @return uint32_t
 */
static uint32_t poom_bswap32(uint32_t x)
{
    return ((x & 0x000000FFU) << 24) | ((x & 0x0000FF00U) << 8) |
           ((x & 0x00FF0000U) >> 8) | ((x & 0xFF000000U) >> 24);
}

/**
 * @brief Internal helper for `poom_u32_from_be`.
 *
 * @param[in] b Parameter passed to the function.
 * @return uint32_t
 */
static uint32_t poom_u32_from_be(const uint8_t b[4])
{
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8) | (uint32_t)b[3];
}

/**
 * @brief Internal helper for `poom_u32_to_be`.
 *
 * @param[in] v Parameter passed to the function.
 * @param[in] out Parameter passed to the function.
 * @return void
 */
static void poom_u32_to_be(uint32_t v, uint8_t out[4])
{
    out[0] = (uint8_t)(v >> 24);
    out[1] = (uint8_t)(v >> 16);
    out[2] = (uint8_t)(v >> 8);
    out[3] = (uint8_t)v;
}

/**
 * @brief Internal helper for `poom_mifare_prng_successor`.
 *
 * @param[in] x Parameter passed to the function.
 * @param[in] n Parameter passed to the function.
 * @return uint32_t
 */
static uint32_t poom_mifare_prng_successor(uint32_t x, uint32_t n)
{
    x = poom_bswap32(x);
    while(n--)
    {
        x = (x >> 1) | ((x >> 16 ^ x >> 18 ^ x >> 19 ^ x >> 21) << 31);
    }
    return poom_bswap32(x);
}

typedef struct
{
    uint32_t odd;
    uint32_t even;
} poom_crypto1_state_t;

static uint8_t poom_crypto1_bit(poom_crypto1_state_t* s,
                                uint8_t in,
                                int is_encrypted);
static uint8_t poom_crypto1_filter(uint32_t x);
static uint8_t poom_mifare_oddparity_bit8_(uint8_t x);

#define POOM_BIT(_x, _n)   ((uint8_t)(((_x) >> (_n)) & 0x1U))
#define POOM_BEBIT(_x, _n) POOM_BIT((_x), ((_n) ^ 24U))
#define POOM_LF_POLY_ODD   (0x29CE5CU)
#define POOM_LF_POLY_EVEN  (0x870804U)

/**
 * @brief Internal helper for `poom_oddparity32`.
 *
 * @param[in] x Parameter passed to the function.
 * @return uint8_t
 */
static uint8_t poom_oddparity32(uint32_t x)
{
    return (uint8_t)__builtin_parity(x);
}

/**
 * @brief Internal helper for `poom_crypto1_keystream_peek`.
 *
 * @param[in] s Parameter passed to the function.
 * @return uint8_t
 */
static uint8_t poom_crypto1_keystream_peek(const poom_crypto1_state_t* s)
{
    if(s == NULL)
    {
        return 0U;
    }
    return poom_crypto1_filter(s->odd);
}

/**
 * @brief Internal helper for `poom_mifare_is_incomplete_byte_rc`.
 *
 * @param[in] rc Parameter passed to the function.
 * @return bool
 */
static bool poom_mifare_is_incomplete_byte_rc_(ReturnCode rc)
{
    return (rc >= RFAL_ERR_INCOMPLETE_BYTE) &&
           (rc <= RFAL_ERR_INCOMPLETE_BYTE_07);
}

/**
 * @brief Internal helper for `poom_mifare_is_expected_raw_rx_rc`.
 *
 * @param[in] rc Parameter passed to the function.
 * @return bool
 */
static bool poom_mifare_is_expected_raw_rx_rc_(ReturnCode rc)
{
    return (rc == ERR_NONE) || (rc == RFAL_ERR_CRC) || (rc == RFAL_ERR_PAR) ||
           (rc == RFAL_ERR_FRAMING) || poom_mifare_is_incomplete_byte_rc_(rc);
}

static bool poom_mifare_key_equals_(const uint8_t a[POOM_MIFARE_KEY_SIZE],
                                    const uint8_t b[POOM_MIFARE_KEY_SIZE])
{
    if(a == NULL || b == NULL)
    {
        return false;
    }
    return memcmp(a, b, POOM_MIFARE_KEY_SIZE) == 0;
}

/**
 * @brief Internal helper for `poom_mifare_build_step2_bits`.
 *
 * @param[in] st Parameter passed to the function.
 * @param[in] nr_be Parameter passed to the function.
 * @param[in] ar_be Parameter passed to the function.
 * @param[in] out_bits_buf Parameter passed to the function.
 * @param[in] out_bits_buf_len Parameter passed to the function.
 * @param[in] out_bits_len Parameter passed to the function.
 * @return bool
 */
static bool poom_mifare_build_step2_bits(poom_crypto1_state_t* st,
                                         const uint8_t nr_be[4],
                                         const uint8_t ar_be[4],
                                         uint8_t* out_bits_buf,
                                         uint16_t out_bits_buf_len,
                                         uint16_t* out_bits_len)
{
    uint16_t bit_pos = 0;
    const uint16_t bits_needed =
        (uint16_t)(POOM_MIFARE_AUTH_STEP2_TX_LEN * POOM_MIFARE_AUTH_BITS_PER_BYTE);

    if(st == NULL || nr_be == NULL || ar_be == NULL || out_bits_buf == NULL ||
       out_bits_len == NULL)
        return false;

    if((uint16_t)rfalConvBitsToBytes(bits_needed) > out_bits_buf_len)
        return false;

    memset(out_bits_buf, 0, out_bits_buf_len);
    for(uint8_t i = 0; i < POOM_MIFARE_AUTH_STEP2_TX_LEN; i++)
    {
        bool is_nr_phase;
        uint8_t plain_byte;
        uint8_t parity_plain;

        is_nr_phase = (i < 4U);
        plain_byte  = is_nr_phase ? nr_be[i] : ar_be[i - 4U];

        for(uint8_t b = 0; b < 8U; b++)
        {
            uint8_t plain_bit = (uint8_t)((plain_byte >> b) & 0x01U);
            uint8_t ks;
            uint8_t cbit;

            if(is_nr_phase)
            {
                ks = poom_crypto1_bit(st, plain_bit, 0);
            }
            else
            {
                ks = poom_crypto1_bit(st, 0U, 0);
            }

            cbit = (uint8_t)(plain_bit ^ ks);
            poom_bits_set(out_bits_buf, bit_pos++, cbit);
        }

        parity_plain = poom_mifare_oddparity_bit8_(plain_byte);
        {
            uint8_t cpar =
                (uint8_t)(parity_plain ^ poom_crypto1_keystream_peek(st));
            poom_bits_set(out_bits_buf, bit_pos++, cpar);
        }
    }

    *out_bits_len = bit_pos;
    return true;
}

/**
 * @brief Internal helper for `poom_mifare_decode_step3_bits`.
 *
 * @param[in] st Parameter passed to the function.
 * @param[in] in_bits_buf Parameter passed to the function.
 * @param[in] in_bits_len Parameter passed to the function.
 * @param[in] out_at Parameter passed to the function.
 * @return bool
 */
static bool poom_mifare_decode_step3_bits(poom_crypto1_state_t* st,
                                          const uint8_t* in_bits_buf,
                                          uint16_t in_bits_len,
                                          uint8_t out_at[4])
{
    uint16_t symbols;
    uint16_t bit_pos = 0;

    if(st == NULL || in_bits_buf == NULL || out_at == NULL)
        return false;

    symbols = (uint16_t)(in_bits_len / POOM_MIFARE_AUTH_BITS_PER_BYTE);
    if(symbols < 4U)
        return false;

    for(uint8_t i = 0; i < 4U; i++)
    {
        uint8_t cpar;
        uint8_t ppar;
        uint8_t value = 0;
        for(uint8_t b = 0; b < 8U; b++)
        {
            uint8_t cbit = poom_bits_get(in_bits_buf, bit_pos++);
            uint8_t ks   = poom_crypto1_bit(st, 0U, 0);
            value |= (uint8_t)((cbit ^ ks) << b);
        }

        cpar = poom_bits_get(in_bits_buf, bit_pos++);
        ppar = (uint8_t)(cpar ^ poom_crypto1_keystream_peek(st));
        if(ppar != poom_mifare_oddparity_bit8_(value))
        {
            printf("  mifare crypto1: parity mismatch on rx byte %u\r\n", i);
        }

        out_at[i] = value;
    }

    return true;
}

/**
 * @brief Internal helper for `poom_mifare_transceive_step2_bits_with_manual_parity`.
 *
 * @param[in] tx_bits Parameter passed to the function.
 * @param[in] tx_bits_len Parameter passed to the function.
 * @param[in] rx_bits Parameter passed to the function.
 * @param[in] rx_bits_buf_len Parameter passed to the function.
 * @param[in] rx_bits_len Parameter passed to the function.
 * @return ReturnCode
 */
static ReturnCode poom_mifare_transceive_step2_bits_with_manual_parity(
    const uint8_t* tx_bits,
    uint16_t tx_bits_len,
    uint8_t* rx_bits,
    uint16_t rx_bits_buf_len,
    uint16_t* rx_bits_len)
{
    rfalTransceiveContext ctx;
    ReturnCode rc;

    if(rx_bits_len != NULL)
        *rx_bits_len = 0;
    if(tx_bits == NULL || tx_bits_len == 0U || rx_bits == NULL ||
       rx_bits_len == NULL)
        return RFAL_ERR_PARAM;
    memset(rx_bits, 0, rx_bits_buf_len);

    ctx.txBuf     = (uint8_t*)tx_bits;
    ctx.txBufLen  = tx_bits_len;
    ctx.rxBuf     = rx_bits;
    ctx.rxBufLen  = (uint16_t)rfalConvBytesToBits(rx_bits_buf_len);
    ctx.rxRcvdLen = rx_bits_len;
    ctx.flags     = (uint32_t)RFAL_TXRX_FLAGS_CRC_TX_MANUAL |
                (uint32_t)RFAL_TXRX_FLAGS_CRC_RX_MANUAL |
                (uint32_t)RFAL_TXRX_FLAGS_CRC_RX_KEEP |
                (uint32_t)RFAL_TXRX_FLAGS_PAR_RX_KEEP |
                (uint32_t)RFAL_TXRX_FLAGS_PAR_TX_NONE;
    ctx.fwt       = POOM_MIFARE_TXRX_TIMEOUT_TICKS;

    rc = rfalStartTransceive(&ctx);
    if(rc != ERR_NONE)
        return rc;

    do
    {
        rfalWorker();
        rc = rfalGetTransceiveStatus();
    } while(rc == RFAL_ERR_BUSY);

    return rc;
}

/**
 * @brief Internal helper for `poom_crypto1_filter`.
 *
 * @param[in] x Parameter passed to the function.
 * @return uint8_t
 */
static uint8_t poom_crypto1_filter(uint32_t x)
{
    uint32_t f;
    f = (0xF22C0U >> (x & 0xFU)) & 16U;
    f |= (0x6C9C0U >> ((x >> 4) & 0xFU)) & 8U;
    f |= (0x3C8B0U >> ((x >> 8) & 0xFU)) & 4U;
    f |= (0x1E458U >> ((x >> 12) & 0xFU)) & 2U;
    f |= (0x0D938U >> ((x >> 16) & 0xFU)) & 1U;
    return POOM_BIT(0xEC57E80AU, f);
}

/**
 * @brief Internal helper for `poom_crypto1_init`.
 *
 * @param[in] s Parameter passed to the function.
 * @param[in] key Parameter passed to the function.
 * @return void
 */
static void poom_crypto1_init(poom_crypto1_state_t* s,
                              const uint8_t key[POOM_MIFARE_KEY_SIZE])
{
    uint64_t k = 0;
    int i;

    s->odd  = 0;
    s->even = 0;

    for(i = 0; i < POOM_MIFARE_KEY_SIZE; i++)
    {
        k = (k << 8) | key[i];
    }

    for(i = 47; i > 0; i -= 2)
    {
        s->odd  = (s->odd << 1) | POOM_BIT(k, (uint8_t)((i - 1) ^ 7));
        s->even = (s->even << 1) | POOM_BIT(k, (uint8_t)(i ^ 7));
    }
}

/**
 * @brief Internal helper for `poom_crypto1_bit`.
 *
 * @param[in] s Parameter passed to the function.
 * @param[in] in Parameter passed to the function.
 * @param[in] is_encrypted Parameter passed to the function.
 * @return uint8_t
 */
static uint8_t poom_crypto1_bit(poom_crypto1_state_t* s,
                                uint8_t in,
                                int is_encrypted)
{
    uint8_t ret     = poom_crypto1_filter(s->odd);
    uint32_t feedin = (uint32_t)ret & (uint32_t) !!is_encrypted;
    uint32_t x;

    feedin ^= (uint32_t) !!in;
    feedin ^= (POOM_LF_POLY_ODD & s->odd);
    feedin ^= (POOM_LF_POLY_EVEN & s->even);

    s->even = (s->even << 1) | (uint32_t)poom_oddparity32(feedin);
    x       = s->odd;
    s->odd  = s->even;
    s->even = x;

    return ret;
}

/**
 * @brief Internal helper for `poom_crypto1_word`.
 *
 * @param[in] s Parameter passed to the function.
 * @param[in] in Parameter passed to the function.
 * @param[in] is_encrypted Parameter passed to the function.
 * @return uint32_t
 */
static uint32_t poom_crypto1_word(poom_crypto1_state_t* s,
                                  uint32_t in,
                                  int is_encrypted)
{
    uint32_t i;
    uint32_t ret = 0;

    for(i = 0; i < 32; i++)
    {
        ret |= (uint32_t)poom_crypto1_bit(s, POOM_BEBIT(in, i), is_encrypted)
               << (24U ^ i);
    }
    return ret;
}

/**
 * @brief Internal helper for `poom_mifare_oddparity_bit8`.
 *
 * @param[in] x Parameter passed to the function.
 * @return uint8_t
 */
static uint8_t poom_mifare_oddparity_bit8_(uint8_t x)
{
    return (uint8_t)!__builtin_parity((uint32_t)x);
}

/**
 * @brief Internal helper for `poom_mifare_crc_a_calc`.
 *
 * @param[in] data Parameter passed to the function.
 * @param[in] len Parameter passed to the function.
 * @param[in] out Parameter passed to the function.
 * @return void
 */
static void poom_mifare_crc_a_calc_(const uint8_t* data, size_t len, uint8_t out[2])
{
    uint16_t crc = 0x6363U;

    if(out == NULL)
    {
        return;
    }

    if(data != NULL)
    {
        for(size_t i = 0; i < len; i++)
        {
            uint8_t d = data[i];
            for(uint8_t b = 0; b < 8U; b++)
            {
                uint8_t mix = (uint8_t)((crc ^ d) & 0x01U);
                crc >>= 1;
                if(mix != 0U)
                {
                    crc ^= 0x8408U;
                }
                d >>= 1;
            }
        }
    }

    out[0] = (uint8_t)(crc & 0xFFU);
    out[1] = (uint8_t)((crc >> 8) & 0xFFU);
}

/**
 * @brief Internal helper for `poom_mifare_crc_a_check`.
 *
 * @param[in] data Parameter passed to the function.
 * @param[in] len Parameter passed to the function.
 * @return bool
 */
static bool poom_mifare_crc_a_check_(const uint8_t* data, size_t len)
{
    uint8_t crc[2];

    if(data == NULL || len < 3U)
    {
        return false;
    }

    poom_mifare_crc_a_calc_(data, len - 2U, crc);
    return (crc[0] == data[len - 2U]) && (crc[1] == data[len - 1U]);
}

/**
 * @brief Internal helper for `poom_mifare_build_crypto_tx_bits`.
 *
 * @param[in] st Parameter passed to the function.
 * @param[in] plain Parameter passed to the function.
 * @param[in] plain_len Parameter passed to the function.
 * @param[in] out_bits Parameter passed to the function.
 * @param[in] out_bits_buf_len Parameter passed to the function.
 * @param[in] out_bits_len Parameter passed to the function.
 * @return bool
 */
static bool poom_mifare_build_crypto_tx_bits_(poom_crypto1_state_t* st,
                                              const uint8_t* plain,
                                              size_t plain_len,
                                              uint8_t* out_bits,
                                              uint16_t out_bits_buf_len,
                                              uint16_t* out_bits_len)
{
    uint8_t frame[32];
    uint8_t crc[2];
    size_t frame_len;
    uint16_t bit_pos = 0U;
    uint16_t bits_needed;
    uint16_t bytes_needed;

    if(out_bits_len != NULL)
    {
        *out_bits_len = 0U;
    }
    if(st == NULL || plain == NULL || plain_len == 0U || out_bits == NULL || out_bits_len == NULL)
    {
        return false;
    }
    if(plain_len > (sizeof(frame) - 2U))
    {
        return false;
    }

    memcpy(frame, plain, plain_len);
    poom_mifare_crc_a_calc_(plain, plain_len, crc);
    frame[plain_len]     = crc[0];
    frame[plain_len + 1] = crc[1];
    frame_len = plain_len + 2U;

    bits_needed  = (uint16_t)(frame_len * POOM_MIFARE_AUTH_BITS_PER_BYTE);
    bytes_needed = (uint16_t)rfalConvBitsToBytes(bits_needed);
    if(bytes_needed > out_bits_buf_len)
    {
        return false;
    }

    memset(out_bits, 0, out_bits_buf_len);
    for(size_t i = 0U; i < frame_len; i++)
    {
        const uint8_t byte = frame[i];
        const uint8_t parity_plain = poom_mifare_oddparity_bit8_(byte);

        for(uint8_t b = 0U; b < 8U; b++)
        {
            const uint8_t plain_bit = (uint8_t)((byte >> b) & 0x01U);
            const uint8_t ks = poom_crypto1_bit(st, 0U, 0);
            const uint8_t cbit = (uint8_t)(plain_bit ^ ks);
            poom_bits_set(out_bits, bit_pos++, cbit);
        }

        {
            const uint8_t cpar =
                (uint8_t)(parity_plain ^ poom_crypto1_keystream_peek(st));
            poom_bits_set(out_bits, bit_pos++, cpar);
        }
    }

    *out_bits_len = bit_pos;
    return true;
}

/**
 * @brief Internal helper for `poom_mifare_decode_crypto_rx_bits`.
 *
 * @param[in] st Parameter passed to the function.
 * @param[in] in_bits Parameter passed to the function.
 * @param[in] in_bits_len Parameter passed to the function.
 * @param[in] out_plain Parameter passed to the function.
 * @param[in] out_plain_cap Parameter passed to the function.
 * @param[in] out_plain_len Parameter passed to the function.
 * @return bool
 */
static bool poom_mifare_decode_crypto_rx_bits_(poom_crypto1_state_t* st,
                                               const uint8_t* in_bits,
                                               uint16_t in_bits_len,
                                               uint8_t* out_plain,
                                               size_t out_plain_cap,
                                               size_t* out_plain_len)
{
    uint16_t bit_pos = 0U;
    const uint16_t symbols = (uint16_t)(in_bits_len / POOM_MIFARE_AUTH_BITS_PER_BYTE);

    if(out_plain_len != NULL)
    {
        *out_plain_len = 0U;
    }
    if(st == NULL || in_bits == NULL || in_bits_len == 0U || out_plain == NULL || out_plain_len == NULL)
    {
        return false;
    }
    if(symbols == 0U || symbols > out_plain_cap)
    {
        return false;
    }

    for(uint16_t i = 0U; i < symbols; i++)
    {
        uint8_t value = 0U;
        for(uint8_t b = 0U; b < 8U; b++)
        {
            const uint8_t cbit = poom_bits_get(in_bits, bit_pos++);
            const uint8_t ks = poom_crypto1_bit(st, 0U, 0);
            const uint8_t plain_bit = (uint8_t)(cbit ^ ks);
            value |= (uint8_t)(plain_bit << b);
        }

        {
            const uint8_t cpar = poom_bits_get(in_bits, bit_pos++);
            const uint8_t ppar =
                (uint8_t)(cpar ^ poom_crypto1_keystream_peek(st));
            if(ppar != poom_mifare_oddparity_bit8_(value))
            {
            }
        }

        out_plain[i] = value;
    }

    *out_plain_len = symbols;
    return true;
}

/**
 * @brief Internal helper for `poom_mifare_decode_crypto_ack4`.
 *
 * @param[in] st Parameter passed to the function.
 * @param[in] in_bits Parameter passed to the function.
 * @param[in] in_bits_len Parameter passed to the function.
 * @param[in] out_nibble Parameter passed to the function.
 * @return bool
 */
static bool poom_mifare_decode_crypto_ack4_(poom_crypto1_state_t* st,
                                           const uint8_t* in_bits,
                                           uint16_t in_bits_len,
                                           uint8_t* out_nibble)
{
    uint8_t nibble = 0U;

    if(out_nibble != NULL)
    {
        *out_nibble = 0U;
    }
    if(st == NULL || in_bits == NULL || out_nibble == NULL)
    {
        return false;
    }
    if(in_bits_len < 4U)
    {
        return false;
    }

    for(uint8_t i = 0U; i < 4U; i++)
    {
        const uint8_t cbit = poom_bits_get(in_bits, i);
        const uint8_t ks = poom_crypto1_bit(st, 0U, 0);
        const uint8_t plain_bit = (uint8_t)(cbit ^ ks);
        nibble |= (uint8_t)(plain_bit << i);
    }

    *out_nibble = nibble;
    return true;
}

/**
 * @brief Internal helper for `poom_mifare_crypto_read_block`.
 *
 * @param[in] block Parameter passed to the function.
 * @param[in] st Parameter passed to the function.
 * @param[in] out16 Parameter passed to the function.
 * @return bool
 */
static bool poom_mifare_crypto_read_block_(uint8_t block,
                                           poom_crypto1_state_t* st,
                                           uint8_t out16[16])
{
    uint8_t cmd[2];
    uint8_t tx_bits[POOM_MIFARE_TXRX_BITS_BUF_MAX];
    uint8_t rx_bits[POOM_MIFARE_TXRX_BITS_BUF_MAX];
    uint8_t plain[32];
    uint16_t tx_bits_len = 0U;
    uint16_t rx_bits_len = 0U;
    size_t plain_len = 0U;
    ReturnCode rc;

    if(st == NULL || out16 == NULL)
    {
        return false;
    }

    cmd[0] = (uint8_t)POOM_MIFARE_CMD_READ;
    cmd[1] = block;

    if(!poom_mifare_build_crypto_tx_bits_(st, cmd, sizeof(cmd), tx_bits, sizeof(tx_bits), &tx_bits_len))
    {
        return false;
    }

    rc = poom_mifare_transceive_step2_bits_with_manual_parity(
        tx_bits, tx_bits_len, rx_bits, sizeof(rx_bits), &rx_bits_len);

    if(!poom_mifare_is_expected_raw_rx_rc_(rc))
    {
        return false;
    }

    if(!poom_mifare_decode_crypto_rx_bits_(st, rx_bits, rx_bits_len, plain, sizeof(plain), &plain_len))
    {
        return false;
    }
    if(plain_len != 18U)
    {
        return false;
    }
    if(!poom_mifare_crc_a_check_(plain, plain_len))
    {
        return false;
    }

    memcpy(out16, plain, 16);
    return true;
}

/**
 * @brief Internal helper for `poom_mifare_crypto_write_block`.
 *
 * @param[in] block Parameter passed to the function.
 * @param[in] st Parameter passed to the function.
 * @param[in] data16 Parameter passed to the function.
 * @return bool
 */
static bool poom_mifare_crypto_write_block_(uint8_t block,
                                            poom_crypto1_state_t* st,
                                            const uint8_t data16[16])
{
    uint8_t cmd[2];
    uint8_t tx_bits[POOM_MIFARE_TXRX_BITS_BUF_MAX];
    uint8_t rx_bits[POOM_MIFARE_TXRX_BITS_BUF_MAX];
    uint8_t plain_data[16];
    uint16_t tx_bits_len = 0U;
    uint16_t rx_bits_len = 0U;
    uint8_t ack = 0U;
    ReturnCode rc;

    if(st == NULL || data16 == NULL)
    {
        return false;
    }

    cmd[0] = (uint8_t)POOM_MIFARE_CMD_WRITE;
    cmd[1] = block;

    if(!poom_mifare_build_crypto_tx_bits_(st, cmd, sizeof(cmd), tx_bits, sizeof(tx_bits), &tx_bits_len))
    {
        return false;
    }

    rc = poom_mifare_transceive_step2_bits_with_manual_parity(
        tx_bits, tx_bits_len, rx_bits, sizeof(rx_bits), &rx_bits_len);
    if(!poom_mifare_is_expected_raw_rx_rc_(rc))
    {
        return false;
    }
    if(!poom_mifare_decode_crypto_ack4_(st, rx_bits, rx_bits_len, &ack))
    {
        printf("  mifare write: card did not return WRITE ack for block %u\r\n",
               (unsigned)block);
        return false;
    }
    if(ack != 0x0AU)
    {
        printf("  mifare write: card rejected WRITE command on block %u "
               "(ack=%02X)\r\n",
               (unsigned)block, (unsigned)ack);
        return false;
    }

    memcpy(plain_data, data16, sizeof(plain_data));
    if(!poom_mifare_build_crypto_tx_bits_(st, plain_data, sizeof(plain_data), tx_bits, sizeof(tx_bits), &tx_bits_len))
    {
        return false;
    }

    rc = poom_mifare_transceive_step2_bits_with_manual_parity(
        tx_bits, tx_bits_len, rx_bits, sizeof(rx_bits), &rx_bits_len);
    if(!poom_mifare_is_expected_raw_rx_rc_(rc))
    {
        return false;
    }
    if(!poom_mifare_decode_crypto_ack4_(st, rx_bits, rx_bits_len, &ack))
    {
        printf("  mifare write: card did not return data ack for block %u\r\n",
               (unsigned)block);
        return false;
    }
    if(ack != 0x0AU)
    {
        printf("  mifare write: card rejected data for block %u (ack=%02X)\r\n",
               (unsigned)block, (unsigned)ack);
        return false;
    }

    return true;
}

/**
 * @brief Internal helper for `poom_mifare_prepare_crypto1_session`.
 *
 * @param[in] s Parameter passed to the function.
 * @param[in] block Parameter passed to the function.
 * @param[in] key_type Parameter passed to the function.
 * @param[in] key Parameter passed to the function.
 * @param[in] nt Parameter passed to the function.
 * @return bool
 */
static bool poom_mifare_prepare_crypto1_session(
    poom_mifare_crypto1_session_t* s,
    uint8_t block,
    poom_mifare_key_type_t key_type,
    const uint8_t key[POOM_MIFARE_KEY_SIZE],
    const uint8_t nt[4])
{
    if(s == NULL || key == NULL || nt == NULL)
        return false;
    if(!s_mf_ctx.active || s_mf_ctx.uid_len == 0 ||
       s_mf_ctx.uid_len > POOM_MIFARE_UID_MAX)
        return false;

    memset(s, 0, sizeof(*s));
    memcpy(s->key, key, POOM_MIFARE_KEY_SIZE);
    memcpy(s->uid, s_mf_ctx.uid, s_mf_ctx.uid_len);
    s->uid_len  = s_mf_ctx.uid_len;
    s->block    = block;
    s->key_type = key_type;
    memcpy(s->nt, nt, 4);
    poom_u32_to_be(esp_random(), s->nr);
    return true;
}

/**
 * @brief Internal helper for `poom_mifare_run_crypto1_auth`.
 *
 * @param[in] s Parameter passed to the function.
 * @param[in] out_state_after_auth Parameter passed to the function.
 * @return bool
 */
static bool poom_mifare_run_crypto1_auth(const poom_mifare_crypto1_session_t* s,
                                         poom_crypto1_state_t* out_state_after_auth)
{
    poom_crypto1_state_t st;
    uint8_t nr_be[4];
    uint8_t ar_be[4];
    uint8_t tx_bits[POOM_MIFARE_TXRX_BITS_BUF_MAX];
    uint8_t rx_bits[POOM_MIFARE_TXRX_BITS_BUF_MAX];
    uint8_t at_be[4];
    uint16_t tx_bits_len = 0;
    uint16_t rx_bits_len = 0;
    uint32_t uid;
    uint32_t nt;
    uint32_t nr;
    uint32_t ar;
    uint32_t at_expected;
    uint32_t at;
    ReturnCode rc;

    if(s == NULL)
        return false;
    if(s->uid_len < 4U)
    {
        printf("  mifare crypto1: unsupported UID length %u\r\n", s->uid_len);
        return false;
    }

    uid         = poom_u32_from_be(s->uid); /* Classic/Mini uses 4-byte UID */
    nt          = poom_u32_from_be(s->nt);
    nr          = poom_u32_from_be(s->nr);
    ar          = poom_mifare_prng_successor(nt, 64U);
    at_expected = poom_mifare_prng_successor(nt, 96U);

#if POOM_MIFARE_TRACE
    printf("  [mf-trace] uid=%08lX nt=%08lX nr=%08lX ar=%08lX at_exp=%08lX\r\n",
           (unsigned long)uid, (unsigned long)nt, (unsigned long)nr,
           (unsigned long)ar, (unsigned long)at_expected);
#endif

    poom_crypto1_init(&st, s->key);
    (void)poom_crypto1_word(&st, uid ^ nt, 0);

    poom_u32_to_be(nr, nr_be);
    poom_u32_to_be(ar, ar_be);

    if(!poom_mifare_build_step2_bits(&st, nr_be, ar_be, tx_bits,
                                     sizeof(tx_bits), &tx_bits_len))
    {
        printf("  mifare crypto1: could not build step2 frame\r\n");
        return false;
    }

    s_crypto1_link_limit = false;
    poom_trace_hex("step2-nr-be", nr_be, sizeof(nr_be));
    poom_trace_hex("step2-ar-be", ar_be, sizeof(ar_be));
    poom_trace_bits("step2-tx", tx_bits, tx_bits_len);

    rc = poom_mifare_transceive_step2_bits_with_manual_parity(
        tx_bits, tx_bits_len, rx_bits, sizeof(rx_bits), &rx_bits_len);

    poom_trace_bits("step3-rx", rx_bits, rx_bits_len);

    if(!poom_mifare_is_expected_raw_rx_rc_(rc))
    {
        if(rc == RFAL_ERR_TIMEOUT && rx_bits_len == 0U)
        {
            s_crypto1_link_limit = false;
            printf("  mifare crypto1: step2 timeout/no response "
                   "(possible wrong key or link/parity issue) (err=%d len=%u).\r\n",
                   rc, rx_bits_len);
            return false;
        }

        if(rc == RFAL_ERR_WRONG_STATE || rc == RFAL_ERR_NOTSUPP ||
           rc == RFAL_ERR_REQUEST)
        {
            s_crypto1_link_limit = true;
        }

        printf("  mifare crypto1: step2 transceive failed err=%d len=%u\r\n",
               rc, rx_bits_len);
        return false;
    }
    if(rx_bits_len < (4U * POOM_MIFARE_AUTH_BITS_PER_BYTE))
    {
        printf("  mifare crypto1: step3 response too short len=%u bits\r\n",
               rx_bits_len);
        return false;
    }

    if(!poom_mifare_decode_step3_bits(&st, rx_bits, rx_bits_len, at_be))
    {
        printf("  mifare crypto1: step3 could not decode parity stream\r\n");
        return false;
    }

    at = poom_u32_from_be(at_be);
    poom_trace_hex("step3-at-be", at_be, sizeof(at_be));
#if POOM_MIFARE_TRACE
    printf("  [mf-trace] at_dec=%08lX at_exp=%08lX\r\n",
           (unsigned long)at, (unsigned long)at_expected);
#endif

    if(at != at_expected && poom_bswap32(at) != at_expected &&
       at != poom_bswap32(at_expected))
    {
        printf("  mifare crypto1: AT mismatch at=%08lX expected=%08lX\r\n",
               (unsigned long)at, (unsigned long)at_expected);
        return false;
    }

    if(!s_mifare_discover_quiet)
    {
        printf("  mifare auth full OK: key %c valid on block %u\r\n",
               (s->key_type == POOM_MIFARE_KEY_A) ? 'A' : 'B', s->block);
    }
    if(out_state_after_auth != NULL)
    {
        memcpy(out_state_after_auth, &st, sizeof(*out_state_after_auth));
    }
    return true;
}

/**
 * @brief Internal helper for `poom_mifare_is_valid_key_type`.
 *
 * @param[in] key_type Parameter passed to the function.
 * @return bool
 */
static bool poom_mifare_is_valid_key_type(poom_mifare_key_type_t key_type)
{
    return (key_type == POOM_MIFARE_KEY_A) || (key_type == POOM_MIFARE_KEY_B);
}

/**
 * @brief Internal helper for `poom_mifare_max_block_for_type`.
 *
 * @param[in] card_type Parameter passed to the function.
 * @return uint16_t
 */
static uint16_t poom_mifare_max_block_for_type(nfc_card_type_t card_type)
{
    switch(card_type)
    {
        case NFC_CARD_MIFARE_MINI:
            return 19; /* 5 sectors x 4 blocks */
        case NFC_CARD_MIFARE_CLASSIC_1K:
            return 63; /* 16 sectors x 4 blocks */
        case NFC_CARD_MIFARE_CLASSIC_4K:
            return 255; /* 32x4 + 8x16 blocks */
        default:
            return 255;
    }
}

/**
 * @brief Internal helper for `poom_mifare_bind_active_if_possible`.
 *
 * @return bool
 */
static bool poom_mifare_bind_active_if_possible(void)
{
    rfalNfcDevice* dev = NULL;
    ReturnCode rc      = rfalNfcGetActiveDevice(&dev);
    poom_nfc_profile_t profile;

    if(rc != ERR_NONE || dev == NULL)
    {
        if(!poom_reader_get_last_profile(&profile))
            return false;
        if(profile.uid_len == 0U || profile.uid_len > POOM_MIFARE_UID_MAX ||
           !profile.atqa_set || !profile.sak_set)
            return false;

        {
            uint16_t atqa = (uint16_t)(((uint16_t)profile.atqa[1] << 8) |
                                       (uint16_t)profile.atqa[0]);
            uint8_t sak        = profile.sak;
            nfc_card_type_t ct = nfc_ident_detect_nfca(atqa, sak);

            if(!poom_mifare_classic_is_supported_card(ct))
                return false;
            if(!poom_mifare_classic_bind_card(profile.uid, profile.uid_len, ct))
                return false;

            s_mf_ctx.atqa_sak_set = true;
            s_mf_ctx.atqa = atqa;
            s_mf_ctx.sak  = sak;
            return true;
        }
    }
    if(dev->type != RFAL_NFC_LISTEN_TYPE_NFCA)
        return false;
    if(dev->nfcid == NULL || dev->nfcidLen == 0 ||
       dev->nfcidLen > POOM_MIFARE_UID_MAX)
        return false;

    uint16_t atqa = ((uint16_t)dev->dev.nfca.sensRes.platformInfo << 8) |
                    (uint16_t)dev->dev.nfca.sensRes.anticollisionInfo;
    uint8_t sak        = dev->dev.nfca.selRes.sak;
    nfc_card_type_t ct = nfc_ident_detect_nfca(atqa, sak);

    if(!poom_mifare_classic_is_supported_card(ct))
        return false;
    if(!poom_mifare_classic_bind_card(dev->nfcid, dev->nfcidLen, ct))
    {
        return false;
    }

    s_mf_ctx.atqa_sak_set = true;
    s_mf_ctx.atqa = atqa;
    s_mf_ctx.sak  = sak;
    return true;
}

/**
 * @brief Internal helper for `poom_mifare_prepare_selected_card`.
 *
 * @return bool
 */
static bool poom_mifare_prepare_selected_card(void)
{
    uint8_t tx[2 + POOM_NFCA_UID_BCC_LEN];
    uint8_t rx[16];
    uint8_t uid_cl1[4];
    uint16_t rx_len = 0;
    rfalNfcaSensRes sens_res;
    rfalNfcaSelRes sel_res;
    ReturnCode rc;

    if(!s_mf_ctx.active || s_mf_ctx.uid_len == 0)
    {
        if(!poom_mifare_bind_active_if_possible())
        {
            rc = rfalNfcaPollerInitialize();
            if(rc != ERR_NONE)
            {
                printf("  mifare auth: poller init failed err=%d\r\n", rc);
                return false;
            }

            rfalFieldOff();
            rfalFieldOnAndStartGT();

            rc = rfalNfcaPollerCheckPresence(RFAL_14443A_SHORTFRAME_CMD_WUPA,
                                             &sens_res);
            if(rc != ERR_NONE)
            {
                printf("  mifare auth: WUPA failed err=%d\r\n", rc);
                return false;
            }

            tx[0] = POOM_NFCA_SEL_CL1;
            tx[1] = POOM_NFCA_ANTICOLLISION;
            rc    = rfalTransceiveBlockingTxRx(
                   tx, 2, rx, sizeof(rx), &rx_len,
                   (uint32_t)RFAL_TXRX_FLAGS_CRC_TX_MANUAL |
                       (uint32_t)RFAL_TXRX_FLAGS_CRC_RX_KEEP |
                       (uint32_t)RFAL_TXRX_FLAGS_CRC_RX_MANUAL,
                   POOM_MIFARE_TXRX_TIMEOUT_TICKS);
            if(rc != ERR_NONE || rx_len < POOM_NFCA_UID_BCC_LEN)
            {
                printf("  mifare auth: anticollision failed err=%d len=%u\r\n",
                       rc, rx_len);
                return false;
            }
            memcpy(uid_cl1, rx, sizeof(uid_cl1));

            tx[0] = POOM_NFCA_SEL_CL1;
            tx[1] = POOM_NFCA_SELECT;
            memcpy(&tx[2], rx, POOM_NFCA_UID_BCC_LEN);
            rc = rfalTransceiveBlockingTxRx(
                tx, (uint16_t)(2 + POOM_NFCA_UID_BCC_LEN), rx, sizeof(rx),
                &rx_len, RFAL_TXRX_FLAGS_DEFAULT,
                POOM_MIFARE_TXRX_TIMEOUT_TICKS);
            if(rc != ERR_NONE || rx_len < 1U)
            {
                printf("  mifare auth: select failed err=%d len=%u\r\n", rc,
                       rx_len);
                return false;
            }

            {
                uint16_t atqa = ((uint16_t)sens_res.platformInfo << 8) |
                                (uint16_t)sens_res.anticollisionInfo;
                uint8_t sak        = rx[0];
                nfc_card_type_t ct = nfc_ident_detect_nfca(atqa, sak);

                if(!poom_mifare_classic_is_supported_card(ct))
                {
                    printf("  mifare auth: unsupported card type after select "
                           "(%s)\r\n",
                           nfc_ident_card_type_to_str(ct));
                    return false;
                }

                if(!poom_mifare_classic_bind_card(uid_cl1, sizeof(uid_cl1), ct))
                {
                    printf(
                        "  mifare auth: bind after anticollision failed\r\n");
                    return false;
                }
            }
        }
    }

    if(!s_mf_ctx.active || s_mf_ctx.uid_len == 0)
    {
        printf("  mifare auth: no selected card context\r\n");
        return false;
    }

    rc = rfalNfcaPollerInitialize();
    if(rc != ERR_NONE)
    {
        printf("  mifare auth: poller init failed err=%d\r\n", rc);
        return false;
    }

    rfalFieldOff();
    rfalFieldOnAndStartGT();

    rc =
        rfalNfcaPollerCheckPresence(RFAL_14443A_SHORTFRAME_CMD_WUPA, &sens_res);
    if(rc != ERR_NONE)
    {
        printf("  mifare auth: WUPA failed err=%d\r\n", rc);
        return false;
    }

    rc = rfalNfcaPollerSelect(s_mf_ctx.uid, s_mf_ctx.uid_len, &sel_res);
    if(rc != ERR_NONE)
    {
        ReturnCode rc_sel = rc;

        tx[0] = POOM_NFCA_SEL_CL1;
        tx[1] = POOM_NFCA_ANTICOLLISION;
        rc    = rfalTransceiveBlockingTxRx(
               tx, 2, rx, sizeof(rx), &rx_len,
               (uint32_t)RFAL_TXRX_FLAGS_CRC_TX_MANUAL |
                   (uint32_t)RFAL_TXRX_FLAGS_CRC_RX_KEEP |
                   (uint32_t)RFAL_TXRX_FLAGS_CRC_RX_MANUAL,
               POOM_MIFARE_TXRX_TIMEOUT_TICKS);
        if(rc == ERR_NONE && rx_len >= POOM_NFCA_UID_BCC_LEN)
        {
            uint16_t atqa;
            uint8_t sak;
            nfc_card_type_t ct;

            memcpy(uid_cl1, rx, sizeof(uid_cl1));

            tx[0] = POOM_NFCA_SEL_CL1;
            tx[1] = POOM_NFCA_SELECT;
            memcpy(&tx[2], rx, POOM_NFCA_UID_BCC_LEN);
            rc = rfalTransceiveBlockingTxRx(
                tx, (uint16_t)(2 + POOM_NFCA_UID_BCC_LEN), rx, sizeof(rx),
                &rx_len, RFAL_TXRX_FLAGS_DEFAULT,
                POOM_MIFARE_TXRX_TIMEOUT_TICKS);
            if(rc == ERR_NONE && rx_len >= 1U)
            {
                atqa = ((uint16_t)sens_res.platformInfo << 8) |
                       (uint16_t)sens_res.anticollisionInfo;
                sak = rx[0];
                ct  = nfc_ident_detect_nfca(atqa, sak);

                if(poom_mifare_classic_is_supported_card(ct) &&
                   poom_mifare_classic_bind_card(uid_cl1, sizeof(uid_cl1), ct))
                {
                    s_mf_ctx.atqa_sak_set = true;
                    s_mf_ctx.atqa = atqa;
                    s_mf_ctx.sak  = sak;
                    printf("  mifare auth: select recovery OK (uid refreshed)\r\n");
                    return true;
                }
            }
        }

        printf("  mifare auth: select failed err=%d\r\n", rc_sel);
        return false;
    }

    s_mf_ctx.atqa_sak_set = true;
    s_mf_ctx.atqa = ((uint16_t)sens_res.platformInfo << 8) |
                    (uint16_t)sens_res.anticollisionInfo;
    s_mf_ctx.sak  = sel_res.sak;
    return true;
}

/**
 * @brief Internal helper for auth progress verbosity.
 *
 * @param[in] assume_selected Parameter passed to the function.
 * @return bool
 */
static bool poom_mifare_should_print_auth_progress_(bool assume_selected)
{
    return !assume_selected && !s_mifare_discover_quiet;
}

/**
 * @brief Internal helper for `poom_mifare_classic_auth_internal`.
 *
 * @param[in] block Parameter passed to the function.
 * @param[in] key_type Parameter passed to the function.
 * @param[in] key Parameter passed to the function.
 * @param[in] assume_selected Parameter passed to the function.
 * @param[in] out_state_after_auth Parameter passed to the function.
 * @return bool
 */
static bool poom_mifare_classic_auth_internal_(uint8_t block,
                                               poom_mifare_key_type_t key_type,
                                               const uint8_t key[6],
                                               bool assume_selected,
                                               poom_crypto1_state_t* out_state_after_auth)
{
    poom_mifare_crypto1_session_t session;
    uint8_t tx[2];
    uint8_t rx[16];
    uint16_t rx_len = 0;
    ReturnCode rc;

    if(key == NULL)
    {
        printf("  mifare auth: key is NULL\r\n");
        return false;
    }
    if(!poom_mifare_is_valid_key_type(key_type))
    {
        printf("  mifare auth: invalid key type\r\n");
        return false;
    }

    s_mf_ctx.last_auth_attempted  = true;
    s_mf_ctx.auth_step1_ok        = false;
    s_mf_ctx.last_auth_partial_ok = false;
    s_mf_ctx.last_auth_full_ok    = false;

    if(!s_mf_ctx.active)
    {
        (void)poom_mifare_bind_active_if_possible();
    }

    if(s_mf_ctx.active)
    {
        uint16_t max_block = poom_mifare_max_block_for_type(s_mf_ctx.card_type);
        if((uint16_t)block > max_block)
        {
            printf("  mifare auth: block %u out of range for %s (max %u)\r\n",
                   block, nfc_ident_card_type_to_str(s_mf_ctx.card_type),
                   max_block);
            return false;
        }
    }

    if(!assume_selected)
    {
        if(rfalGetMode() != RFAL_MODE_POLL_NFCA)
        {
            printf("  mifare auth: RFAL mode is not NFC-A, trying recovery via "
                   "NFCA poller.\r\n");
        }

        if(!poom_mifare_prepare_selected_card())
        {
            printf("  mifare auth: could not prepare selected card for AUTH\r\n");
            return false;
        }
    }

    tx[0] = (uint8_t)key_type; /* 0x60 Auth A / 0x61 Auth B */
    tx[1] = block;

    rc =
        rfalTransceiveBlockingTxRx(tx, sizeof(tx), rx, sizeof(rx), &rx_len,
                                   (uint32_t)RFAL_TXRX_FLAGS_DEFAULT |
                                       (uint32_t)RFAL_TXRX_FLAGS_CRC_RX_MANUAL |
                                       (uint32_t)RFAL_TXRX_FLAGS_CRC_RX_KEEP,
                                   POOM_MIFARE_TXRX_TIMEOUT_TICKS);

#if POOM_MIFARE_TRACE
    printf("  [mf-trace] step1 rc=%d rx_len=%u\r\n", rc, rx_len);
    poom_trace_hex("step1-rx", rx, rx_len);
#endif

    if(rc != ERR_NONE)
    {
        if(!(rc == RFAL_ERR_CRC && rx_len >= POOM_MIFARE_AUTH_RESP_LEN))
        {
            if(poom_mifare_should_print_auth_progress_(assume_selected))
            {
                printf("  mifare auth step1 failed: transceive err=%d\r\n", rc);
            }
            return false;
        }
        if(poom_mifare_should_print_auth_progress_(assume_selected))
        {
            printf("  mifare auth step1: nonce received with CRC warning (err=%d), "
                   "continuing.\r\n",
                   rc);
        }
    }
    if(rx_len < POOM_MIFARE_AUTH_RESP_LEN)
    {
        if(poom_mifare_should_print_auth_progress_(assume_selected))
        {
            printf(
                "  mifare auth step1 failed: expected >=%u bytes nonce, got %u\r\n",
                POOM_MIFARE_AUTH_RESP_LEN, rx_len);
        }
        return false;
    }

    s_mf_ctx.auth_step1_ok = true;
    s_mf_ctx.last_block    = block;
    s_mf_ctx.last_key_type = key_type;
    memcpy(s_mf_ctx.last_nonce, rx, POOM_MIFARE_AUTH_RESP_LEN);

    if(poom_mifare_should_print_auth_progress_(assume_selected))
    {
        printf("  mifare auth step1 OK: Nt=%02X%02X%02X%02X\r\n",
               s_mf_ctx.last_nonce[0], s_mf_ctx.last_nonce[1],
               s_mf_ctx.last_nonce[2], s_mf_ctx.last_nonce[3]);
    }

    if(!poom_mifare_prepare_crypto1_session(&session, block, key_type, key,
                                            s_mf_ctx.last_nonce))
    {
        if(poom_mifare_should_print_auth_progress_(assume_selected))
        {
            printf("  mifare auth: failed to prepare Crypto1 session context.\r\n");
        }
        return false;
    }

    if(!poom_mifare_full_crypto1_ready())
    {
        s_mf_ctx.last_auth_partial_ok = true;
        if(poom_mifare_should_print_auth_progress_(assume_selected))
        {
            printf("  mifare auth partial: step1 OK. Crypto1 final validation "
                   "pending.\r\n");
        }
        return false;
    }

    if(poom_mifare_run_crypto1_auth(&session, out_state_after_auth))
    {
        s_mf_ctx.last_auth_full_ok = true;
        return true;
    }

    if(s_crypto1_link_limit)
    {
        s_mf_ctx.last_auth_partial_ok = true;
        if(poom_mifare_should_print_auth_progress_(assume_selected))
        {
            printf("  mifare auth partial: step1 OK, step2 blocked by current RFAL "
                   "link/parity path.\r\n");
        }
        return false;
    }

    return false;
}

void poom_mifare_classic_init(void)
{
    memset(&s_mf_ctx, 0, sizeof(s_mf_ctx));
    poom_mifare_block_cache_release_();
    memset(s_sector_key_a_valid, 0, sizeof(s_sector_key_a_valid));
    memset(s_sector_key_b_valid, 0, sizeof(s_sector_key_b_valid));
    memset(s_sector_key_a, 0, sizeof(s_sector_key_a));
    memset(s_sector_key_b, 0, sizeof(s_sector_key_b));
    memset(s_last_key_a, 0, sizeof(s_last_key_a));
    memset(s_last_key_b, 0, sizeof(s_last_key_b));
    s_last_key_a_valid = false;
    s_last_key_b_valid = false;
}

void poom_mifare_classic_reset(void)
{
    poom_mifare_classic_init();
}

bool poom_mifare_classic_is_supported_card(nfc_card_type_t card_type)
{
    return (card_type == NFC_CARD_MIFARE_MINI) ||
           (card_type == NFC_CARD_MIFARE_CLASSIC_1K) ||
           (card_type == NFC_CARD_MIFARE_CLASSIC_4K);
}

bool poom_mifare_classic_bind_card(const uint8_t* uid,
                                   uint8_t uid_len,
                                   nfc_card_type_t card_type)
{
    if(!uid || uid_len == 0 || uid_len > POOM_MIFARE_UID_MAX)
        return false;
    if(!poom_mifare_classic_is_supported_card(card_type))
        return false;

    poom_mifare_block_cache_clear_();
    memset(s_sector_key_a_valid, 0, sizeof(s_sector_key_a_valid));
    memset(s_sector_key_b_valid, 0, sizeof(s_sector_key_b_valid));
    memset(s_sector_key_a, 0, sizeof(s_sector_key_a));
    memset(s_sector_key_b, 0, sizeof(s_sector_key_b));
    memset(s_last_key_a, 0, sizeof(s_last_key_a));
    memset(s_last_key_b, 0, sizeof(s_last_key_b));
    s_last_key_a_valid = false;
    s_last_key_b_valid = false;

    s_mf_ctx.active    = true;
    s_mf_ctx.card_type = card_type;
    s_mf_ctx.uid_len   = uid_len;
    memcpy(s_mf_ctx.uid, uid, uid_len);
    return true;
}

bool poom_mifare_classic_has_card(void)
{
    return s_mf_ctx.active;
}

const uint8_t* poom_mifare_classic_get_default_key(size_t idx)
{
#if POOM_MIFARE_USE_TEST_DICTIONARY
    if(idx >= POOM_MIFARE_TEST_DICT_KEY_COUNT)
    {
        return NULL;
    }
    return poom_mifare_test_dict_keys[idx];
#else
    if(idx >= (sizeof(s_default_keys) / sizeof(s_default_keys[0])))
    {
        return NULL;
    }
    return s_default_keys[idx];
#endif
}

size_t poom_mifare_classic_get_default_key_count(void)
{
#if POOM_MIFARE_USE_TEST_DICTIONARY
    return POOM_MIFARE_TEST_DICT_KEY_COUNT;
#else
    return sizeof(s_default_keys) / sizeof(s_default_keys[0]);
#endif
}

bool poom_mifare_classic_auth(uint8_t block,
                              poom_mifare_key_type_t key_type,
                              const uint8_t key[6])
{
    bool ok;

    ok = poom_mifare_classic_auth_internal_(block, key_type, key, false, NULL);
    if(ok && s_mf_ctx.active)
    {
        int sector = poom_mifare_sector_of_block(s_mf_ctx.card_type, block);
        if(sector >= 0)
        {
            poom_mifare_record_working_key_(key, key_type);
            poom_mifare_cache_record_sector_key_((uint8_t)sector, key_type, key);
        }
    }
    return ok;
}

bool poom_mifare_classic_read_block(uint8_t block, uint8_t out_data[16])
{
    poom_crypto1_state_t st;
    int sector;
    uint8_t auth_blk;

    if(out_data == NULL)
    {
        return false;
    }

    if(!s_mf_ctx.active)
    {
        (void)poom_mifare_bind_active_if_possible();
    }
    if(!s_mf_ctx.active)
    {
        printf("  mifare read: no card bound\r\n");
        return false;
    }
    if((uint16_t)block > poom_mifare_max_block_for_type(s_mf_ctx.card_type))
    {
        printf("  mifare read: block out of range (%u)\r\n", (unsigned)block);
        return false;
    }

    sector = poom_mifare_sector_of_block(s_mf_ctx.card_type, block);
    if(sector < 0)
    {
        return false;
    }

    auth_blk = poom_mifare_auth_target_block(s_mf_ctx.card_type, (uint8_t)sector);

    if(!poom_mifare_prepare_selected_card())
    {
        printf("  mifare read: could not select card\r\n");
        return false;
    }

    {
        const uint8_t* ka = poom_mifare_get_sector_key_ptr_((uint8_t)sector, POOM_MIFARE_KEY_A);
        if(ka != NULL &&
           poom_mifare_classic_auth_internal_(auth_blk, POOM_MIFARE_KEY_A, ka, true, &st))
        {
            if(poom_mifare_crypto_read_block_(block, &st, out_data))
            {
                poom_mifare_block_cache_store_(block, out_data);
                return true;
            }
        }

        const uint8_t* kb = poom_mifare_get_sector_key_ptr_((uint8_t)sector, POOM_MIFARE_KEY_B);
        if(kb != NULL &&
           poom_mifare_classic_auth_internal_(auth_blk, POOM_MIFARE_KEY_B, kb, true, &st))
        {
            if(poom_mifare_crypto_read_block_(block, &st, out_data))
            {
                poom_mifare_block_cache_store_(block, out_data);
                return true;
            }
        }
    }

    printf("  mifare read: no cached/authenticated key for sector %d\r\n", sector);
    return false;
}

bool poom_mifare_classic_write_block(uint8_t block, const uint8_t data[16])
{
    poom_crypto1_state_t st;
    int sector;
    uint8_t auth_blk;
    uint8_t tmp[16];
    bool had_cached_key = false;
    bool auth_ok = false;

    if(data == NULL)
    {
        return false;
    }

    if(!s_mf_ctx.active)
    {
        (void)poom_mifare_bind_active_if_possible();
    }
    if(!s_mf_ctx.active)
    {
        printf("  mifare write: no card bound\r\n");
        return false;
    }
    if((uint16_t)block > poom_mifare_max_block_for_type(s_mf_ctx.card_type))
    {
        printf("  mifare write: block out of range (%u)\r\n", (unsigned)block);
        return false;
    }
    if(block == 0U)
    {
        printf("  mifare write: block 0 is manufacturer data and is read-only "
               "on normal MIFARE Classic cards\r\n");
        return false;
    }

    sector = poom_mifare_sector_of_block(s_mf_ctx.card_type, block);
    if(sector < 0)
    {
        return false;
    }

    auth_blk = poom_mifare_auth_target_block(s_mf_ctx.card_type, (uint8_t)sector);

    if(!poom_mifare_prepare_selected_card())
    {
        printf("  mifare write: could not select card\r\n");
        return false;
    }

    {
        const uint8_t* ka = poom_mifare_get_sector_key_ptr_((uint8_t)sector, POOM_MIFARE_KEY_A);
        if(ka != NULL)
        {
            had_cached_key = true;
            if(poom_mifare_classic_auth_internal_(auth_blk, POOM_MIFARE_KEY_A, ka,
                                                  true, &st))
            {
                auth_ok = true;
                if(poom_mifare_crypto_write_block_(block, &st, data))
                {
                    memcpy(tmp, data, sizeof(tmp));
                    poom_mifare_block_cache_store_(block, tmp);
                    return true;
                }
            }
        }

        const uint8_t* kb = poom_mifare_get_sector_key_ptr_((uint8_t)sector, POOM_MIFARE_KEY_B);
        if(kb != NULL)
        {
            had_cached_key = true;
            if(poom_mifare_classic_auth_internal_(auth_blk, POOM_MIFARE_KEY_B, kb,
                                                  true, &st))
            {
                auth_ok = true;
                if(poom_mifare_crypto_write_block_(block, &st, data))
                {
                    memcpy(tmp, data, sizeof(tmp));
                    poom_mifare_block_cache_store_(block, tmp);
                    return true;
                }
            }
        }
    }

    if(!had_cached_key)
    {
        printf("  mifare write: no cached/authenticated key for sector %d\r\n",
               sector);
    }
    else if(!auth_ok)
    {
        printf("  mifare write: cached key for sector %d did not authenticate\r\n",
               sector);
    }
    else
    {
        printf("  mifare write: authenticated, but the card rejected the write "
               "on block %u\r\n",
               (unsigned)block);
    }
    return false;
}

poom_mifare_auth_status_t poom_mifare_classic_get_last_auth_status(void)
{
    if(!s_mf_ctx.last_auth_attempted)
    {
        return POOM_MIFARE_AUTH_STATUS_NONE;
    }
    if(s_mf_ctx.last_auth_full_ok)
    {
        return POOM_MIFARE_AUTH_STATUS_FULL;
    }
    if(s_mf_ctx.last_auth_partial_ok)
    {
        return POOM_MIFARE_AUTH_STATUS_PARTIAL;
    }
    return POOM_MIFARE_AUTH_STATUS_FAIL;
}

bool poom_mifare_classic_try_default_keys(uint8_t block,
                                          poom_mifare_key_type_t key_type,
                                          size_t* matched_idx)
{
    if(matched_idx)
        *matched_idx = (size_t)-1;

    if(!poom_mifare_full_crypto1_ready())
    {
        const uint8_t* k = poom_mifare_classic_get_default_key(0);
        if(k != NULL)
        {
            return poom_mifare_classic_auth(block, key_type, k);
        }
        return false;
    }

    if(s_mf_ctx.active)
    {
        int sector = poom_mifare_sector_of_block(s_mf_ctx.card_type, block);
        if(sector >= 0)
        {
            const uint8_t* cached = poom_mifare_get_sector_key_ptr_((uint8_t)sector, key_type);
            if(cached != NULL)
            {
                if(poom_mifare_classic_auth(block, key_type, cached))
                {
                    return true;
                }
            }
        }
    }

    if(key_type == POOM_MIFARE_KEY_A && s_last_key_a_valid)
    {
        if(poom_mifare_classic_auth(block, key_type, s_last_key_a))
        {
            return true;
        }
    }
    else if(key_type == POOM_MIFARE_KEY_B && s_last_key_b_valid)
    {
        if(poom_mifare_classic_auth(block, key_type, s_last_key_b))
        {
            return true;
        }
    }

    size_t n = poom_mifare_classic_get_default_key_count();

    for(size_t i = 0; i < n; i++)
    {
        const uint8_t* k = poom_mifare_classic_get_default_key(i);
        if(!k)
            continue;
        if(poom_mifare_classic_auth(block, key_type, k))
        {
            if(matched_idx)
            {
                *matched_idx = s_mf_ctx.last_auth_full_ok ? i : (size_t)-1;
            }
            return true;
        }
        if(s_crypto1_link_limit)
            break;
    }
    return false;
}

uint8_t poom_mifare_classic_get_sector_count(void)
{
    if(!s_mf_ctx.active)
    {
        return 0U;
    }
    return poom_mifare_sector_count_for_type(s_mf_ctx.card_type);
}

bool poom_mifare_classic_get_sector_key(uint8_t sector,
                                       poom_mifare_key_type_t key_type,
                                       uint8_t out_key[6])
{
    const uint8_t* ptr;

    if(out_key == NULL)
    {
        return false;
    }
    if(!s_mf_ctx.active)
    {
        return false;
    }
    if(sector >= poom_mifare_sector_count_for_type(s_mf_ctx.card_type))
    {
        return false;
    }

    ptr = poom_mifare_get_sector_key_ptr_(sector, key_type);
    if(ptr == NULL)
    {
        return false;
    }

    memcpy(out_key, ptr, POOM_MIFARE_KEY_SIZE);
    return true;
}

int poom_mifare_classic_sector_for_block(uint8_t block)
{
    if(!s_mf_ctx.active)
    {
        (void)poom_mifare_bind_active_if_possible();
    }
    if(!s_mf_ctx.active)
    {
        return -1;
    }
    if((uint16_t)block > poom_mifare_max_block_for_type(s_mf_ctx.card_type))
    {
        return -1;
    }
    return poom_mifare_sector_of_block(s_mf_ctx.card_type, block);
}

uint16_t poom_mifare_classic_get_max_block(void)
{
    if(!s_mf_ctx.active)
    {
        (void)poom_mifare_bind_active_if_possible();
    }
    if(!s_mf_ctx.active)
    {
        return 0U;
    }
    return poom_mifare_max_block_for_type(s_mf_ctx.card_type);
}

/**
 * @brief Internal helper for `poom_mifare_auth_try_key_for_sector`.
 *
 * @param[in] sector Parameter passed to the function.
 * @param[in] key_type Parameter passed to the function.
 * @param[in] key Parameter passed to the function.
 * @return bool
 */
static bool poom_mifare_auth_try_key_for_sector_(uint8_t sector,
                                                 poom_mifare_key_type_t key_type,
                                                 const uint8_t key[POOM_MIFARE_KEY_SIZE])
{
    const uint8_t auth_blk = poom_mifare_auth_target_block(s_mf_ctx.card_type, sector);

    if(poom_mifare_classic_auth_internal_(auth_blk, key_type, key, false, NULL))
    {
        poom_mifare_record_working_key_(key, key_type);
        poom_mifare_cache_record_sector_key_(sector, key_type, key);
        return true;
    }

    return false;
}

static bool poom_mifare_try_discover_pass_(bool try_key_b,
                                           const uint8_t* key,
                                           uint8_t sectors,
                                           uint8_t* unknown_a,
                                           uint8_t* unknown_b,
                                           bool* found_any)
{
    bool matched = false;

    if(key == NULL || unknown_a == NULL || unknown_b == NULL || found_any == NULL)
    {
        return false;
    }

    for(uint8_t s = 0U; s < sectors; s++)
    {
        if(*unknown_a != 0U && !poom_mifare_sector_key_known_(s, POOM_MIFARE_KEY_A))
        {
            if(poom_mifare_auth_try_key_for_sector_(s, POOM_MIFARE_KEY_A, key))
            {
                *found_any = true;
                matched = true;
                if(*unknown_a != 0U)
                {
                    (*unknown_a)--;
                }
                printf("  sector %u keyA ", (unsigned)s);
                for(size_t i = 0U; i < POOM_MIFARE_KEY_SIZE; i++)
                {
                    printf("%02X", key[i]);
                }
                printf("\r\n");
            }
        }

        if(try_key_b && *unknown_b != 0U &&
           !poom_mifare_sector_key_known_(s, POOM_MIFARE_KEY_B))
        {
            if(poom_mifare_auth_try_key_for_sector_(s, POOM_MIFARE_KEY_B, key))
            {
                *found_any = true;
                matched = true;
                if(*unknown_b != 0U)
                {
                    (*unknown_b)--;
                }
                printf("  sector %u keyB ", (unsigned)s);
                for(size_t i = 0U; i < POOM_MIFARE_KEY_SIZE; i++)
                {
                    printf("%02X", key[i]);
                }
                printf("\r\n");
            }
        }
    }

    return matched;
}

bool poom_mifare_classic_discover_default_keys(bool try_key_b)
{
    bool found_any = false;
    bool had_known = false;
    const size_t dict_n = poom_mifare_classic_get_default_key_count();
    uint8_t sectors;
    uint8_t unknown_a = 0U;
    uint8_t unknown_b = 0U;

    if(!s_mf_ctx.active)
    {
        (void)poom_mifare_bind_active_if_possible();
    }
    if(!s_mf_ctx.active)
    {
        printf("  mifare discover: no card bound\r\n");
        return false;
    }

    sectors = poom_mifare_sector_count_for_type(s_mf_ctx.card_type);
    if(sectors == 0U || sectors > POOM_MIFARE_SECTOR_MAX)
    {
        printf("  mifare discover: invalid sector count %u\r\n", sectors);
        return false;
    }

    if(!poom_mifare_prepare_selected_card())
    {
        printf("  mifare discover: could not select card\r\n");
        return false;
    }

    for(uint8_t s = 0U; s < sectors; s++)
    {
        if(!poom_mifare_sector_key_known_(s, POOM_MIFARE_KEY_A))
        {
            unknown_a++;
        }
        else
        {
            had_known = true;
        }
        if(try_key_b && !poom_mifare_sector_key_known_(s, POOM_MIFARE_KEY_B))
        {
            unknown_b++;
        }
        else if(try_key_b)
        {
            had_known = true;
        }
    }

    s_mifare_discover_quiet = true;

    for(size_t k = 0U; k < (sizeof(s_priority_keys) / sizeof(s_priority_keys[0])); k++)
    {
        if(unknown_a == 0U && unknown_b == 0U)
        {
            break;
        }

        (void)poom_mifare_try_discover_pass_(
            try_key_b, s_priority_keys[k], sectors, &unknown_a, &unknown_b, &found_any);
    }

    for(size_t k = 0U; k < dict_n; k++)
    {
        if(unknown_a == 0U && unknown_b == 0U)
        {
            break;
        }

        const uint8_t* key = poom_mifare_classic_get_default_key(k);
        if(key == NULL)
        {
            continue;
        }

        bool is_priority = false;
        for(size_t pk = 0U; pk < (sizeof(s_priority_keys) / sizeof(s_priority_keys[0])); pk++)
        {
            if(poom_mifare_key_equals_(key, s_priority_keys[pk]))
            {
                is_priority = true;
                break;
            }
        }

        if(is_priority)
        {
            continue;
        }

        (void)poom_mifare_try_discover_pass_(
            try_key_b, key, sectors, &unknown_a, &unknown_b, &found_any);
    }

    s_mifare_discover_quiet = false;

    return found_any || had_known;
}

/**
 * @brief Internal helper for `poom_mifare_flipper_type_prefix`.
 *
 * @param[in] card_type Parameter passed to the function.
 * @return const char*
 */
static const char* poom_mifare_flipper_type_prefix_(nfc_card_type_t card_type)
{
    switch(card_type)
    {
        case NFC_CARD_MIFARE_MINI:
            return "ClassicMini";
        case NFC_CARD_MIFARE_CLASSIC_1K:
            return "Classic1K";
        case NFC_CARD_MIFARE_CLASSIC_4K:
            return "Classic4K";
        default:
            return "Classic";
    }
}

/**
 * @brief Returns the display label for the current state.
 *
 * @param[in] card_type Parameter passed to the function.
 * @return const char*
 */
static const char* poom_mifare_flipper_type_label_(nfc_card_type_t card_type)
{
    switch(card_type)
    {
        case NFC_CARD_MIFARE_MINI:
            return "Mini";
        case NFC_CARD_MIFARE_CLASSIC_1K:
            return "1K";
        case NFC_CARD_MIFARE_CLASSIC_4K:
            return "4K";
        default:
            return "Unknown";
    }
}

/**
 * @brief Formats internal text for display.
 *
 * @param[in] out Parameter passed to the function.
 * @param[in] out_len Parameter passed to the function.
 * @param[in] uid Parameter passed to the function.
 * @param[in] uid_len Parameter passed to the function.
 * @return void
 */
static void poom_mifare_format_uid_dashed_(char* out, size_t out_len, const uint8_t* uid, uint8_t uid_len)
{
    size_t pos = 0U;

    if(out == NULL || out_len == 0U)
    {
        return;
    }
    out[0] = '\0';
    if(uid == NULL || uid_len == 0U)
    {
        return;
    }

    for(uint8_t i = 0U; i < uid_len; i++)
    {
        if(i > 0U)
        {
            if(pos + 1U >= out_len)
            {
                break;
            }
            out[pos++] = '-';
        }
        if(pos + 2U >= out_len)
        {
            break;
        }
        pos += (size_t)snprintf(&out[pos], out_len - pos, "%02X", uid[i]);
    }

    if(pos >= out_len)
    {
        out[out_len - 1U] = '\0';
    }
}

/**
 * @brief Formats internal text for display.
 *
 * @param[in] out Parameter passed to the function.
 * @param[in] out_len Parameter passed to the function.
 * @param[in] uid Parameter passed to the function.
 * @param[in] uid_len Parameter passed to the function.
 * @return void
 */
static void poom_mifare_format_uid_spaced_(char* out, size_t out_len, const uint8_t* uid, uint8_t uid_len)
{
    size_t pos = 0U;

    if(out == NULL || out_len == 0U)
    {
        return;
    }
    out[0] = '\0';
    if(uid == NULL || uid_len == 0U)
    {
        return;
    }

    for(uint8_t i = 0U; i < uid_len; i++)
    {
        if(pos + 3U >= out_len)
        {
            break;
        }
        if(i > 0U)
        {
            out[pos++] = ' ';
        }
        pos += (size_t)snprintf(&out[pos], out_len - pos, "%02X", uid[i]);
    }

    if(pos >= out_len)
    {
        out[out_len - 1U] = '\0';
    }
}

typedef enum
{
    POOM_MIFARE_DUMP_FMT_FLIPPER = 0,
    POOM_MIFARE_DUMP_FMT_POOM_MEMORY,
} poom_mifare_dump_format_t;

static const char* poom_mifare_dump_ext_(poom_mifare_dump_format_t format)
{
    (void)format;
    return ".nfc";
}

static const char* poom_mifare_dump_name_suffix_(poom_mifare_dump_format_t format)
{
    return (format == POOM_MIFARE_DUMP_FMT_POOM_MEMORY) ? "_poom" : "";
}

static const char* poom_mifare_dump_label_(poom_mifare_dump_format_t format)
{
    return (format == POOM_MIFARE_DUMP_FMT_POOM_MEMORY) ? "POOM memory image" : "Flipper .nfc";
}

static void poom_mifare_format_key_hex_(char out[13], const uint8_t key[6])
{
    if(out == NULL)
    {
        return;
    }

    if(key == NULL)
    {
        (void)snprintf(out, 13, "Unknown");
        return;
    }

    (void)snprintf(out,
                   13,
                   "%02X%02X%02X%02X%02X%02X",
                   (unsigned)key[0],
                   (unsigned)key[1],
                   (unsigned)key[2],
                   (unsigned)key[3],
                   (unsigned)key[4],
                   (unsigned)key[5]);
}

static bool poom_mifare_write_dump_header_(const char* path,
                                           poom_mifare_dump_format_t format,
                                           const char* uid_hdr,
                                           uint8_t sectors)
{
    char header[512];
    uint16_t max_block = poom_mifare_max_block_for_type(s_mf_ctx.card_type);
    uint16_t block_count = (max_block > 0U) ? (uint16_t)(max_block + 1U) : 0U;

    if(format == POOM_MIFARE_DUMP_FMT_POOM_MEMORY)
    {
        (void)snprintf(header,
                       sizeof(header),
                       "Filetype: POOM NFC memory image\n"
                       "Version: 1\n\n"
                       "Protocol: ISO14443-A\n"
                       "Device type: Mifare Classic\n"
                       "Card subtype: %s\n"
                       "UID:%s%s\n"
                       "ATQA: %02X %02X\n"
                       "SAK: %02X\n\n"
                       "Data format: block-dump\n"
                       "Data format version: 1\n"
                       "Block size: 16\n"
                       "Sector count: %u\n"
                       "Block count: %u\n\n",
                       poom_mifare_flipper_type_label_(s_mf_ctx.card_type),
                       (s_mf_ctx.uid_len > 0U) ? " " : "",
                       (s_mf_ctx.uid_len > 0U) ? uid_hdr : "",
                       (unsigned)((s_mf_ctx.atqa >> 8) & 0xFFU),
                       (unsigned)(s_mf_ctx.atqa & 0xFFU),
                       (unsigned)s_mf_ctx.sak,
                       (unsigned)sectors,
                       (unsigned)block_count);
    }
    else
    {
        (void)snprintf(header,
                       sizeof(header),
                       "Filetype: Flipper NFC device\n"
                       "Version: 4\n"
                       "Device type: Mifare Classic\n"
                       "UID:%s%s\n"
                       "ATQA: %02X %02X\n"
                       "SAK: %02X\n"
                       "Mifare Classic type: %s\n"
                       "Data format version: 2\n",
                       (s_mf_ctx.uid_len > 0U) ? " " : "",
                       (s_mf_ctx.uid_len > 0U) ? uid_hdr : "",
                       (unsigned)((s_mf_ctx.atqa >> 8) & 0xFFU),
                       (unsigned)(s_mf_ctx.atqa & 0xFFU),
                       (unsigned)s_mf_ctx.sak,
                       poom_mifare_flipper_type_label_(s_mf_ctx.card_type));
    }

    header[sizeof(header) - 1U] = '\0';

    if(sd_card_write_file(path, header) != ESP_OK)
    {
        printf("  mifare dump: write header failed\r\n");
        return false;
    }

    return true;
}

static bool poom_mifare_append_security_section_(const char* path, uint8_t sectors)
{
    char line[96];

    if(sd_card_append_to_file(path, "\n# Security\n") != ESP_OK)
    {
        printf("  mifare dump: append security header failed\r\n");
        return false;
    }

    for(uint8_t s = 0U; s < sectors; s++)
    {
        char key_hex[13];
        const uint8_t* ka = poom_mifare_get_sector_key_ptr_(s, POOM_MIFARE_KEY_A);
        const uint8_t* kb = poom_mifare_get_sector_key_ptr_(s, POOM_MIFARE_KEY_B);

        if(ka != NULL)
        {
            poom_mifare_format_key_hex_(key_hex, ka);
            (void)snprintf(line, sizeof(line), "Sector %u Key A: %s\n", (unsigned)s, key_hex);
        }
        else
        {
            (void)snprintf(line, sizeof(line), "Sector %u Key A: Unknown\n", (unsigned)s);
        }
        line[sizeof(line) - 1U] = '\0';
        if(sd_card_append_to_file(path, line) != ESP_OK)
        {
            printf("  mifare dump: append security failed\r\n");
            return false;
        }

        if(kb != NULL)
        {
            poom_mifare_format_key_hex_(key_hex, kb);
            (void)snprintf(line, sizeof(line), "Sector %u Key B: %s\n", (unsigned)s, key_hex);
        }
        else
        {
            (void)snprintf(line, sizeof(line), "Sector %u Key B: Unknown\n", (unsigned)s);
        }
        line[sizeof(line) - 1U] = '\0';
        if(sd_card_append_to_file(path, line) != ESP_OK)
        {
            printf("  mifare dump: append security failed\r\n");
            return false;
        }
    }

    return true;
}

static bool poom_mifare_classic_dump_to_file_(const char* out_dir,
                                              bool try_key_b,
                                              char* out_path,
                                              size_t out_path_len,
                                              poom_mifare_dump_format_t format)
{
    char uid_part[64];
    char uid_hdr[64];
    char path[160];
    char line[196];
    const char* dir = (out_dir != NULL && out_dir[0] != '\0') ? out_dir : "/nfc";
    uint8_t sectors;
    bool card_present = false;
    bool cache_has_any = false;
    bool cache_is_complete = false;

    if(out_path != NULL && out_path_len > 0U)
    {
        out_path[0] = '\0';
    }

    if(sd_card_is_not_mounted())
    {
        esp_err_t ret = sd_card_mount();
        if(ret != ESP_OK)
        {
            printf("  mifare dump: sd_card_mount failed\r\n");
            return false;
        }
    }

    (void)sd_card_create_dir(dir);

    if(!s_mf_ctx.active)
    {
        (void)poom_mifare_bind_active_if_possible();
    }
    if(!s_mf_ctx.active)
    {
        printf("  mifare dump: no card bound\r\n");
        return false;
    }

    card_present = poom_mifare_prepare_selected_card();

    sectors = poom_mifare_sector_count_for_type(s_mf_ctx.card_type);
    if(sectors == 0U || sectors > POOM_MIFARE_SECTOR_MAX)
    {
        printf("  mifare dump: invalid sector count %u\r\n", sectors);
        return false;
    }

    cache_has_any = poom_mifare_block_cache_has_any_();
    cache_is_complete = poom_mifare_block_cache_has_all_(
        (uint16_t)(poom_mifare_max_block_for_type(s_mf_ctx.card_type) + 1U));

    if(card_present && !cache_is_complete)
    {
        (void)poom_mifare_classic_discover_default_keys(try_key_b);
    }
    else if(!card_present && !cache_has_any)
    {
        printf("  mifare dump: card not present and no cached blocks.\r\n");
        return false;
    }

    poom_mifare_format_uid_dashed_(uid_part, sizeof(uid_part), s_mf_ctx.uid, s_mf_ctx.uid_len);
    poom_mifare_format_uid_spaced_(uid_hdr, sizeof(uid_hdr), s_mf_ctx.uid, s_mf_ctx.uid_len);
    (void)snprintf(path,
                   sizeof(path),
                   "%s/%s_%s%s%s",
                   dir,
                   poom_mifare_flipper_type_prefix_(s_mf_ctx.card_type),
                   uid_part,
                   poom_mifare_dump_name_suffix_(format),
                   poom_mifare_dump_ext_(format));
    path[sizeof(path) - 1U] = '\0';

    if(out_path != NULL && out_path_len > 0U)
    {
        (void)snprintf(out_path, out_path_len, "%s", path);
        out_path[out_path_len - 1U] = '\0';
    }

    if(!s_mf_ctx.atqa_sak_set)
    {
        s_mf_ctx.atqa = 0U;
        s_mf_ctx.sak = 0U;
    }

    if(!poom_mifare_write_dump_header_(path, format, uid_hdr, sectors))
    {
        return false;
    }

    for(uint8_t s = 0U; s < sectors; s++)
    {
        const uint16_t first = poom_mifare_first_block_of_sector(s_mf_ctx.card_type, s);
        const uint8_t blocks = poom_mifare_blocks_in_sector(s_mf_ctx.card_type, s);
        const uint16_t trailer = (uint16_t)(first + (uint16_t)blocks - 1U);

        for(uint8_t b = 0U; b < blocks; b++)
        {
            const uint16_t absb = (uint16_t)(first + b);
            uint8_t outb[16];
            bool ok = false;

            if(absb >= POOM_MIFARE_BLOCK_MAX)
            {
                continue;
            }

            if(poom_mifare_block_cache_load_((uint8_t)absb, outb))
            {
                ok = true;
            }
            else if(card_present)
            {
                ok = poom_mifare_classic_read_block((uint8_t)absb, outb);
            }

            {
                int lpos = 0;
                lpos += snprintf(line, sizeof(line), "Block %u:", (unsigned)absb);

                if(ok)
                {
                    uint8_t tmp[16];
                    memcpy(tmp, outb, sizeof(tmp));

                    if(absb == trailer)
                    {
                        const uint8_t* ka = poom_mifare_get_sector_key_ptr_(s, POOM_MIFARE_KEY_A);
                        const uint8_t* kb = poom_mifare_get_sector_key_ptr_(s, POOM_MIFARE_KEY_B);
                        if(ka != NULL)
                        {
                            memcpy(&tmp[0], ka, 6);
                        }
                        if(kb != NULL)
                        {
                            memcpy(&tmp[10], kb, 6);
                        }
                    }

                    poom_mifare_block_cache_store_((uint8_t)absb, outb);

                    for(uint8_t i = 0U; i < 16U; i++)
                    {
                        lpos += snprintf(&line[lpos], sizeof(line) - (size_t)lpos, " %02X", (unsigned)tmp[i]);
                    }
                }
                else
                {
                    if(absb == trailer)
                    {
                        const uint8_t* ka = poom_mifare_get_sector_key_ptr_(s, POOM_MIFARE_KEY_A);
                        const uint8_t* kb = poom_mifare_get_sector_key_ptr_(s, POOM_MIFARE_KEY_B);
                        for(uint8_t i = 0U; i < 16U; i++)
                        {
                            if(ka != NULL && i < 6U)
                            {
                                lpos += snprintf(&line[lpos], sizeof(line) - (size_t)lpos, " %02X", (unsigned)ka[i]);
                            }
                            else if(kb != NULL && i >= 10U)
                            {
                                lpos += snprintf(&line[lpos], sizeof(line) - (size_t)lpos, " %02X",
                                                 (unsigned)kb[i - 10U]);
                            }
                            else
                            {
                                lpos += snprintf(&line[lpos], sizeof(line) - (size_t)lpos, " ??");
                            }
                        }
                    }
                    else
                    {
                        for(uint8_t i = 0U; i < 16U; i++)
                        {
                            lpos += snprintf(&line[lpos], sizeof(line) - (size_t)lpos, " ??");
                        }
                    }
                }

                lpos += snprintf(&line[lpos], sizeof(line) - (size_t)lpos, "\n");
                line[sizeof(line) - 1U] = '\0';

                if(sd_card_append_to_file(path, line) != ESP_OK)
                {
                    printf("  mifare dump: append failed\r\n");
                    return false;
                }
            }
        }
    }

    if(format == POOM_MIFARE_DUMP_FMT_POOM_MEMORY &&
       !poom_mifare_append_security_section_(path, sectors))
    {
        return false;
    }

    printf("  mifare dump saved (%s): %s\r\n", poom_mifare_dump_label_(format), path);
    return true;
}

bool poom_mifare_classic_dump_to_flipper_file(const char* out_dir,
                                              bool try_key_b,
                                              char* out_path,
                                              size_t out_path_len)
{
    return poom_mifare_classic_dump_to_file_(
        out_dir, try_key_b, out_path, out_path_len, POOM_MIFARE_DUMP_FMT_FLIPPER);
}

bool poom_mifare_classic_dump_to_poom_memory_file(const char* out_dir,
                                                  bool try_key_b,
                                                  char* out_path,
                                                  size_t out_path_len)
{
    return poom_mifare_classic_dump_to_file_(
        out_dir, try_key_b, out_path, out_path_len, POOM_MIFARE_DUMP_FMT_POOM_MEMORY);
}
