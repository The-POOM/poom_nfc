// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 THE POOM

/* BER-TLV parsing helpers for POOM NFC. */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    uint32_t tag;           /* BER-TLV tag value (1..4 bytes packed big-endian). */
    const uint8_t* value;   /* Pointer to the Value field inside the source buffer. */
    size_t value_len;       /* Length of the Value field in bytes. */
    bool constructed;       /* True when the tag is BER-TLV constructed. */
    size_t header_len;      /* Tag + Length field size in bytes. */
    size_t total_len;       /* Full TLV size: header + value. */
} poom_tlv_view_t;

/**
 * @brief Parse one BER-TLV item from the beginning of a buffer.
 *
 * The parser is zero-copy: the `value` field points directly into `buf`.
 *
 * @param[in] buf Input buffer that begins with one BER-TLV item.
 * @param[in] buf_len Number of bytes available in `buf`.
 * @param[out] out_tlv Parsed TLV view.
 * @return true on success, false when the item is malformed or incomplete.
 */
bool poom_tlv_parse_one(const uint8_t* buf, size_t buf_len, poom_tlv_view_t* out_tlv);

/**
 * @brief Iterate to the next BER-TLV item inside a container buffer.
 *
 * `io_offset` is advanced by the parsed item's total length on success.
 *
 * @param[in] buf Input container buffer.
 * @param[in] buf_len Number of bytes available in `buf`.
 * @param[in,out] io_offset Current byte offset into `buf`.
 * @param[out] out_tlv Parsed TLV view at the current offset.
 * @return true when one item was parsed, false when parsing failed or the end
 *         of the buffer was reached.
 */
bool poom_tlv_next(const uint8_t* buf, size_t buf_len, size_t* io_offset, poom_tlv_view_t* out_tlv);

/**
 * @brief Format a numeric BER-TLV tag as uppercase hexadecimal text.
 *
 * @param[in] tag BER-TLV tag value packed big-endian into a uint32_t.
 * @param[out] out Output string buffer.
 * @param[in] out_len Capacity of `out`.
 * @return size_t Number of characters written, or 0 on failure.
 */
size_t poom_tlv_format_tag(uint32_t tag, char* out, size_t out_len);

#ifdef __cplusplus
}
#endif
