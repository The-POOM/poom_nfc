// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 THE POOM

#include "poom_nfc_tlv.h"

#include <stdio.h>

enum
{
    /* BER-TLV tag field bits from ISO/IEC 7816-4 Annex D / BER-TLV rules. */
    POOM_TLV_TAG_CONSTRUCTED_MASK = 0x20U,
    POOM_TLV_TAG_NUMBER_MASK = 0x1FU,
    POOM_TLV_TAG_NUMBER_EXTENDED = 0x1FU,
    POOM_TLV_TAG_CONTINUATION_MASK = 0x80U,

    /* BER-TLV length field rules. */
    POOM_TLV_LEN_LONG_FORM_MASK = 0x80U,
    POOM_TLV_LEN_LONG_FORM_COUNT_MASK = 0x7FU,

    /* Local parser limits: up to 4-byte tags, matching uint32_t storage. */
    POOM_TLV_TAG_BYTES_MAX = 4U,
    POOM_TLV_LEN_SHORT_FORM_BYTES = 1U,
};

static bool poom_tlv_parse_tag_(const uint8_t* buf,
                                size_t buf_len,
                                uint32_t* out_tag,
                                bool* out_constructed,
                                size_t* out_tag_len)
{
    size_t pos = 0U;
    uint32_t tag = 0U;

    if(buf == NULL || buf_len == 0U || out_tag == NULL || out_constructed == NULL || out_tag_len == NULL)
    {
        return false;
    }

    tag = buf[pos++];
    *out_constructed = ((tag & POOM_TLV_TAG_CONSTRUCTED_MASK) != 0U);

    if((tag & POOM_TLV_TAG_NUMBER_MASK) == POOM_TLV_TAG_NUMBER_EXTENDED)
    {
        do
        {
            if(pos >= buf_len || pos >= POOM_TLV_TAG_BYTES_MAX)
            {
                return false;
            }
            tag = (tag << 8) | buf[pos];
        } while((buf[pos++] & POOM_TLV_TAG_CONTINUATION_MASK) != 0U);
    }

    *out_tag = tag;
    *out_tag_len = pos;
    return true;
}

/**
 * @brief Internal helper for `poom_tlv_parse_len_`.
 *
 * Parses BER-TLV short-form or long-form Length bytes.
 *
 * @param[in] buf Parameter passed to the function.
 * @param[in] buf_len Parameter passed to the function.
 * @param[out] out_value_len Parameter passed to the function.
 * @param[out] out_len_len Parameter passed to the function.
 * @return bool
 */
static bool poom_tlv_parse_len_(const uint8_t* buf,
                                size_t buf_len,
                                size_t* out_value_len,
                                size_t* out_len_len)
{
    size_t pos = 0U;
    size_t value_len = 0U;

    if(buf == NULL || buf_len == 0U || out_value_len == NULL || out_len_len == NULL)
    {
        return false;
    }

    if((buf[0] & POOM_TLV_LEN_LONG_FORM_MASK) == 0U)
    {
        *out_value_len = buf[0];
        *out_len_len = POOM_TLV_LEN_SHORT_FORM_BYTES;
        return true;
    }

    size_t octets = (size_t)(buf[0] & POOM_TLV_LEN_LONG_FORM_COUNT_MASK);
    if(octets == 0U || octets > sizeof(size_t) || (POOM_TLV_LEN_SHORT_FORM_BYTES + octets) > buf_len)
    {
        return false;
    }

    pos = POOM_TLV_LEN_SHORT_FORM_BYTES;
    for(size_t i = 0U; i < octets; i++)
    {
        value_len = (value_len << 8) | buf[pos++];
    }

    *out_value_len = value_len;
    *out_len_len = pos;
    return true;
}

/**
 * @brief Parse one BER-TLV item from the start of a buffer.
 *
 * @param[in] buf Parameter passed to the function.
 * @param[in] buf_len Parameter passed to the function.
 * @param[out] out_tlv Parameter passed to the function.
 * @return bool
 */
bool poom_tlv_parse_one(const uint8_t* buf, size_t buf_len, poom_tlv_view_t* out_tlv)
{
    uint32_t tag = 0U;
    bool constructed = false;
    size_t tag_len = 0U;
    size_t len_len = 0U;
    size_t value_len = 0U;
    size_t header_len = 0U;

    if(buf == NULL || out_tlv == NULL)
    {
        return false;
    }

    if(!poom_tlv_parse_tag_(buf, buf_len, &tag, &constructed, &tag_len))
    {
        return false;
    }

    if(tag_len >= buf_len)
    {
        return false;
    }

    if(!poom_tlv_parse_len_(buf + tag_len, buf_len - tag_len, &value_len, &len_len))
    {
        return false;
    }

    header_len = tag_len + len_len;
    if(header_len > buf_len || value_len > (buf_len - header_len))
    {
        return false;
    }

    out_tlv->tag = tag;
    out_tlv->constructed = constructed;
    out_tlv->header_len = header_len;
    out_tlv->value = buf + header_len;
    out_tlv->value_len = value_len;
    out_tlv->total_len = header_len + value_len;
    return true;
}

/**
 * @brief Advance through a sequence of BER-TLV items.
 *
 * @param[in] buf Parameter passed to the function.
 * @param[in] buf_len Parameter passed to the function.
 * @param[in,out] io_offset Parameter passed to the function.
 * @param[out] out_tlv Parameter passed to the function.
 * @return bool
 */
bool poom_tlv_next(const uint8_t* buf, size_t buf_len, size_t* io_offset, poom_tlv_view_t* out_tlv)
{
    poom_tlv_view_t item;

    if(buf == NULL || io_offset == NULL || out_tlv == NULL || *io_offset > buf_len)
    {
        return false;
    }

    if(*io_offset == buf_len)
    {
        return false;
    }

    if(!poom_tlv_parse_one(buf + *io_offset, buf_len - *io_offset, &item))
    {
        return false;
    }

    *out_tlv = item;
    *io_offset += item.total_len;
    return true;
}

/**
 * @brief Format one BER-TLV tag as uppercase hexadecimal text.
 *
 * @param[in] tag Parameter passed to the function.
 * @param[out] out Parameter passed to the function.
 * @param[in] out_len Parameter passed to the function.
 * @return size_t
 */
size_t poom_tlv_format_tag(uint32_t tag, char* out, size_t out_len)
{
    uint8_t parts[4];
    size_t part_count = 0U;
    size_t pos = 0U;

    if(out == NULL || out_len == 0U)
    {
        return 0U;
    }

    out[0] = '\0';
    do
    {
        if(part_count >= sizeof(parts))
        {
            return 0U;
        }
        parts[part_count++] = (uint8_t)(tag & 0xFFU);
        tag >>= 8;
    } while(tag != 0U);

    for(size_t i = 0U; i < part_count; i++)
    {
        const uint8_t b = parts[part_count - 1U - i];
        if((pos + 2U) >= out_len)
        {
            out[0] = '\0';
            return 0U;
        }
        pos += (size_t)snprintf(&out[pos], out_len - pos, "%02X", (unsigned)b);
    }

    return pos;
}
