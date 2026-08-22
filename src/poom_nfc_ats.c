/*
 * poom_nfc_ats.c
 *
 * Shared ATS (Answer To Select) parser for POOM NFC.
 *
 * This module normalizes the ATS bytes obtained during ISO-DEP activation so
 * the same interpretation is reused by:
 * - NFC-A / ISO-DEP activation traces
 * - CLI summaries for stored profiles
 * - T4T emulation setup paths
 */

#include "poom_nfc_ats.h"

#include <string.h>

#include "rfal_isoDep.h"

/**
 * @brief Parse a raw ATS buffer and derive the fields most useful to POOM.
 *
 * This helper is shared by CLI output, NFC-A / ISO-DEP activation traces, and
 * the T4T emulator path so those call sites do not keep separate ATS decoders.
 *
 * The function accepts a raw ATS starting with `TL`, trims the effective
 * length to `TL` when the caller buffer is longer, and then decodes optional
 * `TA(1)`, `TB(1)`, `TC(1)`, plus historical bytes.
 *
 * @param[in] ats Raw ATS bytes.
 * @param[in] ats_len Number of bytes available in `ats`.
 * @param[out] out_info Parsed ATS result.
 * @return true when parsing succeeds, false on malformed or truncated ATS.
 */
bool poom_nfc_ats_parse(const uint8_t* ats, uint8_t ats_len, poom_nfc_ats_info_t* out_info)
{
    uint8_t idx = 0U;

    if((ats == NULL) || (out_info == NULL) || (ats_len < 2U))
    {
        return false;
    }

    (void)memset(out_info, 0, sizeof(*out_info));

    out_info->tl = ats[0];
    if(out_info->tl == 0U)
    {
        return false;
    }
    if(out_info->tl < ats_len)
    {
        ats_len = out_info->tl;
    }
    if(ats_len < 2U)
    {
        return false;
    }

    out_info->ats_len = ats_len;
    out_info->t0 = ats[1];
    out_info->fsci = (uint8_t)(out_info->t0 & RFAL_ISODEP_ATS_T0_FSCI_MASK);
    out_info->fsc = rfalIsoDepFSxI2FSx(out_info->fsci);
    out_info->fwi = 4U;
    out_info->sfgi = 0U;

    idx = 2U;

    if((out_info->t0 & RFAL_ISODEP_ATS_T0_TA_PRESENCE_MASK) != 0U)
    {
        if(idx >= ats_len)
        {
            return false;
        }
        out_info->ta = ats[idx++];
        out_info->ta_present = true;
    }

    if((out_info->t0 & RFAL_ISODEP_ATS_T0_TB_PRESENCE_MASK) != 0U)
    {
        if(idx >= ats_len)
        {
            return false;
        }
        out_info->tb = ats[idx++];
        out_info->tb_present = true;
        out_info->fwi = (uint8_t)((out_info->tb & RFAL_ISODEP_ATS_TB_FWI_MASK) >> 4);
        out_info->sfgi = (uint8_t)(out_info->tb & RFAL_ISODEP_ATS_TB_SFGI_MASK);
    }

    if((out_info->t0 & RFAL_ISODEP_ATS_T0_TC_PRESENCE_MASK) != 0U)
    {
        if(idx >= ats_len)
        {
            return false;
        }
        out_info->tc = ats[idx++];
        out_info->tc_present = true;
        out_info->nad_supported = ((out_info->tc & 0x01U) != 0U);
        out_info->did_supported = ((out_info->tc & 0x02U) != 0U);
    }

    out_info->hb_len = (uint8_t)((idx <= ats_len) ? (ats_len - idx) : 0U);
    if(out_info->hb_len > POOM_NFC_ATS_HB_MAX)
    {
        out_info->hb_len = POOM_NFC_ATS_HB_MAX;
    }
    if(out_info->hb_len > 0U)
    {
        (void)memcpy(out_info->hb, &ats[idx], out_info->hb_len);
    }

    return true;
}
