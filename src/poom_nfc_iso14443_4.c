// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2026 THE POOM

/*
 * POOM NFC reader (refactor, printf-only)
 *
 * Standards mapping (high level)
 *  - ISO/IEC 14443-3: Type A/B activation (REQA/ATQA, anticollision/select, REQB/ATQB/ATTRIB)
 *  - ISO/IEC 14443-4: ISO-DEP activation (RATS/ATS, PPS) + block protocol (I/R/S blocks)
 */

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <ctype.h>


#include "rfal_rf.h"
#include "rfal_analogConfig.h"
#include "rfal_nfca.h"
#include "rfal_nfcb.h"
#include "rfal_nfcv.h"
#include "rfal_isoDep.h"

#include "poom_nfc_ats.h"
#include "poom_nfc_profile.h"
#include "poom_nfc_card_ident.h"

/* ============================================================================
 * Constants / helpers (no magic numbers)
 * ========================================================================== */
/* =========================
 *  Defines / helpers
 * ========================= */
#ifndef ERR_NONE
  #define ERR_NONE  (0U)
#endif
#ifndef ERR_BUSY
  #define ERR_BUSY  (2U)
#endif

enum {
	POOM_NFC_BUF_MAX = 260,   /* enough for 256-byte frames + overhead */
	POOM_RFAL_RX_MAX = 0xFF,  /* original code limit */
};

/* ISO/IEC 14443-3 (Type A) */
enum {
	POOM_ISO14443A_CMD_REQA      = 0x26,
	POOM_ISO14443A_SEL_CL1       = 0x93,
	POOM_ISO14443A_SEL_CL2       = 0x95,
	POOM_ISO14443A_SEL_CL3       = 0x97,
	POOM_ISO14443A_ANTICOLLISION = 0x20, /* NVB for anticollision */
	POOM_ISO14443A_SELECT        = 0x70, /* NVB for select */
	POOM_ISO14443A_UID_BCC_LEN   = 5,    /* UID(4) + BCC */
	POOM_ISO14443A_SAK_CASCADE_MASK = 0x04, /* SAK bit: UID not complete, next cascade level */
	POOM_ISO14443A_SAK_ISODEP_MASK = 0x20, /* SAK bit: ISO-DEP compliance */
};

/* ISO/IEC 14443-4 (Activation) */
enum {
	POOM_ISO14443_4_CMD_RATS       = 0xE0, /* ISO/IEC 14443-4: 5.1 RATS */
	POOM_ISO14443_4_CMD_PPS_PREFIX = 0xD0, /* ISO/IEC 14443-4: 5.3 PPSS (D0..DF) */
};

/* ISO/IEC 14443-3 (Type B) */
enum {
	POOM_ISO14443B_CMD_REQB   = 0x05, /* ISO/IEC 14443-3 Type B: REQB/WUPB */
	POOM_ISO14443B_CMD_ATTRIB = 0x1D, /* ISO/IEC 14443-3 Type B: ATTRIB */
	POOM_ISO14443B_PUPI_LEN   = 4,
};

/* ISO/IEC 14443-4 (Block protocol) - PCB bits */
enum {
	POOM_ISO14443_4_PCB_I_BLOCK_BASE = 0x02, /* 14443-4: Fig 15 I-block PCB: b8..=0, b2=block# */
	POOM_ISO14443_4_PCB_HAS_NAD      = 0x04, /* NAD following */
	POOM_ISO14443_4_PCB_HAS_CID      = 0x08, /* CID following */
	POOM_ISO14443_4_PCB_CHAINING     = 0x10, /* chaining */
};

/* ISO/IEC 14443-4: R-block examples (Fig 16) */
enum {
	POOM_ISO14443_4_PCB_R_BLOCK_ACK_BASE = 0xA2,
	POOM_ISO14443_4_PCB_R_BLOCK_NAK_BASE = 0xA2, /* Use ACK while requesting next chained block. */
};

/* ISO/IEC 14443-4: S-block detection helpers (Fig 17) */
enum {
	POOM_ISO14443_4_PCB_S_BLOCK_MASK = 0xC0,
	POOM_ISO14443_4_PCB_S_BLOCK_TAG  = 0xC0,
	POOM_ISO14443_4_PCB_S_WTX_BASE   = 0xF2,
};

/* ISO/IEC 14443-4: 7.3 WTX INF mask */
enum {
	POOM_ISO14443_4_WTXM_MASK = 0x3F,
	POOM_ISO14443_4_WTXM_MIN  = 1U,
	POOM_ISO14443_4_WTXM_MAX  = 59U,
	POOM_ISO14443_4_WTX_MAX   = 20U,
};

/* RFAL time values use 1/fc units. dFWT matches RFAL's ISO-DEP poller margin. */
enum {
	POOM_RFAL_ACTIVATION_TIMEOUT_TICKS = (216960U + 71680U + 71680U),
	POOM_RFAL_ISODEP_DFWT_TICKS       = 49152U,
};

/* ISO/IEC 14443-4: 5.1 RATS parameter byte */

/**
 * @brief Internal helper for `poom_iso14443_4_rats_param_make`.
 *
 * @param[in] fsdi Parameter passed to the function.
 * @param[in] cid Parameter passed to the function.
 * @return inline uint8_t
 */
static inline uint8_t poom_iso14443_4_rats_param_make(uint8_t fsdi, uint8_t cid)
{
	return (uint8_t)(((fsdi & 0x0F) << 4) | (cid & 0x0F));
}

/* ============================================================================
 * Module state
 * ========================================================================== */

static uint8_t  poom_tx[POOM_NFC_BUF_MAX];
static uint8_t  poom_rx[POOM_NFC_BUF_MAX];
static uint16_t poom_tx_len, poom_rx_len;

static uint16_t poom_ascii_hex_len;
static uint8_t  poom_ascii_hex_buf[POOM_NFC_BUF_MAX];

static uint16_t poom_rapdu_len;
static uint8_t  poom_rapdu[POOM_NFC_BUF_MAX];

static bool     poom_verbose = true;
static uint8_t  poom_iso_dep_chunk_len = 16; /* max INF per I-block for our simple fragmentation */
static uint32_t poom_iso_dep_fwt_ticks;
static rfalMode poom_mode = RFAL_MODE_NONE;
static bool     poom_nfca_isodep_active = false;

/* Last activation snapshot (best-effort, for CLI workflows) */
static poom_nfc_profile_t poom_last_profile;
static bool poom_last_profile_valid = false;

/**
 * @brief Internal helper for `poom_last_profile_reset`.
 *
 * @return void
 */
static void poom_last_profile_reset_(void)
{
    (void)memset(&poom_last_profile, 0, sizeof(poom_last_profile));
    poom_last_profile_valid = false;
}

/**
 * @brief Internal helper for `poom_last_profile_set_mode_from_nfca`.
 *
 * @return void
 */
static void poom_last_profile_set_mode_from_nfca_(void)
{
    if(!poom_last_profile_valid)
    {
        return;
    }

    if(poom_last_profile.ats_len > 0U)
    {
        poom_last_profile.mode = POOM_NFC_EMU_MODE_T4T;
        return;
    }

    if(poom_last_profile.atqa_set && poom_last_profile.sak_set)
    {
        const uint16_t atqa =
            (uint16_t)(((uint16_t)poom_last_profile.atqa[0] << 8) |
                       (uint16_t)poom_last_profile.atqa[1]);
        const nfc_card_type_t t =
            nfc_ident_detect_nfca(atqa, poom_last_profile.sak);
        if(t == NFC_CARD_ULTRALIGHT_OR_NTAG)
        {
            poom_last_profile.mode = POOM_NFC_EMU_MODE_MFUL;
            return;
        }
    }

    poom_last_profile.mode = POOM_NFC_EMU_MODE_3A;
}

/**
 * @brief Internal helper for `poom_last_profile_nfca_uid_append_from_anticol`.
 *
 * @param[in] uid_bcc Parameter passed to the function.
 * @return void
 */
static void poom_last_profile_nfca_uid_append_from_anticol_(const uint8_t uid_bcc[5])
{
    if(uid_bcc == NULL)
    {
        return;
    }

    const uint8_t cascade_tag = 0x88U;

    if(uid_bcc[0] == cascade_tag)
    {
        if((poom_last_profile.uid_len + 3U) <= sizeof(poom_last_profile.uid))
        {
            poom_last_profile.uid[poom_last_profile.uid_len++] = uid_bcc[1];
            poom_last_profile.uid[poom_last_profile.uid_len++] = uid_bcc[2];
            poom_last_profile.uid[poom_last_profile.uid_len++] = uid_bcc[3];
        }
        return;
    }

    if((poom_last_profile.uid_len + 4U) <= sizeof(poom_last_profile.uid))
    {
        poom_last_profile.uid[poom_last_profile.uid_len++] = uid_bcc[0];
        poom_last_profile.uid[poom_last_profile.uid_len++] = uid_bcc[1];
        poom_last_profile.uid[poom_last_profile.uid_len++] = uid_bcc[2];
        poom_last_profile.uid[poom_last_profile.uid_len++] = uid_bcc[3];
    }
}

/**
 * @brief Internal helper for `poom_nfca_uid_bcc_valid`.
 *
 * @param[in] uid_bcc Parameter passed to the function.
 * @return bool
 */
static bool poom_nfca_uid_bcc_valid_(const uint8_t uid_bcc[5])
{
    if(uid_bcc == NULL)
    {
        return false;
    }

    return ((uint8_t)(uid_bcc[0] ^ uid_bcc[1] ^ uid_bcc[2] ^ uid_bcc[3]) == uid_bcc[4]);
}

/* ============================================================================
 * Small printing helpers
 * ========================================================================== */

/**
 * @brief Internal helper for `poom_print_hex_inline`.
 *
 * @param[in] buf Parameter passed to the function.
 * @param[in] len Parameter passed to the function.
 * @return void
 */
static void poom_print_hex_inline_(const uint8_t *buf, uint16_t len)
{
	for (uint16_t i = 0; i < len; i++) {
		printf("%02X", buf[i]);
		if (i + 1 < len) printf(" ");
	}
}

/**
 * @brief Internal helper for `poom_print_hex`.
 *
 * @param[in] buf Parameter passed to the function.
 * @param[in] len Parameter passed to the function.
 * @return void
 */
static void poom_print_hex(const uint8_t *buf, uint16_t len)
{
	poom_print_hex_inline_(buf, len);
	printf("\n");
}

/**
 * @brief Internal helper for `poom_nfca_cascade_name`.
 *
 * @param[in] sel_code Parameter passed to the function.
 * @return const char*
 */
static const char* poom_nfca_cascade_name_(uint8_t sel_code)
{
	switch (sel_code) {
		case POOM_ISO14443A_SEL_CL1: return "CL1";
		case POOM_ISO14443A_SEL_CL2: return "CL2";
		case POOM_ISO14443A_SEL_CL3: return "CL3";
		default:                     return "CL?";
	}
}

/**
 * @brief Internal helper for `poom_print_nfca_anticollision_summary`.
 *
 * @param[in] sel_code Parameter passed to the function.
 * @param[in] uid_bcc Parameter passed to the function.
 * @return void
 */
static void poom_print_nfca_anticollision_summary_(uint8_t sel_code, const uint8_t uid_bcc[5])
{
	if (!poom_verbose || uid_bcc == NULL) {
		return;
	}

	printf("      %s anticollision: UID=", poom_nfca_cascade_name_(sel_code));
	if (uid_bcc[0] == 0x88U) {
		printf("CT ");
		poom_print_hex_inline_(&uid_bcc[1], 3U);
	} else {
		poom_print_hex_inline_(uid_bcc, 4U);
	}
	printf(" BCC=%02X (%s)\n",
	       uid_bcc[4],
	       poom_nfca_uid_bcc_valid_(uid_bcc) ? "ok" : "bad");
}

/**
 * @brief Internal helper for `poom_print_nfca_sak_summary`.
 *
 * @param[in] sel_code Parameter passed to the function.
 * @param[in] sak Parameter passed to the function.
 * @return void
 */
static void poom_print_nfca_sak_summary_(uint8_t sel_code, uint8_t sak)
{
	if (!poom_verbose) {
		return;
	}

	printf("      %s select: SAK=%02X", poom_nfca_cascade_name_(sel_code), sak);
	if ((sak & POOM_ISO14443A_SAK_CASCADE_MASK) != 0U) {
		printf(" -> more UID");
	} else {
		printf(" -> UID complete");
	}
	if ((sak & POOM_ISO14443A_SAK_ISODEP_MASK) != 0U) {
		printf(", ISO-DEP");
	} else {
		printf(", no ISO-DEP");
	}
	printf("\n");
}

/**
 * @brief Internal helper for `poom_print_nfca_final_summary`.
 *
 * @return void
 */
static void poom_print_nfca_final_summary_(void)
{
	if (!poom_verbose || !poom_last_profile_valid) {
		return;
	}

	printf("      UID final: ");
	if (poom_last_profile.uid_len > 0U) {
		poom_print_hex_inline_(poom_last_profile.uid, poom_last_profile.uid_len);
		printf(" (%u bytes)\n", (unsigned)poom_last_profile.uid_len);
	} else {
		printf("<unknown>\n");
	}

	if (poom_last_profile.atqa_set && poom_last_profile.sak_set) {
		uint16_t atqa =
			(uint16_t)(((uint16_t)poom_last_profile.atqa[1] << 8) |
			           (uint16_t)poom_last_profile.atqa[0]);
		nfc_card_type_t type = nfc_ident_detect_nfca(atqa, poom_last_profile.sak);

		printf("      NFCA summary: ATQA=0x%04X SAK=0x%02X Type=%s\n",
		       atqa,
		       poom_last_profile.sak,
		       nfc_ident_card_type_to_str(type));
	}
}

/**
 * @brief Internal helper for `poom_print_ats_summary`.
 *
 * @param[in] ats Parameter passed to the function.
 * @param[in] ats_len Parameter passed to the function.
 * @return void
 */
static void poom_print_ats_summary_(const uint8_t *ats, uint8_t ats_len)
{
	poom_nfc_ats_info_t info;

	if (!poom_verbose || ats == NULL || ats_len < 2U) {
		return;
	}
	if (!poom_nfc_ats_parse(ats, ats_len, &info)) {
		printf("      ATS summary: invalid\n");
		return;
	}

	printf("      ATS summary: TL=%u FSCI=%u FSC=%u",
	       (unsigned)info.tl,
	       (unsigned)info.fsci,
	       (unsigned)info.fsc);

	if (info.ta_present) {
		printf(" TA=%02X", info.ta);
	}

	if (info.tb_present) {
		printf(" TB=%02X FWI=%u SFGI=%u",
		       info.tb,
		       (unsigned)info.fwi,
		       (unsigned)info.sfgi);
	}

	if (info.tc_present) {
		printf(" TC=%02X DID=%s NAD=%s",
		       info.tc,
		       info.did_supported ? "yes" : "no",
		       info.nad_supported ? "yes" : "no");
	}

	if (info.hb_len > 0U) {
		printf(" HB=");
		poom_print_hex_inline_(info.hb, info.hb_len);
	}

	printf("\n");
}

/**
 * @brief Internal helper for `poom_hex_nibble`.
 *
 * @param[in] c Parameter passed to the function.
 * @param[in] out Parameter passed to the function.
 * @return bool
 */
static bool poom_hex_nibble(char c, uint8_t *out)
{
	if ((c >= '0') && (c <= '9')) {
		*out = (uint8_t)(c - '0');
		return true;
	}
	if ((c >= 'a') && (c <= 'f')) {
		*out = (uint8_t)(10 + (c - 'a'));
		return true;
	}
	if ((c >= 'A') && (c <= 'F')) {
		*out = (uint8_t)(10 + (c - 'A'));
		return true;
	}
	return false;
}

/**
 * @brief Internal helper for `poom_ascii_hex_to_bytes`.
 *
 * @param[in] ascii Parameter passed to the function.
 * @param[in] out Parameter passed to the function.
 * @param[in] out_max Parameter passed to the function.
 * @param[in] out_len Parameter passed to the function.
 * @return bool
 */
static bool poom_ascii_hex_to_bytes(const char *ascii, uint8_t *out, uint16_t out_max, uint16_t *out_len)
{
	uint16_t wr = 0;
	int8_t hi = -1;

	if ((ascii == NULL) || (out == NULL) || (out_len == NULL)) return false;

	for (const char *p = ascii; *p != '\0'; p++) {
		uint8_t v = 0;
		char c = *p;

		if (isspace((unsigned char)c) || c == ':' || c == '-' || c == ',') {
			continue;
		}

		if ((c == '0') && ((p[1] == 'x') || (p[1] == 'X'))) {
			p++;
			continue;
		}

		if (!poom_hex_nibble(c, &v)) {
			printf("Invalid hex char: '%c'\n", c);
			return false;
		}

		if (hi < 0) {
			hi = (int8_t)v;
		} else {
			if (wr >= out_max) {
				printf("Hex payload too long (max %u bytes)\n", out_max);
				return false;
			}
			out[wr++] = (uint8_t)(((uint8_t)hi << 4) | v);
			hi = -1;
		}
	}

	if (hi >= 0) {
		printf("Odd number of hex nibbles\n");
		return false;
	}

	*out_len = wr;
	return true;
}

/* ============================================================================
 * Options
 * ========================================================================== */

void poom_reader_set_verbose(bool enable) { poom_verbose = enable; }
bool poom_reader_is_verbose(void) { return poom_verbose; }

bool poom_reader_set_iso_dep_chunk_len(uint8_t value_1_to_250)
{
	if (value_1_to_250 == 0 || value_1_to_250 > 250) return false;
	poom_iso_dep_chunk_len = value_1_to_250;
	return true;
}

/* ============================================================================
 * Error helper
 * ========================================================================== */

#define POOM_RETURN_FALSE_ON_ERR(_ret, _call) \
	do {                                       \
		(_ret) = (_call);                       \
		if ((_ret) != ERR_NONE) {               \
			printf("Error %d\n", (_ret));       \
			return false;                       \
		}                                       \
	} while (0)

/* ============================================================================
 * RFAL transceive wrapper
 * ========================================================================== */

/**
 * @brief Run a blocking RFAL transceive using the shared TX/RX buffers.
 *
 * @param[in] add_crc true to let RFAL manage CRC, false to keep CRC manual.
 * @param[in] verbose true to print TX/RX frames.
 * @return RFAL return code from the transceive operation.
 */
static uint32_t poom_iso_dep_timeout_ticks_(uint8_t wtxm)
{
	uint64_t timeout;
	uint32_t fwt = poom_iso_dep_fwt_ticks;

	if(fwt == 0U)
	{
		fwt = rfalIsoDepFWI2FWT(RFAL_ISODEP_FWI_DEFAULT);
	}
	if(wtxm < POOM_ISO14443_4_WTXM_MIN)
	{
		wtxm = POOM_ISO14443_4_WTXM_MIN;
	}

	timeout = (uint64_t)fwt * (uint64_t)wtxm;
	if(timeout > RFAL_ISODEP_MAX_FWT)
	{
		timeout = RFAL_ISODEP_MAX_FWT;
	}
	timeout += POOM_RFAL_ISODEP_DFWT_TICKS;
	return (uint32_t)timeout;
}

static ReturnCode poom_nfc_transceive_bytes_timeout_(bool add_crc,
	                                                   bool verbose,
	                                                   uint32_t timeout_ticks)
{
	uint32_t flags;
	ReturnCode ret;

	if (verbose) {
		printf("  [TX] ");
		poom_print_hex(poom_tx, poom_tx_len);
	}

	flags = add_crc
		? RFAL_TXRX_FLAGS_DEFAULT
		: ((uint32_t)RFAL_TXRX_FLAGS_CRC_TX_MANUAL | (uint32_t)RFAL_TXRX_FLAGS_CRC_RX_KEEP);

	ret = rfalTransceiveBlockingTxRx(
		poom_tx,
		poom_tx_len,
		poom_rx,
		POOM_RFAL_RX_MAX,
		&poom_rx_len,
		flags,
		timeout_ticks
	);

	if (verbose) {
		if (ret == ERR_NONE) {
			if (poom_rx_len > 0U) {
				printf("  [RX] ");
				poom_print_hex(poom_rx, poom_rx_len);
			} else {
				printf("  [RX] <no data>\n");
			}
		} else {
			if (poom_rx_len > 0U) {
				printf("  [RX] err=%d ", ret);
				poom_print_hex(poom_rx, poom_rx_len);
			} else {
				printf("  [RX] <no response> err=%d\n", ret);
			}
		}
	}

	return ret;
}

static ReturnCode poom_nfc_transceive_bytes(bool add_crc, bool verbose)
{
	const uint32_t timeout_ticks = poom_nfca_isodep_active
		? poom_iso_dep_timeout_ticks_(POOM_ISO14443_4_WTXM_MIN)
		: POOM_RFAL_ACTIVATION_TIMEOUT_TICKS;

	return poom_nfc_transceive_bytes_timeout_(add_crc, verbose, timeout_ticks);
}

/**
 * @brief Execute one NFC-A anticollision/select cascade level.
 *
 * Appends the discovered UID part to the cached activation profile and returns
 * the SAK received for the selected level.
 *
 * @param[in] sel_code NFC-A select code for the cascade level.
 * @param[out] sak_out Optional output SAK byte.
 * @return true on successful anticollision and select, false otherwise.
 */
static bool poom_nfca_select_cascade_level(uint8_t sel_code, uint8_t *sak_out)
{
	ReturnCode ret;

	poom_tx[0] = sel_code;
	poom_tx[1] = POOM_ISO14443A_ANTICOLLISION;
	poom_tx_len = 2;

	ret = poom_nfc_transceive_bytes(false, poom_verbose);
	if (poom_rx_len < POOM_ISO14443A_UID_BCC_LEN) {
		return false;
	}

	if (!poom_nfca_uid_bcc_valid_(poom_rx)) {
		if (poom_verbose) {
			printf("  [RX] invalid UID BCC during anticollision\n");
		}
		return false;
	}

	if (ret != ERR_NONE && poom_verbose) {
		printf("  [RX] anticol recovered from err=%d using valid UID+BCC\n", ret);
	}

	poom_print_nfca_anticollision_summary_(sel_code, poom_rx);

	poom_last_profile_nfca_uid_append_from_anticol_(poom_rx);
	poom_last_profile_valid = true;

	poom_tx[0] = sel_code;
	poom_tx[1] = POOM_ISO14443A_SELECT;
	memcpy(&poom_tx[2], poom_rx, POOM_ISO14443A_UID_BCC_LEN);
	poom_tx_len = 2 + POOM_ISO14443A_UID_BCC_LEN;

	ret = poom_nfc_transceive_bytes(true, poom_verbose);
	if (ret != ERR_NONE || poom_rx_len < 1U) {
		return false;
	}

	if (poom_verbose) {
		printf("  [RX] SAK(%s): %02X\n", poom_nfca_cascade_name_(sel_code), poom_rx[0]);
	}
	poom_print_nfca_sak_summary_(sel_code, poom_rx[0]);

	if (sak_out != NULL) {
		*sak_out = poom_rx[0];
	}
	return true;
}

/* ============================================================================
 * ISO-DEP (ISO/IEC 14443-4) block handling
 * ========================================================================== */

typedef struct {
	uint8_t pcb;
	uint8_t cid;
	uint8_t nad;
	uint8_t inf_len;
	uint8_t *inf;
} poom_iso_dep_block_t;

typedef struct {
	uint8_t max_inf_per_block;
	uint8_t i_block_number;

	bool    use_cid;
	uint8_t cid;

	bool    use_nad;
	uint8_t nad;
} poom_iso_dep_session_t;

static poom_iso_dep_block_t   poom_blk;
static poom_iso_dep_session_t poom_iso_dep;

/**
 * @brief Internal helper for `poom_iso_dep_next_i_block_number`.
 *
 * @return uint8_t
 */
static uint8_t poom_iso_dep_next_i_block_number(void)
{
	uint8_t bn = poom_iso_dep.i_block_number;
	poom_iso_dep.i_block_number ^= 1U;
	return bn;
}

/* ISO/IEC 14443-4: 7.1.1.1 (I-block PCB) */

/**
 * @brief Internal helper for `poom_iso_dep_build_i_block`.
 *
 * @param[in] inf Parameter passed to the function.
 * @param[in] len Parameter passed to the function.
 * @param[in] chaining Parameter passed to the function.
 * @return void
 */
static void poom_iso_dep_build_i_block(uint8_t *inf, uint8_t len, bool chaining)
{
	uint8_t bn = poom_iso_dep_next_i_block_number();

	poom_blk.pcb = (uint8_t)(POOM_ISO14443_4_PCB_I_BLOCK_BASE | (bn & 0x01));

	if (poom_iso_dep.use_cid) {
		poom_blk.pcb |= POOM_ISO14443_4_PCB_HAS_CID;
		poom_blk.cid = poom_iso_dep.cid;
	}
	if (poom_iso_dep.use_nad) {
		poom_blk.pcb |= POOM_ISO14443_4_PCB_HAS_NAD;
		poom_blk.nad = poom_iso_dep.nad;
	}
	if (chaining) {
		poom_blk.pcb |= POOM_ISO14443_4_PCB_CHAINING;
	}

	poom_blk.inf = inf;
	poom_blk.inf_len = len;
}

/* ISO/IEC 14443-4: 7.1.1.1 (R-block PCB). Despite the name, this currently emits ACK. */

/**
 * @brief Internal helper for `poom_iso_dep_build_r_block_nak`.
 *
 * @return void
 */
static void poom_iso_dep_build_r_block_nak(void)
{
	uint8_t bn = poom_iso_dep_next_i_block_number();

	poom_blk.pcb = (uint8_t)(POOM_ISO14443_4_PCB_R_BLOCK_NAK_BASE | (bn & 0x01));

	if (poom_iso_dep.use_cid) {
		poom_blk.pcb |= POOM_ISO14443_4_PCB_HAS_CID;
		poom_blk.cid = poom_iso_dep.cid;
	}

	poom_blk.inf = NULL;
	poom_blk.inf_len = 0;
}

/* ISO/IEC 14443-4: 7.3 WTX (S(WTX)) */

/**
 * @brief Internal helper for `poom_iso_dep_prepare_wtx_response`.
 *
 * @param[in] inf_byte_in_place Parameter passed to the function.
 * @return void
 */
static void poom_iso_dep_prepare_wtx_response(uint8_t *inf_byte_in_place)
{
	inf_byte_in_place[0] &= POOM_ISO14443_4_WTXM_MASK;
	poom_blk.inf = inf_byte_in_place;
	poom_blk.inf_len = 1;
}

/**
 * @brief Parses input data for this module.
 *
 * @param[in] data Parameter passed to the function.
 * @param[in] len Parameter passed to the function.
 * @return void
 */
static void poom_iso_dep_parse_rx_block(uint8_t *data, uint16_t len)
{
	uint16_t idx = 0;

	poom_blk.pcb = data[idx++];

	if (poom_iso_dep.use_nad && idx < len) {
		poom_blk.nad = data[idx++];
	}
	if (poom_iso_dep.use_cid && idx < len) {
		poom_blk.cid = data[idx++];
	}

	poom_blk.inf = &data[idx];
	poom_blk.inf_len = (uint8_t)((idx <= len) ? (len - idx) : 0);
}

/**
 * @brief Internal helper for `poom_iso_dep_send_block`.
 *
 * @return ReturnCode
 */
static ReturnCode poom_iso_dep_send_block_timeout_(uint32_t timeout_ticks)
{
	poom_tx_len = 0;
	poom_tx[poom_tx_len++] = poom_blk.pcb;

	if (poom_iso_dep.use_nad) {
		poom_tx[poom_tx_len++] = poom_blk.nad;
	}
	if (poom_iso_dep.use_cid) {
		poom_tx[poom_tx_len++] = poom_blk.cid;
	}

	if (poom_blk.inf_len && poom_blk.inf != NULL) {
		memcpy(&poom_tx[poom_tx_len], poom_blk.inf, poom_blk.inf_len);
		poom_tx_len += poom_blk.inf_len;
	}

	ReturnCode ret =
		poom_nfc_transceive_bytes_timeout_(true, poom_verbose, timeout_ticks);
	if(ret == ERR_NONE && poom_rx_len > 0U)
	{
		poom_iso_dep_parse_rx_block(poom_rx, poom_rx_len);
	}
	else
	{
		poom_blk.pcb = 0U;
		poom_blk.inf = NULL;
		poom_blk.inf_len = 0U;
	}
	return ret;
}

static ReturnCode poom_iso_dep_send_block(void)
{
	return poom_iso_dep_send_block_timeout_(
		poom_iso_dep_timeout_ticks_(POOM_ISO14443_4_WTXM_MIN));
}

static bool poom_iso_dep_is_wtx_request_(void)
{
	const uint8_t pcb_without_cid =
		(uint8_t)(poom_blk.pcb & (uint8_t)~POOM_ISO14443_4_PCB_HAS_CID);

	return pcb_without_cid == POOM_ISO14443_4_PCB_S_WTX_BASE &&
	       poom_blk.inf != NULL && poom_blk.inf_len == 1U;
}

static bool poom_iso_dep_handle_wtx_(void)
{
	uint8_t wtx_count = 0U;

	while(poom_iso_dep_is_wtx_request_())
	{
		const uint8_t wtxm = (uint8_t)(poom_blk.inf[0] & POOM_ISO14443_4_WTXM_MASK);
		ReturnCode ret;

		if(wtxm < POOM_ISO14443_4_WTXM_MIN || wtxm > POOM_ISO14443_4_WTXM_MAX ||
		   wtx_count >= POOM_ISO14443_4_WTX_MAX)
		{
			return false;
		}
		wtx_count++;
		poom_iso_dep_prepare_wtx_response(poom_blk.inf);
		ret = poom_iso_dep_send_block_timeout_(poom_iso_dep_timeout_ticks_(wtxm));
		if(ret != ERR_NONE)
		{
			printf("Error %d\n", ret);
			return false;
		}
	}

	return true;
}

/**
 * @brief Reset the local ISO-DEP session state to its default values.
 */
static void poom_iso_dep_session_init(uint8_t fwi, bool use_cid)
{
	poom_iso_dep.max_inf_per_block = poom_iso_dep_chunk_len;

	poom_iso_dep.use_cid = use_cid;
	poom_iso_dep.cid = 0;

	poom_iso_dep.use_nad = false;
	poom_iso_dep.nad = 0;

	poom_iso_dep.i_block_number = 0;
	poom_iso_dep_fwt_ticks = rfalIsoDepFWI2FWT(fwi);
}

/* ============================================================================
 * APDU exchange over ISO-DEP (ISO/IEC 14443-4: Clause 7)
 * ========================================================================== */

/**
 * @brief Exchange one C-APDU over ISO-DEP and collect the resulting R-APDU.
 *
 * Handles I-block chaining and WTX processing using the local session state.
 *
 * @param[in] capdu APDU buffer to send.
 * @param[in] capdu_len APDU length in bytes.
 * @return true on successful exchange, false otherwise.
 */
static bool poom_iso_dep_exchange_apdu(uint8_t *capdu, uint32_t capdu_len, bool print_final_rapdu)
{
	ReturnCode ret;
	uint32_t offset = 0;
	int32_t remaining = (int32_t)capdu_len;

	while (remaining > 0) {
		uint8_t chunk = (remaining > poom_iso_dep.max_inf_per_block)
			? poom_iso_dep.max_inf_per_block
			: (uint8_t)remaining;

		bool chaining = (remaining > chunk);

		poom_iso_dep_build_i_block(&capdu[offset], chunk, chaining);

		ret = poom_iso_dep_send_block();
		if (ret != ERR_NONE) {
			printf("Error %d\n", ret);
			return false;
		}
		if (!poom_iso_dep_handle_wtx_()) {
			return false;
		}

		offset += chunk;
		remaining -= chunk;
	}

	if ( (poom_blk.pcb & POOM_ISO14443_4_PCB_S_BLOCK_MASK) == POOM_ISO14443_4_PCB_S_BLOCK_TAG ) {
		return false;
	}

	poom_rapdu_len = 0;
	if (poom_blk.inf_len > 0) {
		memcpy(&poom_rapdu[poom_rapdu_len], poom_blk.inf, poom_blk.inf_len);
		poom_rapdu_len += poom_blk.inf_len;
	}

	while ((poom_blk.pcb & POOM_ISO14443_4_PCB_CHAINING) != 0) {
		poom_iso_dep_build_r_block_nak();

		ret = poom_iso_dep_send_block();
		if (ret != ERR_NONE) {
			printf("Error %d\n", ret);
			return false;
		}
		if (!poom_iso_dep_handle_wtx_()) {
			return false;
		}

		if (poom_blk.inf_len > 0) {
			memcpy(&poom_rapdu[poom_rapdu_len], poom_blk.inf, poom_blk.inf_len);
			poom_rapdu_len += poom_blk.inf_len;
		}
	}

	if (print_final_rapdu) {
		printf("R-APDU: ");
		poom_print_hex(poom_rapdu, poom_rapdu_len);
	}
	return true;
}

/**
 * @brief Activate an NFC-A card and optionally enter ISO-DEP.
 *
 * Performs REQA, anticollision/select, and, when supported by the tag, a RATS
 * exchange to initialize the ISO-DEP session and cache ATS/profile data.
 *
 * @return true on successful activation, false otherwise.
 */
static bool poom_connect_iso14443a(void)
{
	ReturnCode ret;
	uint8_t sak;
	bool is_isodep;

	poom_last_profile_reset_();

	rfalNfcaPollerInitialize();
	rfalFieldOff();
	rfalFieldOnAndStartGT();
	poom_nfca_isodep_active = false;

	if (poom_verbose) printf("  [TX] REQA (%02X)\n", POOM_ISO14443A_CMD_REQA);
	POOM_RETURN_FALSE_ON_ERR(ret,
		rfalNfcaPollerCheckPresence(POOM_ISO14443A_CMD_REQA, (rfalNfcaSensRes *)poom_rx)
	);

	if (poom_verbose) {
		printf("  [RX] ATQA: ");
		poom_print_hex(poom_rx, 2);
		printf("      ATQA summary: 0x%02X%02X\n", poom_rx[1], poom_rx[0]);
	}

	poom_last_profile.atqa[0] = poom_rx[0];
	poom_last_profile.atqa[1] = poom_rx[1];
	poom_last_profile.atqa_set = true;
	poom_last_profile_valid = true;

	if (!poom_nfca_select_cascade_level(POOM_ISO14443A_SEL_CL1, &sak)) {
		return false;
	}
	if ((sak & POOM_ISO14443A_SAK_CASCADE_MASK) != 0U) {
		if (!poom_nfca_select_cascade_level(POOM_ISO14443A_SEL_CL2, &sak)) {
			return false;
		}
		if ((sak & POOM_ISO14443A_SAK_CASCADE_MASK) != 0U) {
			if (!poom_nfca_select_cascade_level(POOM_ISO14443A_SEL_CL3, &sak)) {
				return false;
			}
		}
	}

	is_isodep = ((sak & POOM_ISO14443A_SAK_ISODEP_MASK) != 0U);
	poom_last_profile.sak = sak;
	poom_last_profile.sak_set = true;
	poom_last_profile_valid = true;

	if (!is_isodep) {
		poom_print_nfca_final_summary_();
		return true;
	}

	poom_tx[0] = POOM_ISO14443_4_CMD_RATS;
	poom_tx[1] = poom_iso14443_4_rats_param_make(/*FSDI*/0, /*CID*/0);
	poom_tx_len = 2;
	ret = poom_nfc_transceive_bytes(true, poom_verbose);
	if (ret == ERR_NONE && poom_rx_len > 0U) {
		poom_nfc_ats_info_t ats_info;
		const bool ats_ok =
			poom_nfc_ats_parse(poom_rx, (uint8_t)poom_rx_len, &ats_info);

		if (poom_verbose) {
			printf("  [RX] ATS: ");
			poom_print_hex(poom_rx, poom_rx_len);
		}
		poom_nfca_isodep_active = true;
		poom_iso_dep_session_init(ats_ok ? ats_info.fwi : RFAL_ISODEP_FWI_DEFAULT,
		                          ats_ok && ats_info.did_supported);

		uint16_t copy_len = poom_rx_len;
		if(copy_len > (uint16_t)sizeof(poom_last_profile.ats)) {
			copy_len = (uint16_t)sizeof(poom_last_profile.ats);
		}
		memcpy(poom_last_profile.ats, poom_rx, copy_len);
		poom_last_profile.ats_len = (uint8_t)copy_len;
		poom_last_profile_valid = true;
		poom_print_ats_summary_(poom_rx, (uint8_t)poom_rx_len);
	} else if (poom_verbose) {
		printf("      RATS failed or ATS empty; card stays at ISO/IEC 14443-3A only\n");
	}

	poom_last_profile_set_mode_from_nfca_();
	poom_print_nfca_final_summary_();
	return true;
}

/**
 * @brief Activate an NFC-B card and initialize the ISO-DEP session.
 *
 * Performs REQB/ATQB discovery followed by ATTRIB activation.
 *
 * @return true on successful activation, false otherwise.
 */
static bool poom_connect_iso14443b(void)
{
	ReturnCode ret;

	rfalNfcbPollerInitialize();
	rfalFieldOff();
	rfalFieldOnAndStartGT();

	poom_tx[0] = POOM_ISO14443B_CMD_REQB;
	poom_tx[1] = 0x00; /* AFI = 0 => all families */
	poom_tx[2] = 0x00; /* PARAM: N=1 slot, REQB */
	poom_tx_len = 3;

	POOM_RETURN_FALSE_ON_ERR(ret, poom_nfc_transceive_bytes(true, poom_verbose));

	poom_tx[0] = POOM_ISO14443B_CMD_ATTRIB;
	memcpy(&poom_tx[1], &poom_rx[1], POOM_ISO14443B_PUPI_LEN); /* PUPI from ATQB */

	poom_tx[1 + 4] = 0x00; /* PARAM1 */
	poom_tx[1 + 5] = 0x00; /* PARAM2 */
	poom_tx[1 + 6] = 0x01; /* PARAM3 */
	poom_tx[1 + 7] = 0x00; /* PARAM4 (CID=0) */
	poom_tx_len = 1 + 4 + 4;

	POOM_RETURN_FALSE_ON_ERR(ret, poom_nfc_transceive_bytes(true, poom_verbose));
	poom_iso_dep_session_init(RFAL_ISODEP_FWI_DEFAULT, true);
	return true;
}

/**
 * @brief Activate an ISO 15693 vicinity card with a basic inventory request.
 *
 * @return true on successful activation, false otherwise.
 */
static bool poom_connect_iso15693(void)
{
	ReturnCode ret;

	rfalNfcvPollerInitialize();
	rfalFieldOff();
	rfalFieldOnAndStartGT();

	const uint8_t ISO15693_FLAG_INVENTORY = 0x26;
	const uint8_t ISO15693_CMD_INVENTORY  = 0x01;

	poom_tx[0] = ISO15693_FLAG_INVENTORY;
	poom_tx[1] = ISO15693_CMD_INVENTORY;
	poom_tx[2] = 0x00;
	poom_tx_len = 3;

	POOM_RETURN_FALSE_ON_ERR(ret, poom_nfc_transceive_bytes(true, poom_verbose));
	return true;
}

/* Public API. */

bool poom_reader_send_raw_hex(const char *ascii_hex)
{
	if (!poom_ascii_hex_to_bytes(ascii_hex, poom_ascii_hex_buf, POOM_NFC_BUF_MAX, &poom_ascii_hex_len)) {
		return false;
	}
	if (poom_ascii_hex_len == 0) {
		printf("Empty hex payload\n");
		return false;
	}

	if (poom_mode == RFAL_MODE_POLL_NFCA) {
		if (!poom_nfca_isodep_active) {
			printf("Error: connected NFC-A card is not ISO-DEP (no RATS/ATS).\n");
			return false;
		}
			return poom_iso_dep_exchange_apdu(poom_ascii_hex_buf, poom_ascii_hex_len, true);
		} else if (poom_mode == RFAL_MODE_POLL_NFCB) {
			return poom_iso_dep_exchange_apdu(poom_ascii_hex_buf, poom_ascii_hex_len, true);
	} else if (poom_mode == RFAL_MODE_POLL_NFCV) {
		memcpy(poom_tx, poom_ascii_hex_buf, poom_ascii_hex_len);
		poom_tx_len = (uint16_t)poom_ascii_hex_len;
		return (poom_nfc_transceive_bytes(true, poom_verbose) == ERR_NONE);
	} else {
		printf("Error: no card detected. Run poom_reader_connect_card() first.\n");
		return false;
	}
}

bool poom_reader_isodep_transceive_apdu(const uint8_t* apdu,
                                        size_t apdu_len,
                                        uint8_t* out_rapdu,
                                        size_t out_max,
                                        size_t* out_len)
{
	if(out_len == NULL)
	{
		return false;
	}

	*out_len = 0U;

	if(apdu == NULL || apdu_len == 0U || apdu_len > POOM_NFC_BUF_MAX)
	{
		return false;
	}

	if(poom_mode == RFAL_MODE_POLL_NFCA)
	{
		if(!poom_nfca_isodep_active)
		{
			return false;
		}
	}
	else if(poom_mode != RFAL_MODE_POLL_NFCB)
	{
		return false;
	}

	memcpy(poom_ascii_hex_buf, apdu, apdu_len);
	poom_ascii_hex_len = (uint16_t)apdu_len;

	if(!poom_iso_dep_exchange_apdu(poom_ascii_hex_buf, poom_ascii_hex_len, false))
	{
		return false;
	}

	*out_len = (size_t)poom_rapdu_len;
	if(poom_rapdu_len == 0U)
	{
		return false;
	}

	if(out_rapdu == NULL || out_max < (size_t)poom_rapdu_len)
	{
		return false;
	}

	memcpy(out_rapdu, poom_rapdu, poom_rapdu_len);
	return true;
}

bool poom_reader_get_last_rapdu(uint8_t* out_rapdu, size_t out_max, size_t* out_len)
{
	if(out_len == NULL)
	{
		return false;
	}

	*out_len = (size_t)poom_rapdu_len;
	if(poom_rapdu_len == 0U)
	{
		return false;
	}

	if(out_rapdu == NULL || out_max < (size_t)poom_rapdu_len)
	{
		return false;
	}

	memcpy(out_rapdu, poom_rapdu, poom_rapdu_len);
	return true;
}

bool poom_reader_connect_card(void)
{
	if (poom_connect_iso14443a()) {
		poom_mode = RFAL_MODE_POLL_NFCA;
		printf("  ISO/IEC 14443-A card detected.\n");
		return true;
	} else if (poom_connect_iso14443b()) {
		poom_mode = RFAL_MODE_POLL_NFCB;
		printf("  ISO/IEC 14443-B card detected.\n");
		poom_last_profile_reset_();
		return true;
	} else if (poom_connect_iso15693()) {
		poom_mode = RFAL_MODE_POLL_NFCV;
		printf("  ISO/IEC 15693 (Vicinity) card detected.\n");
		poom_last_profile_reset_();
		return true;
	} else {
		poom_mode = RFAL_MODE_NONE;
		poom_last_profile_reset_();
		printf("  No card detected.\n");
		return false;
	}
}

bool poom_reader_get_last_profile(poom_nfc_profile_t* out_profile)
{
	if(out_profile == NULL)
	{
		return false;
	}

	if(!poom_last_profile_valid)
	{
		return false;
	}

	memcpy(out_profile, &poom_last_profile, sizeof(*out_profile));
	return true;
}
