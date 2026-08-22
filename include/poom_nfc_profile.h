#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "poom_nfc_emulator.h"

#ifdef __cplusplus
extern "C" {
#endif

#define POOM_NFC_PROFILE_NAME_MAX (16U)

typedef struct
{
    poom_nfc_emu_mode_t mode;

    uint8_t uid[10];
    uint8_t uid_len; /* 4, 7, 10 */

    uint8_t atqa[2];
    bool atqa_set;

    uint8_t sak;
    bool sak_set;

    uint8_t ats[32]; /* ATS: TL + body */
    uint8_t ats_len;

    char name[POOM_NFC_PROFILE_NAME_MAX]; /* optional label */
    bool name_set;
} poom_nfc_profile_t;

static inline void poom_nfc_profile_clear(poom_nfc_profile_t* p)
{
    if(p == NULL)
    {
        return;
    }
    (void)memset(p, 0, sizeof(*p));
}

static inline bool poom_nfc_profile_has_uid(const poom_nfc_profile_t* p)
{
    return (p != NULL) && (p->uid_len > 0U);
}

#ifdef __cplusplus
}
#endif
