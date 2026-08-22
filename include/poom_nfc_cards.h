#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define POOM_NFC_CARD_UID_MAX (16U)

#define POOM_NFC_CARD_FLAG_ATQA_SET (1U << 0)
#define POOM_NFC_CARD_FLAG_SAK_SET  (1U << 1)

typedef struct
{
    uint8_t type;
    uint8_t uid_len;
    uint8_t uid[POOM_NFC_CARD_UID_MAX];
    uint8_t flags;   /* POOM_NFC_CARD_FLAG_* */
    uint8_t atqa[2]; /* NFC-A only */
    uint8_t sak;     /* NFC-A only */
} poom_nfc_card_id_t;

static inline bool poom_nfc_card_id_is_valid(const poom_nfc_card_id_t* id)
{
    if (id == NULL)
    {
        return false;
    }
    if ((id->uid_len == 0U) || (id->uid_len > POOM_NFC_CARD_UID_MAX))
    {
        return false;
    }
    return true;
}

static inline bool poom_nfc_card_id_equal(const poom_nfc_card_id_t* a, const poom_nfc_card_id_t* b)
{
    size_t i;

    if ((a == NULL) || (b == NULL))
    {
        return false;
    }

    if ((a->type != b->type) || (a->uid_len != b->uid_len))
    {
        return false;
    }

    for (i = 0U; i < (size_t)a->uid_len; i++)
    {
        if (a->uid[i] != b->uid[i])
        {
            return false;
        }
    }

    return true;
}

#ifdef __cplusplus
}
#endif
