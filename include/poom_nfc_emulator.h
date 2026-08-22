#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum
{
    POOM_NFC_EMU_MODE_3A = 0,  /* ISO14443A L3 (anticollision/select only) */
    POOM_NFC_EMU_MODE_T4T,     /* ISO-DEP + Type 4 Tag APDU handling */
    POOM_NFC_EMU_MODE_MFUL,    /* MIFARE Ultralight-like L3 commands */
} poom_nfc_emu_mode_t;

typedef struct
{
    poom_nfc_emu_mode_t mode;
    uint8_t uid[10];
    uint8_t uid_len;   /* 4 or 7 */
    uint8_t sak;
    bool sak_set;
    uint8_t atqa[2];
    bool atqa_set;

    uint8_t ats[32];   /* full ATS bytes (TL + body), optional */
    uint8_t ats_len;

    char uri[128];     /* used by T4T URI payload builder */
    bool uri_set;

    char image_path[128]; /* optional MFUL image path:
                           * Flipper .nfc (NTAG213/215) supported
                           * 64 legacy
                           * 180 NTAG213 data-only, 212 NTAG213+signature
                           * 540 NTAG215 data-only, 572 NTAG215+signature */
    bool image_path_set;
} poom_nfc_emu_cfg_t;

void poom_nfc_emulator_init(void);
void poom_nfc_emulator_reset_config(void);

bool poom_nfc_emulator_set_mode(poom_nfc_emu_mode_t mode);
bool poom_nfc_emulator_set_uid(const uint8_t* uid, uint8_t uid_len);
bool poom_nfc_emulator_set_sak(uint8_t sak);
bool poom_nfc_emulator_set_atqa(const uint8_t atqa[2]);
bool poom_nfc_emulator_set_ats(const uint8_t* ats, uint8_t ats_len);
bool poom_nfc_emulator_set_uri(const char* uri);
bool poom_nfc_emulator_clear_uri(void);
bool poom_nfc_emulator_set_mful_image_file(const char* path);

bool poom_nfc_emulator_start(void);
void poom_nfc_emulator_stop(void);
bool poom_nfc_emulator_is_running(void);

void poom_nfc_emulator_get_config(poom_nfc_emu_cfg_t* out_cfg);
const char* poom_nfc_emulator_mode_to_str(poom_nfc_emu_mode_t mode);

#ifdef __cplusplus
}
#endif
