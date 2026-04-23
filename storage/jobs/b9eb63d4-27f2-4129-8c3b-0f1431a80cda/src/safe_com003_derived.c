/* N56: COM-003 — key derived from password via KDF, not hardcoded */
#include <stdint.h>
#include <string.h>

#define KEY_LEN 32

/* CORRECT: key material derived at runtime from external input via KDF */
int derive_key(const uint8_t *password, int pwlen,
               const uint8_t *salt, int saltlen,
               uint8_t *key, int keylen) {
    /* Placeholder for PBKDF2/HKDF call — actual KDF would go here */
    if (!password || pwlen <= 0 || !salt || saltlen <= 0) return -1;
    /* In a real implementation this calls a proper KDF */
    (void)key; (void)keylen;
    return 0;
}
