/* P56: CBC-003 — IV is a hardcoded constant (all zeros) */
#include <stdint.h>
#include <string.h>

#define BLOCK_LEN 16

static const uint8_t FIXED_IV[BLOCK_LEN] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

void cbc_enc(uint8_t *key, uint8_t *pt, uint8_t *ct, int len) {
    uint8_t iv[BLOCK_LEN];
    /* VIOLATION: hardcoded constant IV is predictable and breaks CBC security */
    memcpy(iv, FIXED_IV, BLOCK_LEN);
    (void)key; (void)pt; (void)ct; (void)len;
}
