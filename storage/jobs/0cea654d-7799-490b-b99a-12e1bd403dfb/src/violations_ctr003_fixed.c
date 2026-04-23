/* P62: CTR-003 — CTR nonce/counter is a fixed constant (not from DRBG) */
#include <stdint.h>
#include <string.h>

#define BLOCK_LEN 16

/* VIOLATION: fixed nonce reused across all CTR encrypt calls */
static const uint8_t FIXED_NONCE[BLOCK_LEN] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};

void ctr_enc(const uint8_t *key, const uint8_t *pt, uint8_t *ct, int len) {
    uint8_t ctr[BLOCK_LEN];
    /* VIOLATION: nonce should come from DRBG/getrandom, not a constant */
    memcpy(ctr, FIXED_NONCE, BLOCK_LEN);
    (void)key; (void)pt; (void)ct; (void)len;
}
