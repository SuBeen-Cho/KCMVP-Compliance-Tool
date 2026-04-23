/* N60: CTR-003 — CTR nonce generated from CSPRNG (getrandom) */
#include <stdint.h>
#include <sys/random.h>

#define BLOCK_LEN 16

int ctr_enc(const uint8_t *key, const uint8_t *pt, uint8_t *ct, int len) {
    uint8_t ctr[BLOCK_LEN];
    /* CORRECT: getrandom provides CSPRNG-backed nonce for CTR mode */
    if (getrandom(ctr, BLOCK_LEN, 0) != BLOCK_LEN) return -1;
    (void)key; (void)pt; (void)ct; (void)len;
    return 0;
}
