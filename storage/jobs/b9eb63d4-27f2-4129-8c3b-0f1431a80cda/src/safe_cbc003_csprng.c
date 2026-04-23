/* N54: CBC-003 — IV properly generated via CSPRNG (getrandom) */
#include <stdint.h>
#include <sys/random.h>
#include <string.h>

#define BLOCK_LEN 16

int cbc_enc(uint8_t *key, uint8_t *pt, uint8_t *ct, int len) {
    uint8_t iv[BLOCK_LEN];
    /* CORRECT: getrandom() provides CSPRNG-backed randomness for IV */
    if (getrandom(iv, BLOCK_LEN, 0) != BLOCK_LEN) return -1;
    (void)key; (void)pt; (void)ct; (void)len;
    return 0;
}
