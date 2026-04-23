/* P55: CBC-003 — IV generated with non-cryptographic rand() */
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#define BLOCK_LEN 16

void cbc_enc(uint8_t *key, uint8_t *pt, uint8_t *ct, int len) {
    uint8_t iv[BLOCK_LEN];
    int i;
    /* VIOLATION: rand() is not a CSPRNG; IV must come from DRBG/getrandom */
    srand((unsigned int)time(NULL));
    for (i = 0; i < BLOCK_LEN; i++) {
        iv[i] = (uint8_t)(rand() & 0xFF);
    }
    (void)key; (void)pt; (void)ct; (void)len;
}
