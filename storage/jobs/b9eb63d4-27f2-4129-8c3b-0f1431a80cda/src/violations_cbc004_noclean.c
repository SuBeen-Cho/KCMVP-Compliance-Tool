/* P61: CBC-004 — CBC IV and local key copy not zeroed after use */
#include <stdint.h>
#include <string.h>

#define BLOCK_LEN 16

void cbc_enc(const uint8_t *key, const uint8_t *iv_in,
             const uint8_t *pt, uint8_t *ct, int len) {
    uint8_t iv[BLOCK_LEN];
    uint8_t local_key[32];
    int i, j;
    memcpy(iv, iv_in, BLOCK_LEN);
    memcpy(local_key, key, 32);

    for (i = 0; i < len / BLOCK_LEN; i++) {
        uint8_t block[BLOCK_LEN];
        for (j = 0; j < BLOCK_LEN; j++)
            block[j] = pt[i*BLOCK_LEN+j] ^ iv[j];
        /* simplified: copy block to ct and update iv */
        memcpy(ct + i*BLOCK_LEN, block, BLOCK_LEN);
        memcpy(iv, block, BLOCK_LEN);
    }
    /* VIOLATION: iv and local_key must be zeroed with memset_s after use */
}
