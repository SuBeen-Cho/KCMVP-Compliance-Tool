/* P44: CTR-001 — ctr_encrypt/decrypt 모두 lea_decrypt 호출 */
#include <stdint.h>

#define BLOCK_LEN 16

void lea_decrypt(uint8_t *key, uint8_t *ct, uint8_t *pt);

void ctr_encrypt(uint8_t *key, uint8_t *ctr, uint8_t *pt, uint8_t *ct, int len) {
    uint8_t ks[BLOCK_LEN];
    lea_decrypt(key, ctr, ks);  /* VIOLATION */
    int i;
    for (i = 0; i < len; i++) ct[i] = pt[i] ^ ks[i];
}

void ctr_decrypt(uint8_t *key, uint8_t *ctr, uint8_t *ct, uint8_t *pt, int len) {
    uint8_t ks[BLOCK_LEN];
    lea_decrypt(key, ctr, ks);  /* VIOLATION */
    int i;
    for (i = 0; i < len; i++) pt[i] = ct[i] ^ ks[i];
}
