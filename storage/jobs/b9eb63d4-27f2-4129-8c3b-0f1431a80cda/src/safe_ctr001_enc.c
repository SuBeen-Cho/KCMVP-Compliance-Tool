/* N41: CTR-001 — ctr_encrypt/decrypt 모두 lea_encrypt 사용 (정상) */
#include <stdint.h>

#define BLOCK_LEN 16

void lea_encrypt(uint8_t *key, uint8_t *pt, uint8_t *ct);

void ctr_encrypt(uint8_t *key, uint8_t *ctr, uint8_t *pt, uint8_t *ct, int len) {
    uint8_t ks[BLOCK_LEN];
    lea_encrypt(key, ctr, ks);  /* CORRECT */
    int i;
    for (i = 0; i < len; i++) ct[i] = pt[i] ^ ks[i];
    ctr[15]++;
}

void ctr_decrypt(uint8_t *key, uint8_t *ctr, uint8_t *ct, uint8_t *pt, int len) {
    uint8_t ks[BLOCK_LEN];
    lea_encrypt(key, ctr, ks);  /* CORRECT: 복호화도 ENC 사용 */
    int i;
    for (i = 0; i < len; i++) pt[i] = ct[i] ^ ks[i];
    ctr[15]++;
}
