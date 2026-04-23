/* N44: CTR-001 — 내부 ENC 함수 이름이 일반적 (block_cipher), lea_decrypt 호출 없음 */
#include <stdint.h>

#define BLOCK_LEN 16

void block_cipher_enc(uint8_t *key, uint8_t *in, uint8_t *out);

void ctr_encrypt(uint8_t *key, uint8_t *ctr, uint8_t *pt, uint8_t *ct, int len) {
    uint8_t ks[BLOCK_LEN];
    block_cipher_enc(key, ctr, ks);  /* 일반 ENC 함수 사용 (정상) */
    int i;
    for (i = 0; i < len; i++) ct[i] = pt[i] ^ ks[i];
    ctr[15]++;
}

void ctr_decrypt(uint8_t *key, uint8_t *ctr, uint8_t *ct, uint8_t *pt, int len) {
    uint8_t ks[BLOCK_LEN];
    block_cipher_enc(key, ctr, ks);  /* CORRECT */
    int i;
    for (i = 0; i < len; i++) pt[i] = ct[i] ^ ks[i];
    ctr[15]++;
}
