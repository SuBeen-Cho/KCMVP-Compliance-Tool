/* N42: CTR-001 — 단일 ctr_encrypt 함수, 복호화 별도 없음 (대칭) */
#include <stdint.h>

#define BLOCK_LEN 16

void lea_encrypt(uint8_t *key, uint8_t *in, uint8_t *out);

/* CTR 모드: 암호화=복호화이므로 하나의 함수 */
void lea_ctr(uint8_t *key, uint8_t *ctr, uint8_t *in, uint8_t *out, int len) {
    uint8_t ks[BLOCK_LEN];
    lea_encrypt(key, ctr, ks);  /* CORRECT */
    int i;
    for (i = 0; i < len; i++) out[i] = in[i] ^ ks[i];
    ctr[15]++;
}
