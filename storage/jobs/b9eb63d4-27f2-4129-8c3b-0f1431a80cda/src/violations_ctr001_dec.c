/* P43: CTR-001 — ctr_decrypt가 내부에서 lea_decrypt 호출 (ENC 써야 함) */
#include <stdint.h>
#include <string.h>

#define BLOCK_LEN 16

void lea_encrypt(uint8_t *key, uint8_t *pt, uint8_t *ct);
void lea_decrypt(uint8_t *key, uint8_t *ct, uint8_t *pt);

void ctr_encrypt(uint8_t *key, uint8_t *ctr, uint8_t *pt, uint8_t *ct, int len) {
    uint8_t ks[BLOCK_LEN];
    lea_encrypt(key, ctr, ks);  /* CORRECT: ENC 사용 */
    int i;
    for (i = 0; i < len; i++) ct[i] = pt[i] ^ ks[i];
    ctr[15]++;
}

void ctr_decrypt(uint8_t *key, uint8_t *ctr, uint8_t *ct, uint8_t *pt, int len) {
    uint8_t ks[BLOCK_LEN];
    lea_decrypt(key, ctr, ks);  /* VIOLATION: CTR는 복호화도 ENC 사용해야 함 */
    int i;
    for (i = 0; i < len; i++) pt[i] = ct[i] ^ ks[i];
    ctr[15]++;
}
