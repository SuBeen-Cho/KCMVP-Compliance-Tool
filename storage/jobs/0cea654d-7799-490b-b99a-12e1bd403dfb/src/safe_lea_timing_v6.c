/* N26: LEA-042 — 상수 시간 비교 (조건 분기 없음) → 정상 */
#include <stdint.h>
#include <string.h>

#define LEA_KEYLEN 16

/* Constant-time: 분기 없이 XOR 연산만 사용 */
void lea_encrypt(uint32_t *ct, const uint32_t *pt, const uint8_t *key) {
    int i;
    uint32_t mask = 0;
    /* no data-dependent branch on key — constant time */
    for (i = 0; i < LEA_KEYLEN; i++) {
        mask ^= key[i];   /* XOR only, no conditional branch */
    }
    ct[0] = pt[0] ^ mask;
    ct[1] = pt[1] + ct[0];
    ct[2] = pt[2] ^ ct[1];
    ct[3] = pt[3] + ct[2];
}
