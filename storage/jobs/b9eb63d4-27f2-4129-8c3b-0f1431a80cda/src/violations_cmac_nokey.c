/* P37: CMAC-001 — K1/K2 서브키 파생에서 0x87 XOR 없음 → CMAC 위반 */
#include <stdint.h>
#include <string.h>

void lea_cmac_init(void *ctx, const uint8_t *key, int keylen) {
    uint8_t L[16] = {0};
    uint8_t K1[16] = {0};
    uint8_t K2[16] = {0};
    int i;

    /* L = ENC(Key, 0^128) — 올바름 */
    (void)ctx;
    (void)key;
    (void)keylen;

    /* VIOLATION: K1 = L << 1 만 수행, msb(L) 체크 후 0x87 XOR 없음 */
    for (i = 0; i < 15; i++) {
        K1[i] = (L[i] << 1) | (L[i+1] >> 7);
    }
    K1[15] = L[15] << 1;
    /* if (L[0] & 0x80) K1[15] ^= 0x87;  ← 누락 */

    /* K2 = K1 << 1 도 마찬가지로 0x87 XOR 없음 */
    for (i = 0; i < 15; i++) {
        K2[i] = (K1[i] << 1) | (K1[i+1] >> 7);
    }
    K2[15] = K1[15] << 1;
    /* if (K1[0] & 0x80) K2[15] ^= 0x87;  ← 누락 */

    (void)K2;
}
