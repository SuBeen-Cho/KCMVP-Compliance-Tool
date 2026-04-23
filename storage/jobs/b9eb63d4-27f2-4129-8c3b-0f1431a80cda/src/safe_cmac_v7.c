/* N29: CMAC-001 — 올바른 K1/K2 서브키 파생 (정상) */
#include <stdint.h>
#include <string.h>

void lea_cmac_init(void *ctx, const uint8_t *key, int keylen) {
    uint8_t L[16] = {0};
    uint8_t K1[16] = {0};
    uint8_t K2[16] = {0};
    int i;

    (void)ctx;
    (void)key;
    (void)keylen;

    /* K1 = L << 1, msb(L)==1 이면 K1[15] ^= 0x87 */
    for (i = 0; i < 15; i++) {
        K1[i] = (L[i] << 1) | (L[i+1] >> 7);
    }
    K1[15] = L[15] << 1;
    if (L[0] & 0x80) K1[15] ^= 0x87;   /* CORRECT: Rb XOR */

    /* K2 = K1 << 1, msb(K1)==1 이면 K2[15] ^= 0x87 */
    for (i = 0; i < 15; i++) {
        K2[i] = (K1[i] << 1) | (K1[i+1] >> 7);
    }
    K2[15] = K1[15] << 1;
    if (K1[0] & 0x80) K2[15] ^= 0x87;  /* CORRECT: Rb XOR */

    (void)K2;
}
