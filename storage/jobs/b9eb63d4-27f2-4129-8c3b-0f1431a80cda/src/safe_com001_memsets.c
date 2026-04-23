/* N48: COM-001 — memset_s로 안전 제로화 (정상) */
#include <stdint.h>
#include <string.h>

void lea_decrypt_safe(uint8_t *key, uint8_t *ct, uint8_t *pt) {
    uint32_t rk[192];
    int i;
    for (i = 0; i < 24; i++) rk[i] = ((uint32_t*)key)[i % 4] ^ i;
    /* 복호화 수행 */
    pt[0] ^= ct[0];
    /* CORRECT: memset_s로 안전 제로화 */
    memset_s(rk, sizeof(rk), 0, sizeof(rk));
}
