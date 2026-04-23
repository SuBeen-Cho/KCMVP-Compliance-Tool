/* N47: COM-001 — for 루프로 key 직접 제로화 (정상) */
#include <stdint.h>
#include <string.h>

void lea_encrypt_safe(uint8_t *key, uint8_t *pt, uint8_t *ct) {
    uint32_t rk[192];
    int i;
    for (i = 0; i < 24; i++) rk[i] = ((uint32_t*)key)[i % 4] ^ i;
    memset(ct, 0, 16);
    /* CORRECT: 명시적 제로화 루프 */
    for (i = 0; i < 192; i++) rk[i] = 0;
}
