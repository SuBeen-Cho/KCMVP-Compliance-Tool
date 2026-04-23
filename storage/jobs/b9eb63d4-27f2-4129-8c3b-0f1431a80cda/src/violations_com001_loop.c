/* P47: COM-001 — 암호화 후 rk 제로화 없음 (memset만 있고 안전 제로화 누락) */
#include <stdint.h>
#include <string.h>

void lea_encrypt(uint8_t *key, uint8_t *pt, uint8_t *ct) {
    uint32_t rk[192];  /* 라운드키 — 사용 후 제로화 필요 */
    int i;
    /* 키 스케줄 */
    for (i = 0; i < 24; i++) rk[i] = ((uint32_t*)key)[i % 4] ^ i;
    /* 암호화 수행 */
    memset(ct, 0, 16);
    /* VIOLATION: rk 배열 사용 후 안전 제로화(memset_s/explicit_bzero) 없음 */
}
