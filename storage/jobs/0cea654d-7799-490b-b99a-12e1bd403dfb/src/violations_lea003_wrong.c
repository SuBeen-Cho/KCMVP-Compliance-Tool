/* P45: LEA-003 — 키 스케줄 라운드 수 20 (올바른 값: 24/28/32) */
#include <stdint.h>

#define BLOCK_WORDS 4

void lea_key_schedule(uint32_t *key, uint32_t *rk) {
    int i;
    /* VIOLATION: 128비트 키에 24 라운드가 맞으나 20으로 잘못 설정 */
    for (i = 0; i < 20; i++) {
        rk[i * 6 + 0] = key[0] + i;
        rk[i * 6 + 1] = key[1] ^ i;
        rk[i * 6 + 2] = key[2] + i;
        rk[i * 6 + 3] = key[3] ^ i;
    }
}
