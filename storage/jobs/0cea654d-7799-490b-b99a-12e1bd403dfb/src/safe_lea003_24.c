/* N45: LEA-003 — lea_key_schedule: 128비트 키에 24 라운드 (정상) */
#include <stdint.h>

#define LEA_ROUNDS_128 24

void lea_key_schedule_128(uint32_t *key, uint32_t *rk) {
    int i;
    for (i = 0; i < 24; i++) {  /* CORRECT: 128비트 → 24 라운드 */
        rk[i * 6 + 0] = key[0] ^ (i * 0x9e3779b9);
        rk[i * 6 + 1] = key[1] ^ (i * 0x9e3779b9);
    }
}
