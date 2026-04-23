/* P46: LEA-003 — key_setup에서 라운드 16 (유효 값: 24/28/32) */
#include <stdint.h>

void key_setup(uint8_t *key, int keylen, uint32_t *rk) {
    int i;
    /* VIOLATION: 어떤 키 길이도 16 라운드를 쓰지 않음 */
    for (i = 0; i < 16; i++) {
        rk[i] = ((uint32_t)key[i % keylen]) << (i & 7);
    }
}
