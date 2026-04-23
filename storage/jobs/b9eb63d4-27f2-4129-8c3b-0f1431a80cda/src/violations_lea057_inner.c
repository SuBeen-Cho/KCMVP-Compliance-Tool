/* P42: LEA-057 — 외부 루프 키 갱신 없이 내부에서만 ct 복사 */
#include <stdint.h>
#include <string.h>

#define BLOCK_LEN 16
#define KEY_LEN   16

void lea_ecb_mct(uint8_t *key, uint8_t *pt, uint8_t *ct) {
    int i, j, k;
    for (i = 0; i < 100; i++) {
        for (j = 0; j < 1000; j++) {
            memcpy(ct, pt, BLOCK_LEN);
            memcpy(pt, ct, BLOCK_LEN);
            /* 내부 루프: key 갱신 없음 */
        }
        /* VIOLATION: 외부 루프에서 key XOR 갱신 누락 */
        /* 올바른 형태: for(k=0;k<KEY_LEN;k++) key[k] ^= ct[k]; */
    }
}
