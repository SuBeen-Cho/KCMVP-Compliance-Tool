/* N38: LEA-047 — CTR-MCT 정상: 카운터 증가 포함 */
#include <stdint.h>
#include <string.h>

#define BLOCK_LEN 16

void lea_ctr_mct(uint8_t *key, uint8_t *ctr, uint8_t *pt, uint8_t *ct) {
    int i, j, k;
    uint8_t ks[BLOCK_LEN];

    for (i = 0; i < 100; i++) {
        for (j = 0; j < 1000; j++) {
            memcpy(ks, ctr, BLOCK_LEN);
            for (k = 0; k < BLOCK_LEN; k++) ct[k] = pt[k] ^ ks[k];
            /* CORRECT: CTR-MCT 카운터 증가 */
            for (k = BLOCK_LEN - 1; k >= 0; k--) {
                if (++ctr[k]) break;  /* 128비트 카운터 증가 */
            }
        }
        key[0] ^= ct[0];
    }
}
