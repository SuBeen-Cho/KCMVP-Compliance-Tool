/* N27: LEA-046 — MCT 이중 루프 100×1000 → 정상 */
#include <stdint.h>
#include <string.h>

#define BLOCK_LEN 16

void lea_mct(uint8_t *key, uint8_t *pt, uint8_t *ct) {
    int i, j;
    uint8_t tmp[BLOCK_LEN];
    /* CORRECT: 외부 100, 내부 1000 */
    for (i = 0; i < 100; i++) {          /* correct outer bound */
        for (j = 0; j < 1000; j++) {     /* correct inner bound */
            memcpy(tmp, pt, BLOCK_LEN);
            memcpy(ct, tmp, BLOCK_LEN);
        }
        /* key update: Key ^= CT[999] (128-bit) */
        key[0] ^= ct[0];
    }
}
