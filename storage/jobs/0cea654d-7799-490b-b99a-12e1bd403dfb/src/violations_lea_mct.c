/* P35: LEA-046 — MCT 이중 루프가 10x100 (100x1000 이어야 함) */
#include <stdint.h>
#include <string.h>

#define BLOCK_LEN 16

void lea_mct(uint8_t *key, uint8_t *pt, uint8_t *ct) {
    int i, j;
    uint8_t tmp[BLOCK_LEN];
    /* VIOLATION: 외부 루프 10, 내부 루프 100 → 100×1000 이어야 함 */
    for (i = 0; i < 10; i++) {           /* should be i < 100 */
        for (j = 0; j < 100; j++) {      /* should be j < 1000 */
            memcpy(tmp, pt, BLOCK_LEN);
            memcpy(ct, tmp, BLOCK_LEN);
        }
        /* key update after outer loop */
        key[0] ^= ct[0];
    }
}
