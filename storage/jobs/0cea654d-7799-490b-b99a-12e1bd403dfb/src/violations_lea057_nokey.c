/* P41: LEA-057 — MCT 외부 루프에 키 XOR 갱신 없음 */
#include <stdint.h>
#include <string.h>

#define BLOCK_LEN 16

void lea_mct(uint8_t *key, uint8_t *pt, uint8_t *ct) {
    int i, j;
    for (i = 0; i < 100; i++) {
        for (j = 0; j < 1000; j++) {
            memcpy(ct, pt, BLOCK_LEN);
            memcpy(pt, ct, BLOCK_LEN);
        }
        /* VIOLATION: 외부 루프 후 key ^= ct 갱신이 없음 */
    }
}
