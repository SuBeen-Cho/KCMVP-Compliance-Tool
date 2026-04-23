/* N39: LEA-057 — MCT 정상: key[k] ^= ct[k] 갱신 있음 */
#include <stdint.h>
#include <string.h>

#define BLOCK_LEN 16
#define KEY_LEN   16

void lea_mct(uint8_t *key, uint8_t *pt, uint8_t *ct) {
    int i, j, k;
    for (i = 0; i < 100; i++) {
        for (j = 0; j < 1000; j++) {
            memcpy(ct, pt, BLOCK_LEN);
            memcpy(pt, ct, BLOCK_LEN);
        }
        /* CORRECT: 외부 루프 후 키 XOR 갱신 */
        for (k = 0; k < KEY_LEN; k++) {
            key[k] ^= ct[k];
        }
    }
}
