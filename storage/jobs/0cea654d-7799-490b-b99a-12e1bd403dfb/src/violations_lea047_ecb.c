/* P39: LEA-047 — ECB-MCT: 내부 루프 후 PT←CT 갱신 없음 */
#include <stdint.h>
#include <string.h>

#define BLOCK_LEN 16

void lea_ecb_mct(uint8_t *key, uint8_t *pt, uint8_t *ct) {
    int i, j;
    uint8_t tmp[BLOCK_LEN];

    for (i = 0; i < 100; i++) {
        for (j = 0; j < 1000; j++) {
            memcpy(tmp, pt, BLOCK_LEN);
            memcpy(ct, tmp, BLOCK_LEN);
            /* VIOLATION: ECB-MCT는 내부 루프 후 PT = CT[j] 해야 함
               여기서는 PT 갱신 없이 다음 반복으로 넘어감 */
        }
        /* key update */
        key[0] ^= ct[0];
    }
}
