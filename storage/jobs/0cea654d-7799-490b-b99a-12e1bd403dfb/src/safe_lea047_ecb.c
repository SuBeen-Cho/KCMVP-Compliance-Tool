/* N36: LEA-047 — ECB-MCT 정상: 내부 루프 후 PT = CT[j] */
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
            memcpy(pt, ct, BLOCK_LEN);  /* CORRECT: PT ← CT (ECB-MCT 갱신) */
        }
        key[0] ^= ct[0];  /* key update */
    }
}
