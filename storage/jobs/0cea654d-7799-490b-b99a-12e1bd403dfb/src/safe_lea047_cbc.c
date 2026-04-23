/* N37: LEA-047 — CBC-MCT 정상: IV 갱신 포함 */
#include <stdint.h>
#include <string.h>

#define BLOCK_LEN 16

void lea_cbc_mct(uint8_t *key, uint8_t *iv, uint8_t *pt, uint8_t *ct) {
    int i, j, k;
    uint8_t tmp[BLOCK_LEN];
    uint8_t prev_ct[BLOCK_LEN];

    for (i = 0; i < 100; i++) {
        for (j = 0; j < 1000; j++) {
            for (k = 0; k < BLOCK_LEN; k++) tmp[k] = pt[k] ^ iv[k];
            memcpy(ct, tmp, BLOCK_LEN);
            memcpy(prev_ct, iv, BLOCK_LEN);
            memcpy(iv, ct, BLOCK_LEN);  /* CORRECT: IV ← CT[j] (CBC-MCT 갱신) */
            memcpy(pt, ct, BLOCK_LEN);
        }
        key[0] ^= ct[0];
    }
}
