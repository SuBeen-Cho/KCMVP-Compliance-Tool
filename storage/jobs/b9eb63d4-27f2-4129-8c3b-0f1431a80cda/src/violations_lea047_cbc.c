/* P40: LEA-047 — CBC-MCT: IV 갱신 없음 */
#include <stdint.h>
#include <string.h>

#define BLOCK_LEN 16

void lea_cbc_mct(uint8_t *key, uint8_t *iv, uint8_t *pt, uint8_t *ct) {
    int i, j;
    uint8_t tmp[BLOCK_LEN];

    for (i = 0; i < 100; i++) {
        for (j = 0; j < 1000; j++) {
            /* CBC 암호화 */
            int k;
            for (k = 0; k < BLOCK_LEN; k++) tmp[k] = pt[k] ^ iv[k];
            memcpy(ct, tmp, BLOCK_LEN);
            /* VIOLATION: CBC-MCT는 IV = CT[j-1] 갱신이 있어야 함
               여기서는 IV 갱신 없음 */
            memcpy(pt, ct, BLOCK_LEN);
        }
        key[0] ^= ct[0];
    }
}
