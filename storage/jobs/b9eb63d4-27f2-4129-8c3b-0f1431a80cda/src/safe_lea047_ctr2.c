/* N65: LEA-047 CTR variant — ctr_mct with correct counter increment per iteration */
#include <stdint.h>
#include <string.h>

#define BLOCK_LEN 16
#define MCT_ITERATIONS 1000

typedef struct { uint8_t rk[1152]; } LEA_CTR_CTX;

int lea_ctr_enc(LEA_CTR_CTX *ctx, uint8_t *ct, const uint8_t *pt,
                int len, uint8_t *ctr);

/* CORRECT: increment 128-bit big-endian counter by 1 */
static void increment_ctr(uint8_t *ctr, int ctrlen) {
    int i;
    for (i = ctrlen - 1; i >= 0; i--) {
        if (++ctr[i] != 0) break;
    }
}

void ctr_mct(LEA_CTR_CTX *ctx, uint8_t *pt, uint8_t *ct, uint8_t *ctr) {
    int i;
    uint8_t buf[BLOCK_LEN];
    memcpy(buf, pt, BLOCK_LEN);

    for (i = 0; i < MCT_ITERATIONS; i++) {
        lea_ctr_enc(ctx, ct, buf, BLOCK_LEN, ctr);
        memcpy(buf, ct, BLOCK_LEN);
        /* CORRECT: increment counter after each block */
        increment_ctr(ctr, BLOCK_LEN);
    }
}
