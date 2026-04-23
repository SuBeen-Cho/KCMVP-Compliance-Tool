/* P67: LEA-047 CTR variant — ctr_mct loop without counter increment */
#include <stdint.h>
#include <string.h>

#define BLOCK_LEN 16
#define MCT_ITERATIONS 1000

typedef struct { uint8_t rk[1152]; } LEA_CTR_CTX;

int lea_ctr_enc(LEA_CTR_CTX *ctx, uint8_t *ct, const uint8_t *pt,
                int len, uint8_t *ctr);

void ctr_mct(LEA_CTR_CTX *ctx, uint8_t *pt, uint8_t *ct, uint8_t *ctr) {
    int i;
    uint8_t buf[BLOCK_LEN];
    memcpy(buf, pt, BLOCK_LEN);

    for (i = 0; i < MCT_ITERATIONS; i++) {
        /* VIOLATION: counter not incremented between MCT iterations */
        lea_ctr_enc(ctx, ct, buf, BLOCK_LEN, ctr);
        memcpy(buf, ct, BLOCK_LEN);
        /* ctr should be incremented here: ctr[15]++ with carry propagation */
    }
}
