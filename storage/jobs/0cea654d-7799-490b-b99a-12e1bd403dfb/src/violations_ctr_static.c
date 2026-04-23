/* P36: CTR-002 — static counter → CTR nonce 재사용 위반 */
#include <string.h>

typedef struct { unsigned char *key; int keylen; } CTRCtx;

void ctr_init(CTRCtx *ctx, unsigned char *iv, unsigned int ivlen) {
    static unsigned char counter[16];   /* VIOLATION: static counter → 재사용 */
    memcpy(counter, iv, ivlen);
    (void)ctx;
}

void ctr_encrypt(CTRCtx *ctx, const unsigned char *pt, unsigned char *ct, unsigned int len) {
    unsigned int i;
    for (i = 0; i < len; i++) {
        ct[i] = pt[i] ^ 0xAA;
    }
    (void)ctx;
}
