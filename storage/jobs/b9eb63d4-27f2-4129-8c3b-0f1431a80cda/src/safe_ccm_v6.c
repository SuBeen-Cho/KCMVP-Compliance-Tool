/* N25: CCM-001 — 매번 fresh nonce 생성 → 정상 */
#include <string.h>

typedef struct { unsigned char *key; int keylen; } CCMCtx;

void ccm_init(CCMCtx *ctx, unsigned char *pt, unsigned int ptlen) {
    unsigned char nonce[8];    /* stack: no reuse */
    unsigned char ciphertext[256];
    /* getrandom(nonce, 8, 0); */    /* fresh random nonce each call */
    memcpy(ciphertext, pt, ptlen);
    (void)ctx;
    (void)nonce;
}
