/* N24: GCM-001 — 매번 fresh nonce 생성 (static 아님) → 정상 */
#include <string.h>

typedef struct { unsigned char *key; int keylen; } GCMCtx;

/* stack 할당 nonce + getrandom → 재사용 없음 */
void gcm_init(GCMCtx *ctx, unsigned char *pt, unsigned int ptlen) {
    unsigned char nonce[12];   /* stack: no reuse */
    unsigned char ciphertext[256];
    /* getrandom(nonce, 12, 0); */   /* fresh random nonce each call */
    memcpy(ciphertext, pt, ptlen);
    (void)ctx;
    (void)nonce;
}
