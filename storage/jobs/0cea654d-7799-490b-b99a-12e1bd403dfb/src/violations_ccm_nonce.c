/* P33: CCM-001 — static nonce 재사용 위반 */
#include <string.h>

typedef struct { unsigned char *key; int keylen; } CCMCtx;

/* static 선언된 nonce → CTR 키스트림 반복으로 기밀성 파괴 */
void ccm_init(CCMCtx *ctx, unsigned char *pt, unsigned int ptlen) {
    static unsigned char nonce[8];   /* VIOLATION: static nonce */
    unsigned char ciphertext[256];
    memcpy(ciphertext, pt, ptlen);
    (void)ctx;
    (void)nonce;
}
