/* P32: GCM-001 — static nonce 재사용 위반 */
#include <string.h>

typedef struct { unsigned char *key; int keylen; } GCMCtx;

/* static 선언된 nonce → 함수 재호출 시 덮어쓰이므로 재사용 발생 */
void gcm_init(GCMCtx *ctx, unsigned char *pt, unsigned int ptlen) {
    static unsigned char nonce[12];   /* VIOLATION: static nonce */
    unsigned char ciphertext[256];
    memcpy(ciphertext, pt, ptlen);
    (void)ctx;
    (void)nonce;
}
