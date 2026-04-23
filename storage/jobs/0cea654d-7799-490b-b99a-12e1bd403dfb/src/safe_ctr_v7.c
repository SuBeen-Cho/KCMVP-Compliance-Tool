/* N28: CTR-002 — stack counter → 재사용 없음 (정상) */
#include <string.h>

typedef struct { unsigned char *key; int keylen; } CTRCtx;

void ctr_init(CTRCtx *ctx, unsigned char *iv, unsigned int ivlen) {
    unsigned char counter[16];   /* stack: 매 호출마다 새로 초기화 */
    memcpy(counter, iv, ivlen);
    (void)ctx;
    (void)counter;
}
