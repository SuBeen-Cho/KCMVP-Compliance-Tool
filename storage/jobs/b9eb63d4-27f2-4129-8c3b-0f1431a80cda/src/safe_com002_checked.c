/* N62: COM-002 — return values of all crypto functions properly checked */
#include <stdint.h>

typedef struct { uint8_t ctx[256]; } LEA_CTX;

int lea_set_key(LEA_CTX *ctx, const uint8_t *key, int keylen);
int lea_encrypt_block(LEA_CTX *ctx, uint8_t *ct, const uint8_t *pt);

int encrypt_data(const uint8_t *key, const uint8_t *pt, uint8_t *ct) {
    LEA_CTX ctx;
    int ret;
    /* CORRECT: check lea_set_key return value */
    ret = lea_set_key(&ctx, key, 16);
    if (ret != 0) return ret;
    /* CORRECT: check lea_encrypt_block return value */
    ret = lea_encrypt_block(&ctx, ct, pt);
    if (ret != 0) return ret;
    return 0;
}
