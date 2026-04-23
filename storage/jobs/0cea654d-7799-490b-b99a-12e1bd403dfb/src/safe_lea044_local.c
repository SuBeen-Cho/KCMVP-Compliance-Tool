/* N63: LEA-044 — key kept in local scope and cleared with memset_s after use */
#include <stdint.h>
#include <string.h>

typedef struct { uint8_t ctx[256]; } LEA_CTX;
int lea_set_key(LEA_CTX *ctx, const uint8_t *key, int keylen);
int lea_encrypt_block(LEA_CTX *ctx, uint8_t *ct, const uint8_t *pt);

int lea_encrypt(const uint8_t *key, int keylen,
                const uint8_t *pt, uint8_t *ct) {
    LEA_CTX ctx;
    uint8_t local_key[32];
    int ret;
    /* CORRECT: key is local and will be zeroed before function returns */
    memcpy(local_key, key, (keylen <= 32 ? keylen : 32));
    ret = lea_set_key(&ctx, local_key, keylen);
    if (ret == 0) ret = lea_encrypt_block(&ctx, ct, pt);
    /* CORRECT: zero local key copy to prevent residual leakage */
    memset_s(local_key, sizeof(local_key), 0, sizeof(local_key));
    memset_s(&ctx, sizeof(ctx), 0, sizeof(ctx));
    return ret;
}
