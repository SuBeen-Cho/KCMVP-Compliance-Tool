/* P64: COM-002 — return value of lea_set_key (called inside void function) ignored */
#include <stdint.h>

typedef struct { uint8_t ctx[256]; } LEA_CTX;

int lea_set_key(LEA_CTX *ctx, const uint8_t *key, int keylen);
int lea_encrypt_block(LEA_CTX *ctx, uint8_t *ct, const uint8_t *pt);

/* VIOLATION: function is void — no way to propagate errors from lea_set_key */
void encrypt_data(const uint8_t *key, const uint8_t *pt, uint8_t *ct) {
    LEA_CTX ctx;
    /* VIOLATION: return value of lea_set_key not checked */
    lea_set_key(&ctx, key, 16);
    lea_encrypt_block(&ctx, ct, pt);
}
