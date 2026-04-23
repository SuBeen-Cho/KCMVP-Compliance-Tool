/* P57: GCM-003 — lea_gcm_set_ctr is called BEFORE lea_gcm_init (wrong API order) */
#include <stdint.h>

typedef struct { uint8_t ctx[256]; } LEA_GCM_CTX;

int lea_gcm_init(LEA_GCM_CTX *ctx, const uint8_t *key, int keylen);
int lea_gcm_set_ctr(LEA_GCM_CTX *ctx, const uint8_t *ctr, int ctrlen);
int lea_gcm_encrypt(LEA_GCM_CTX *ctx, uint8_t *ct, const uint8_t *pt, int len);
int lea_gcm_final(LEA_GCM_CTX *ctx, uint8_t *tag, int taglen);

void gcm_encrypt_wrong_order(uint8_t *key, uint8_t *nonce, uint8_t *pt, uint8_t *ct) {
    LEA_GCM_CTX ctx;
    uint8_t tag[16];
    /* VIOLATION: set_ctr must come AFTER init, not before */
    lea_gcm_set_ctr(&ctx, nonce, 12);
    lea_gcm_init(&ctx, key, 16);
    lea_gcm_encrypt(&ctx, ct, pt, 32);
    lea_gcm_final(&ctx, tag, 16);
}
