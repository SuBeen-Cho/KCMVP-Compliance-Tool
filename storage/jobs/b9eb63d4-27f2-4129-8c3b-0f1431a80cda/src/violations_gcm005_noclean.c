/* P60: GCM-005 — LEA_GCM_CTX not zeroed after use */
#include <stdint.h>
#include <string.h>

typedef struct { uint8_t state[512]; } LEA_GCM_CTX;

int lea_gcm_init(LEA_GCM_CTX *ctx, const uint8_t *key, int keylen);
int lea_gcm_set_ctr(LEA_GCM_CTX *ctx, const uint8_t *ctr, int ctrlen);
int lea_gcm_encrypt(LEA_GCM_CTX *ctx, uint8_t *ct, const uint8_t *pt, int len);
int lea_gcm_final(LEA_GCM_CTX *ctx, uint8_t *tag, int taglen);

int gcm_encrypt(uint8_t *key, uint8_t *nonce, uint8_t *pt, int len,
                uint8_t *ct, uint8_t *tag) {
    LEA_GCM_CTX ctx;
    int ret;
    lea_gcm_init(&ctx, key, 16);
    lea_gcm_set_ctr(&ctx, nonce, 12);
    ret = lea_gcm_encrypt(&ctx, ct, pt, len);
    lea_gcm_final(&ctx, tag, 16);
    /* VIOLATION: GCM context must be zeroed after use with memset_s */
    return ret;
}
