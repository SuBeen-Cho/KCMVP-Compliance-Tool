/* N55: GCM-003 — correct GCM API order: init -> set_ctr -> encrypt -> final */
#include <stdint.h>
#include <sys/random.h>

typedef struct { uint8_t ctx[256]; } LEA_GCM_CTX;

int lea_gcm_init(LEA_GCM_CTX *ctx, const uint8_t *key, int keylen);
int lea_gcm_set_ctr(LEA_GCM_CTX *ctx, const uint8_t *ctr, int ctrlen);
int lea_gcm_encrypt(LEA_GCM_CTX *ctx, uint8_t *ct, const uint8_t *pt, int len);
int lea_gcm_final(LEA_GCM_CTX *ctx, uint8_t *tag, int taglen);

int gcm_encrypt_correct(uint8_t *key, uint8_t *ct, const uint8_t *pt) {
    LEA_GCM_CTX ctx;
    uint8_t nonce[12];
    uint8_t tag[16];
    /* CORRECT: getrandom provides unpredictable nonce */
    if (getrandom(nonce, sizeof(nonce), 0) != (ssize_t)sizeof(nonce)) return -1;
    /* CORRECT: init first, then set_ctr */
    lea_gcm_init(&ctx, key, 16);
    lea_gcm_set_ctr(&ctx, nonce, 12);
    lea_gcm_encrypt(&ctx, ct, pt, 32);
    lea_gcm_final(&ctx, tag, 16);
    return 0;
}
