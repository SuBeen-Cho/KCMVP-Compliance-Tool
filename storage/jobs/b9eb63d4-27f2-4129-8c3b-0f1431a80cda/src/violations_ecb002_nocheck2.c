/* P66: ECB-002 — ecb_cipher function without len%%16 validation */
#include <stdint.h>
#include <string.h>

#define BLOCK_LEN 16

typedef struct { uint8_t rk[1152]; } LEA_ECB_CTX;

int lea_ecb_enc(LEA_ECB_CTX *ctx, uint8_t *ct, const uint8_t *pt, int len);

int ecb_cipher(LEA_ECB_CTX *ctx, uint8_t *ct, const uint8_t *pt, int len) {
    /* VIOLATION: no check that len is a multiple of BLOCK_LEN (16) */
    return lea_ecb_enc(ctx, ct, pt, len);
}
