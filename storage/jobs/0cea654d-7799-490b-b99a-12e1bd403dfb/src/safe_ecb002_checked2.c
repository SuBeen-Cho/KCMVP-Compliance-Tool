/* N64: ECB-002 — ecb_cipher with proper len%%16 block alignment check */
#include <stdint.h>
#include <string.h>

#define BLOCK_LEN 16

typedef struct { uint8_t rk[1152]; } LEA_ECB_CTX;

int lea_ecb_enc(LEA_ECB_CTX *ctx, uint8_t *ct, const uint8_t *pt, int len);

int ecb_cipher(LEA_ECB_CTX *ctx, uint8_t *ct, const uint8_t *pt, int len) {
    /* CORRECT: verify plaintext length is a multiple of block size */
    if (len <= 0 || (len % 16) != 0) return -1;
    return lea_ecb_enc(ctx, ct, pt, len);
}
