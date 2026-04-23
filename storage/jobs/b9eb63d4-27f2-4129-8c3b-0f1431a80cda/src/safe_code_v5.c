
#include <stdint.h>
#include <string.h>
#include "lea.h"

/* ===== N21: CBC-001 — CBC 암호화에서 올바른 XOR 연쇄 ===== */
void n21_cbc_enc_with_xor(const LEA_KEY *ctx, const uint8_t *pt,
                            uint8_t *ct, size_t len, const uint8_t *iv) {
    uint8_t block[16];
    const uint8_t *prev = iv;
    size_t i;
    int j;
    for (i = 0; i < len; i += 16) {
        for (j = 0; j < 16; j++) block[j] = pt[i + j] ^ prev[j]; /* XOR */
        lea_encrypt(ctx, block, ct + i);
        prev = ct + i;
    }
}

/* ===== N22: CBC-002 — CBC 복호화에서 올바른 XOR 연쇄 ===== */
void n22_cbc_decrypt_with_xor(const LEA_KEY *ctx, const uint8_t *ct,
                                uint8_t *pt, size_t len, const uint8_t *iv) {
    uint8_t block[16];
    const uint8_t *prev = iv;
    size_t i;
    int j;
    for (i = 0; i < len; i += 16) {
        lea_cbc_decrypt(ctx, ct + i, block, 16, iv);
        for (j = 0; j < 16; j++) pt[i + j] = block[j] ^ prev[j]; /* XOR */
        prev = ct + i;
    }
}

/* ===== N23: ECB-002 — ECB 암호화에서 len%16 검사 있음 ===== */
int n23_ecb_encrypt_with_check(const LEA_KEY *ctx, const uint8_t *pt,
                                 uint8_t *ct, size_t len) {
    size_t i;
    if (len % 16 != 0) return -1;   /* 정상: 16배수 검사 */
    for (i = 0; i < len; i += 16) {
        lea_encrypt(ctx, pt + i, ct + i);
    }
    return 0;
}
