
#include <stdint.h>
#include <string.h>
#include "lea.h"

/* ===== P29: CBC-001 — CBC 암호화에서 XOR 연쇄 없음 ===== */
/* 위반: CT[i]=ENC(PT[i]) 만 수행. CT[i-1]과 XOR(^) 없음 */
void p29_cbc_enc_no_xor(const LEA_KEY *ctx, const uint8_t *pt,
                         uint8_t *ct, size_t len) {
    size_t i;
    for (i = 0; i < len; i += 16) {
        lea_encrypt(ctx, pt + i, ct + i);
        /* 위반: 이전 암호문 블록과 XOR 없이 단순 암호화 */
    }
}

/* ===== P30: CBC-002 — CBC 복호화에서 XOR 연쇄 없음 ===== */
/* 위반: PT[i]=DEC(CT[i]) 만 수행. CT[i-1]과 XOR(^) 없음 */
void p30_cbc_decrypt_no_xor(const LEA_KEY *ctx, const uint8_t *ct,
                              uint8_t *pt, size_t len) {
    size_t i;
    for (i = 0; i < len; i += 16) {
        lea_cbc_decrypt(ctx, ct + i, pt + i, 16, NULL);
        /* 위반: 이전 암호문 블록과 XOR 없이 단순 복호화 */
    }
}

/* ===== P31: ECB-002 — ECB 암호화에서 len%16 검사 없음 ===== */
/* 위반: 입력 길이의 16배수 여부 확인 없이 블록 단위 암호화 */
int p31_ecb_encrypt_no_check(const LEA_KEY *ctx, const uint8_t *pt,
                               uint8_t *ct, size_t len) {
    size_t i;
    /* 위반: len % 16 검사 없음 */
    for (i = 0; i < len; i += 16) {
        lea_encrypt(ctx, pt + i, ct + i);
    }
    return 0;
}
