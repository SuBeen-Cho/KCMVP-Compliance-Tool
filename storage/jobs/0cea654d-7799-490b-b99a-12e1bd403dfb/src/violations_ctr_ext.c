
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "lea.h"

/* ===== P14: CTR-003 rand()로 nonce 생성 (CSPRNG 미사용) ===== */
void p14_ctr_rand_nonce(LEA_KEY *ctx, uint8_t *pt, size_t len, uint8_t *ct) {
    uint8_t ctr[16];
    for (int i = 0; i < 16; i++) ctr[i] = (uint8_t)(rand() & 0xff);
    /* 위반: rand() 사용 — getrandom 사용 필요 */
    lea_ctr_encrypt(ctx, pt, ct, len, ctr);
}

/* ===== P15: CTR-004 카운터/키 제로화 누락 ===== */
void p15_ctr_no_zeroize(LEA_KEY *ctx, uint8_t *pt, size_t len, uint8_t *ct) {
    uint8_t ctr[16] = {0x01};
    lea_ctr_encrypt(ctx, pt, ct, len, ctr);
    /* 위반: ctr, ctx 제로화 없이 반환 */
}

/* ===== P16: CTR-LEA-001 잘못된 카운터 크기 (8바이트) ===== */
void p16_ctr_wrong_counter_size(LEA_KEY *ctx, uint8_t *pt, size_t len, uint8_t *ct) {
    uint8_t ctr[8] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    /* 위반: 카운터는 반드시 16바이트 */
    lea_ctr_encrypt(ctx, pt, ct, len, ctr);
}

/* ===== P17: CCM-002 Nonce 길이 범위 위반 (Nlen=6, 7 미만) ===== */
void p17_ccm_short_nonce(LEA_KEY *ctx, uint8_t *pt, size_t len, uint8_t *ct) {
    int Nlen = 6;   /* 위반: 7~13바이트 범위 위반 */
    uint8_t nonce[6] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    uint8_t tag[8];
    lea_ccm_encrypt(ctx, pt, ct, len, nonce, tag, Nlen, 8);
}

/* ===== P18: CCM-002 Nonce 길이 범위 위반 (nonce_len=14, 13 초과) ===== */
void p18_ccm_long_nonce(LEA_KEY *ctx, uint8_t *pt, size_t len, uint8_t *ct) {
    int nonce_len = 14;  /* 위반: 13 초과 */
    uint8_t nonce[14] = {0};
    uint8_t tag[8];
    lea_ccm_encrypt(ctx, pt, ct, len, nonce, tag, nonce_len, 8);
}

/* ===== P19: CCM-003 Tag 길이 허용값 위반 (Tlen=5, 홀수) ===== */
void p19_ccm_invalid_tag_len(LEA_KEY *ctx, uint8_t *pt, size_t len, uint8_t *ct) {
    int Tlen = 5;   /* 위반: {4,6,8,10,12,14,16} 외 */
    uint8_t nonce[7] = {0};
    uint8_t tag[5];
    lea_ccm_encrypt(ctx, pt, ct, len, nonce, tag, 7, Tlen);
}

/* ===== P20: CCM-003 Tag 길이 2 (너무 짧음) ===== */
void p20_ccm_tag_too_short(LEA_KEY *ctx, uint8_t *pt, size_t len, uint8_t *ct) {
    int t_len = 2;   /* 위반: 4 미만 */
    uint8_t nonce[8] = {0};
    uint8_t tag[2];
    lea_ccm_encrypt(ctx, pt, ct, len, nonce, tag, 8, t_len);
}

/* ===== P21: CCM-004 인증 실패 시 평문 미폐기 ===== */
int p21_ccm_no_plaintext_clear(LEA_KEY *ctx, uint8_t *ct, uint8_t *pt,
                                size_t len, uint8_t *nonce, uint8_t *tag) {
    int ret = lea_ccm_decrypt(ctx, ct, pt, len, nonce, tag, 8, 8);
    if (ret != 0) {
        /* 위반: 인증 실패 시 pt 버퍼 0화 없이 반환 */
        return -1;
    }
    return 0;
}

/* ===== P22: OFB-001 잘못된 IV 크기 (8바이트) ===== */
void p22_ofb_wrong_iv_size(LEA_KEY *ctx, uint8_t *pt, size_t len, uint8_t *ct) {
    uint8_t iv[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    /* 위반: IV는 반드시 16바이트 */
    lea_ofb_encrypt(ctx, pt, ct, len, iv);
}
