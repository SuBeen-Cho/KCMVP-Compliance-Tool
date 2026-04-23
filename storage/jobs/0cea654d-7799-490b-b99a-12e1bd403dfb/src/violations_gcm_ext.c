
#include <stdint.h>
#include <string.h>
#include "lea.h"

/* ===== P01: GCM-002 태그 길이 너무 짧음 (tag_len=3) ===== */
int p01_gcm_short_tag(LEA_GCM_CTX *ctx, uint8_t *pt, size_t len,
                       uint8_t *nonce, uint8_t *ct) {
    int tag_len = 3;   /* 위반: 4바이트 미만 */
    uint8_t tag[3];
    lea_gcm_encrypt(ctx, pt, ct, len, nonce, tag, tag_len);
    return 0;
}

/* ===== P02: GCM-002 태그 길이 너무 큼 (tag_len=20) ===== */
int p02_gcm_long_tag(LEA_GCM_CTX *ctx, uint8_t *pt, size_t len,
                      uint8_t *nonce, uint8_t *ct) {
    int tag_len = 20;   /* 위반: 16바이트 초과 */
    uint8_t tag[20];
    lea_gcm_encrypt(ctx, pt, ct, len, nonce, tag, tag_len);
    return 0;
}

/* ===== P03: GCM-003 GCM API 호출 순서 위반 (set_ctr 후 init) ===== */
void p03_gcm_wrong_order(LEA_GCM_CTX *ctx, uint8_t *key, uint8_t *nonce) {
    /* 위반: set_ctr 먼저 호출 후 init */
    lea_gcm_set_ctr(ctx, nonce);
    lea_gcm_init(ctx, key, 128);
    lea_gcm_final(ctx, NULL, NULL, 0);
}

/* ===== P04: GCM-004 인증 실패 시 -1 미반환 (0 반환) ===== */
int p04_gcm_no_neg_return(LEA_GCM_CTX *ctx, uint8_t *tag_in,
                           uint8_t *tag_out, size_t tag_len) {
    int ret = lea_gcm_final(ctx, tag_in, tag_out, tag_len);
    if (ret != 0) {
        /* auth_fail 상황인데 0 반환 — 위반 */
        return 0;
    }
    return 0;
}

/* ===== P05: GCM-005 nonce/key 사용 후 제로화 누락 ===== */
void p05_gcm_no_zeroize(LEA_GCM_CTX *ctx, uint8_t *key, uint8_t *nonce,
                         uint8_t *pt, uint8_t *ct, size_t len) {
    uint8_t tag[16];
    lea_gcm_init(ctx, key, 128);
    lea_gcm_set_ctr(ctx, nonce);
    lea_gcm_encrypt(ctx, pt, ct, len, nonce, tag, 16);
    lea_gcm_final(ctx, tag, tag, 16);
    /* 위반: key, nonce, ctx 제로화 없이 반환 */
}

/* ===== P06: GCM-004 tag_mismatch 처리 누락 (return -1 없음) ===== */
int p06_gcm_tag_mismatch_ignored(uint8_t *tag_out, uint8_t *tag_in, size_t tlen) {
    /* 위반: 태그 비교 결과를 무시하고 항상 0 반환 */
    if (memcmp(tag_out, tag_in, tlen) != 0) {
        /* tag_mismatch 발생 — 그냥 통과 */
    }
    return 0;  /* 위반: -1 미반환 */
}

/* ===== P07: GCM-002 t_len 변수 2 (너무 짧음) ===== */
void p07_gcm_tlen_too_short(LEA_GCM_CTX *ctx, uint8_t *pt, uint8_t *ct, size_t len) {
    int t_len = 2;  /* 위반: 4 미만 */
    uint8_t tag[2];
    lea_gcm_encrypt(ctx, pt, ct, len, NULL, tag, t_len);
}
