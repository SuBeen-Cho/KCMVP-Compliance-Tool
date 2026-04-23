
#include <stdint.h>
#include <string.h>
#include "lea.h"

/* ===== N01: GCM-002 정상 태그 크기 (16바이트) ===== */
void n01_gcm_proper_tag_size(LEA_GCM_CTX *ctx, uint8_t *pt, size_t len,
                               uint8_t *nonce, uint8_t *ct) {
    int tag_len = 16;  /* 정상: 16바이트 */
    uint8_t tag[16];
    lea_gcm_encrypt(ctx, pt, ct, len, nonce, tag, tag_len);
}

/* ===== N02: GCM-002 정상 태그 크기 (12바이트) ===== */
void n02_gcm_12byte_tag(LEA_GCM_CTX *ctx, uint8_t *pt, size_t len,
                         uint8_t *nonce, uint8_t *ct) {
    int t_len = 12;  /* 정상: 4~16 범위 */
    uint8_t tag[12];
    lea_gcm_encrypt(ctx, pt, ct, len, nonce, tag, t_len);
}

/* ===== N03: GCM-004 인증 실패 시 -1 반환 (올바른 처리) ===== */
int n03_gcm_proper_auth_return(LEA_GCM_CTX *ctx, uint8_t *tag_in,
                                uint8_t *tag_out, size_t tlen) {
    if (memcmp(tag_in, tag_out, tlen) != 0) {
        return -1;  /* 정상: 인증 실패 시 -1 반환 */
    }
    return 0;
}

/* ===== N04: GCM-005 사용 후 올바른 제로화 ===== */
void n04_gcm_proper_zeroize(uint8_t *key, uint8_t *nonce, LEA_GCM_CTX *ctx) {
    /* GCM 연산 후 */
    explicit_bzero(key, 16);
    explicit_bzero(nonce, 12);
    explicit_bzero(ctx, sizeof(LEA_GCM_CTX));  /* 정상 */
}

/* ===== N05: CBC-061 정상 IV 크기 (16바이트) ===== */
void n05_cbc_correct_iv_size(LEA_KEY *ctx, uint8_t *pt, size_t len, uint8_t *ct) {
    uint8_t iv[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                      0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    lea_cbc_encrypt(ctx, pt, ct, len, iv);  /* 정상: 16바이트 IV */
}

/* ===== N06: CBC-005 통일된 에러 코드 (정보 미노출) ===== */
int n06_cbc_unified_error(uint8_t *buf, size_t len) {
    if (!verify_pkcs7(buf, len)) {
        return -1;  /* 정상: 상세 오류 없이 -1만 반환 */
    }
    return 0;
}

/* ===== N07: CTR-LEA-001 정상 카운터 크기 (16바이트) ===== */
void n07_ctr_correct_counter_size(LEA_KEY *ctx, uint8_t *pt, size_t len, uint8_t *ct) {
    uint8_t ctr[16] = {0};  /* 정상: 16바이트 */
    lea_ctr_encrypt(ctx, pt, ct, len, ctr);
}

/* ===== N08: CCM-002 정상 Nonce 길이 (8바이트, 7~13 범위) ===== */
void n08_ccm_valid_nonce_len(LEA_KEY *ctx, uint8_t *pt, size_t len, uint8_t *ct) {
    int Nlen = 8;   /* 정상: 7~13 범위 */
    uint8_t nonce[8] = {0};
    uint8_t tag[8];
    lea_ccm_encrypt(ctx, pt, ct, len, nonce, tag, Nlen, 8);
}

/* ===== N09: CCM-003 정상 Tag 길이 (8바이트, {4,6,8,...,16} 중 하나) ===== */
void n09_ccm_valid_tag_len(LEA_KEY *ctx, uint8_t *pt, size_t len, uint8_t *ct) {
    int Tlen = 8;   /* 정상: 허용값 {4,6,8,10,12,14,16} */
    uint8_t nonce[8] = {0};
    uint8_t tag[8];
    lea_ccm_encrypt(ctx, pt, ct, len, nonce, tag, 8, Tlen);
}

/* ===== N10: CCM-004 인증 실패 시 평문 0화 (올바른 처리) ===== */
int n10_ccm_clear_plaintext_on_fail(LEA_KEY *ctx, uint8_t *ct, uint8_t *pt,
                                     size_t len, uint8_t *nonce, uint8_t *tag) {
    int ret = lea_ccm_decrypt(ctx, ct, pt, len, nonce, tag, 8, 8);
    if (ret != 0) {
        memset(pt, 0, len);  /* 정상: 실패 시 평문 0화 */
        return -1;
    }
    return 0;
}

/* ===== N11: OFB-001 정상 IV 크기 (16바이트) ===== */
void n11_ofb_correct_iv(LEA_KEY *ctx, uint8_t *pt, size_t len, uint8_t *ct) {
    uint8_t iv[16] = {0};  /* 정상: 16바이트 */
    lea_ofb_encrypt(ctx, pt, ct, len, iv);
}

/* ===== N12: CMAC-002 crypto_memcmp 사용 (상수 시간 비교) ===== */
int n12_cmac_const_time_compare(uint8_t *tag_computed, uint8_t *tag_received,
                                  size_t len) {
    if (crypto_memcmp(tag_computed, tag_received, len) != 0) {
        return -1;  /* 정상: 상수 시간 비교 */
    }
    return 0;
}

/* ===== N13: CMAC-003 K1/K2 사용 후 올바른 제로화 ===== */
void n13_cmac_zeroize_subkeys(LEA_KEY *ctx, uint8_t *msg, size_t len,
                                uint8_t *mac) {
    uint8_t K1[16], K2[16];
    lea_cmac_generate_subkeys(ctx, K1, K2);
    lea_cmac_compute(ctx, msg, len, K1, K2, mac);
    explicit_bzero(K1, 16);  /* 정상: K1 제로화 */
    explicit_bzero(K2, 16);  /* 정상: K2 제로화 */
}

/* ===== N14: COM-002 에러 처리 올바름 (반환값 검사) ===== */
int n14_proper_error_check(LEA_KEY *ctx, uint8_t *key, uint8_t *pt, uint8_t *ct,
                            size_t len, uint8_t *iv) {
    int ret;
    ret = lea_set_key(ctx, key, 128);
    if (ret < 0) return ret;  /* 정상: 반환값 검사 */
    ret = lea_cbc_encrypt(ctx, pt, ct, len, iv);
    if (ret < 0) return ret;
    return 0;
}

/* ===== N15: LEA-041 S-box 없는 ARX 연산 (정상) ===== */
uint32_t n15_lea_arx_no_sbox(uint32_t a, uint32_t b, uint32_t c) {
    /* 정상: ARX 연산만 사용, S-box 없음 */
    uint32_t t = (a + b) ^ c;
    t = (t << 9) | (t >> 23);  /* ROL9 */
    return t;
}

/* ===== N16: CBC-003 getrandom으로 IV 생성 (CSPRNG 사용) ===== */
int n16_cbc_csprng_iv(LEA_KEY *ctx, uint8_t *pt, size_t len, uint8_t *ct) {
    uint8_t iv[16];
    getrandom(iv, sizeof(iv), 0);  /* 정상: CSPRNG */
    return lea_cbc_encrypt(ctx, pt, ct, len, iv);
}

/* ===== N17: CTR-003 getrandom으로 nonce 생성 (CSPRNG 사용) ===== */
int n17_ctr_csprng_nonce(LEA_KEY *ctx, uint8_t *pt, size_t len, uint8_t *ct) {
    uint8_t ctr[16];
    getrandom(ctr, sizeof(ctr), 0);  /* 정상: CSPRNG */
    return lea_ctr_encrypt(ctx, pt, ct, len, ctr);
}

/* ===== N18: CCM-002 정상 Nonce (13바이트, 최대 허용값) ===== */
void n18_ccm_max_nonce_len(LEA_KEY *ctx, uint8_t *pt, size_t len, uint8_t *ct) {
    int nonce_len = 13;  /* 정상: 최대값 */
    uint8_t nonce[13] = {0};
    uint8_t tag[16];
    lea_ccm_encrypt(ctx, pt, ct, len, nonce, tag, nonce_len, 16);
}

/* ===== N19: GCM-003 올바른 API 호출 순서 (init→set_ctr→encrypt→final) ===== */
int n19_gcm_correct_order(LEA_GCM_CTX *ctx, uint8_t *key, uint8_t *nonce,
                           uint8_t *pt, uint8_t *ct, size_t len) {
    uint8_t tag[16];
    lea_gcm_init(ctx, key, 128);       /* 정상: init 먼저 */
    lea_gcm_set_ctr(ctx, nonce);       /* 그 다음 set_ctr */
    lea_gcm_encrypt(ctx, pt, ct, len, nonce, tag, 16);
    return lea_gcm_final(ctx, tag, tag, 16);
}

/* ===== N20: CFB-001 getrandom으로 IV 생성 (CSPRNG 사용) ===== */
int n20_cfb_csprng_iv(LEA_KEY *ctx, uint8_t *pt, size_t len, uint8_t *ct) {
    uint8_t iv[16];
    getrandom(iv, sizeof(iv), 0);  /* 정상: CSPRNG */
    return lea_cfb128_encrypt(ctx, pt, ct, len, iv);
}
