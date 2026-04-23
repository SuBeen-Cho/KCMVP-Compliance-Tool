"""
KCMVP 정확도 테스트 데이터 v4 — 미커버 룰셋 확장판
- 총 48건: P(위반) 28건 + N(정상) 20건
- 커버 룰: GCM-002/003/004/005, CBC-003/004/005/061,
           CTR-003/004/LEA-001, CCM-002/003/004,
           OFB-001, CFB-001, CMAC-002/003, COM-002, LEA-041
"""
import zipfile, io, os

# ─────────────────────────────────────────────────────
# 파일 1: violations_gcm_ext.c  (GCM 확장 룰 위반 — P01~P07)
# ─────────────────────────────────────────────────────
VIOLATIONS_GCM_EXT_C = r"""
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
"""

# ─────────────────────────────────────────────────────
# 파일 2: violations_cbc_ext.c  (CBC 확장 룰 위반 — P08~P13)
# ─────────────────────────────────────────────────────
VIOLATIONS_CBC_EXT_C = r"""
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "lea.h"

/* ===== P08: CBC-003 rand()로 IV 생성 (CSPRNG 미사용) ===== */
void p08_cbc_rand_iv(LEA_KEY *ctx, uint8_t *pt, size_t len, uint8_t *ct) {
    uint8_t iv[16];
    for (int i = 0; i < 16; i++) iv[i] = (uint8_t)(rand() & 0xff);
    /* 위반: rand() 사용 — getrandom/DRBG 사용 필요 */
    lea_cbc_encrypt(ctx, pt, ct, len, iv);
}

/* ===== P09: CBC-004 IV/키 사용 후 제로화 누락 ===== */
void p09_cbc_no_zeroize(LEA_KEY *ctx, uint8_t *key, uint8_t *pt, size_t len, uint8_t *ct) {
    uint8_t iv[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                      0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    lea_cbc_encrypt(ctx, pt, ct, len, iv);
    /* 위반: iv, key 메모리 제로화 없이 반환 */
}

/* ===== P10: CBC-005 패딩 오류 정보 노출 (printf padding error) ===== */
int p10_cbc_leaky_padding_error(uint8_t *ct, size_t len) {
    int pad_byte = ct[len - 1];
    if (pad_byte > 16 || pad_byte == 0) {
        /* 위반: 패딩 오류 상세 정보 외부 노출 */
        printf("Padding verification failed: invalid padding byte %d\n", pad_byte);
        return -1;
    }
    for (int i = 0; i < pad_byte; i++) {
        if (ct[len - 1 - i] != pad_byte) {
            fprintf(stderr, "Padding error: expected %d got %d at offset %d\n",
                    pad_byte, ct[len-1-i], i);
            return -1;
        }
    }
    return 0;
}

/* ===== P11: CBC-061 잘못된 IV 크기 (8바이트) ===== */
void p11_cbc_wrong_iv_size(LEA_KEY *ctx, uint8_t *pt, size_t len, uint8_t *ct) {
    uint8_t iv[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    /* 위반: IV는 반드시 16바이트 */
    lea_cbc_encrypt(ctx, pt, ct, len, iv);
}

/* ===== P12: CBC-061 잘못된 IV 크기 (32바이트) ===== */
void p12_cbc_iv_too_large(LEA_KEY *ctx, uint8_t *pt, size_t len, uint8_t *ct) {
    uint8_t iv[32] = {0};
    /* 위반: IV 32바이트 — 16바이트 필요 */
    lea_cbc_encrypt(ctx, pt, ct, 16, iv);
}

/* ===== P13: CBC-005 RETURN INVALID_PADDING 상수 노출 ===== */
int p13_cbc_return_bad_padding(uint8_t *buf, size_t len) {
    if (!verify_pkcs7(buf, len)) {
        return -INVALID_PADDING;  /* 위반: 패딩 관련 상수 노출 */
    }
    return 0;
}
"""

# ─────────────────────────────────────────────────────
# 파일 3: violations_ctr_ext.c  (CTR/CCM/기타 — P14~P22)
# ─────────────────────────────────────────────────────
VIOLATIONS_CTR_EXT_C = r"""
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
"""

# ─────────────────────────────────────────────────────
# 파일 4: violations_misc_ext.c  (기타 룰 위반 — P23~P28)
# ─────────────────────────────────────────────────────
VIOLATIONS_MISC_EXT_C = r"""
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "lea.h"

/* ===== P23: CFB-001 rand()로 IV 생성 (CSPRNG 미사용) ===== */
void p23_cfb_rand_iv(LEA_KEY *ctx, uint8_t *pt, size_t len, uint8_t *ct) {
    uint8_t iv[16];
    for (int i = 0; i < 16; i++) iv[i] = rand() & 0xff;
    /* 위반: getrandom/DRBG 미사용 */
    lea_cfb128_encrypt(ctx, pt, ct, len, iv);
}

/* ===== P24: CMAC-002 memcmp으로 태그 비교 (타이밍 공격 취약) ===== */
int p24_cmac_memcmp_not_const_time(uint8_t *tag_computed, uint8_t *tag_received,
                                    size_t len) {
    /* 위반: memcmp는 타이밍 의존적 — crypto_memcmp 사용 필요 */
    if (memcmp(tag_computed, tag_received, len) != 0) {
        return -1;
    }
    return 0;
}

/* ===== P25: CMAC-003 K1/K2 서브키 사용 후 제로화 누락 ===== */
void p25_cmac_no_subkey_zeroize(LEA_KEY *ctx, uint8_t *msg, size_t len,
                                  uint8_t *mac) {
    uint8_t K1[16], K2[16];
    /* K1, K2 생성 */
    lea_cmac_generate_subkeys(ctx, K1, K2);
    lea_cmac_compute(ctx, msg, len, K1, K2, mac);
    /* 위반: K1, K2 사용 후 제로화 없이 반환 */
}

/* ===== P26: COM-002 에러 처리 누락 (반환값 무시) ===== */
void p26_no_error_check(LEA_KEY *ctx, uint8_t *key, uint8_t *pt, uint8_t *ct,
                         size_t len, uint8_t *iv) {
    /* 위반: 모든 반환값 무시 — 에러 코드 체크 없음 */
    lea_set_key(ctx, key, 128);
    lea_cbc_encrypt(ctx, pt, ct, len, iv);
}

/* ===== P27: LEA-041 S-box 사용 (ARX 원칙 위반) ===== */
static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76
    /* ... 나머지 생략 */
};

uint8_t p27_lea_with_sbox(uint8_t input) {
    /* 위반: LEA는 S-box 비사용 ARX 구조 */
    uint8_t s_box_result = sbox[input & 0x0f];
    return s_box_result;
}

/* ===== P28: CMAC-002 strcmp로 태그 비교 (타이밍 공격 취약) ===== */
int p28_cmac_strcmp_compare(const char *expected_mac, const char *computed_mac) {
    /* 위반: strcmp는 타이밍 의존적 */
    if (strcmp(expected_mac, computed_mac) != 0) {
        return -1;
    }
    return 0;
}
"""

# ─────────────────────────────────────────────────────
# 파일 5: safe_code_v4.c  (정상 코드 — N01~N20)
# ─────────────────────────────────────────────────────
SAFE_CODE_V4_C = r"""
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
"""

# ─────────────────────────────────────────────────────
# 간소 헤더
# ─────────────────────────────────────────────────────
LEA_H = r"""
#ifndef LEA_H
#define LEA_H
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

typedef struct { uint32_t rk[8][32]; } LEA_KEY;
typedef struct { uint32_t state[4]; int initialized; uint8_t J0[16]; } LEA_GCM_CTX;

int  lea_set_key(LEA_KEY *ctx, const uint8_t *key, int key_bits);
void lea_encrypt(const LEA_KEY *ctx, const uint8_t *pt, uint8_t *ct);
int  lea_cbc_encrypt(const LEA_KEY *ctx, const uint8_t *pt, uint8_t *ct,
                     size_t len, const uint8_t *iv);
int  lea_cbc_decrypt(const LEA_KEY *ctx, const uint8_t *ct, uint8_t *pt,
                     size_t len, const uint8_t *iv);
int  lea_ctr_encrypt(const LEA_KEY *ctx, const uint8_t *pt, uint8_t *ct,
                     size_t len, uint8_t *counter);
int  lea_gcm_init(LEA_GCM_CTX *ctx, const uint8_t *key, int key_bits);
int  lea_gcm_set_ctr(LEA_GCM_CTX *ctx, const uint8_t *nonce);
int  lea_gcm_encrypt(LEA_GCM_CTX *ctx, const uint8_t *pt, uint8_t *ct,
                     size_t len, const uint8_t *nonce, uint8_t *tag, int tag_len);
int  lea_gcm_decrypt(LEA_GCM_CTX *ctx, const uint8_t *ct, uint8_t *pt,
                     size_t len, const uint8_t *nonce, uint8_t *tag);
int  lea_gcm_final(LEA_GCM_CTX *ctx, const uint8_t *tag_in, uint8_t *tag_out,
                   size_t tag_len);
int  lea_ccm_encrypt(const LEA_KEY *ctx, const uint8_t *pt, uint8_t *ct,
                     size_t len, const uint8_t *nonce, uint8_t *tag,
                     int nonce_len, int tag_len);
int  lea_ccm_decrypt(const LEA_KEY *ctx, const uint8_t *ct, uint8_t *pt,
                     size_t len, const uint8_t *nonce, const uint8_t *tag,
                     int nonce_len, int tag_len);
int  lea_ofb_encrypt(const LEA_KEY *ctx, const uint8_t *pt, uint8_t *ct,
                     size_t len, uint8_t *iv);
int  lea_cfb128_encrypt(const LEA_KEY *ctx, const uint8_t *pt, uint8_t *ct,
                        size_t len, uint8_t *iv);
int  lea_cmac_generate_subkeys(const LEA_KEY *ctx, uint8_t *K1, uint8_t *K2);
int  lea_cmac_compute(const LEA_KEY *ctx, const uint8_t *msg, size_t len,
                      const uint8_t *K1, const uint8_t *K2, uint8_t *mac);
int  lea_online_init(void *ctx);
int  lea_online_update(void *ctx, const uint8_t *data, size_t len);
int  lea_online_final(void *ctx, uint8_t *out, size_t *out_len);
void secure_clear(void *buf, size_t len);
void explicit_bzero(void *buf, size_t len);
int  getrandom(void *buf, size_t len, unsigned int flags);
int  crypto_memcmp(const void *a, const void *b, size_t len);
int  verify_pkcs7(const uint8_t *buf, size_t len);

#define INVALID_PADDING 0x01

#endif /* LEA_H */
"""

# ─────────────────────────────────────────────────────
# Ground Truth (48건)
# ─────────────────────────────────────────────────────
GROUND_TRUTH = """# Accuracy Test v4 — Ground Truth (48건)
# 미커버 룰셋 확장 테스트
# Format: file | label | expected_rule_id | description

## violations_gcm_ext.c (P = 위반, 7건)
violations_gcm_ext.c | P | GCM-002 | P01: tag_len=3 (4 미만)
violations_gcm_ext.c | P | GCM-002 | P02: tag_len=20 (16 초과)
violations_gcm_ext.c | P | GCM-003 | P03: set_ctr 먼저 호출 후 init (순서 위반)
violations_gcm_ext.c | P | GCM-004 | P04: 인증 실패 시 0 반환 (−1 미반환)
violations_gcm_ext.c | P | GCM-005 | P05: nonce/key 제로화 누락
violations_gcm_ext.c | P | GCM-004 | P06: tag_mismatch 처리 누락
violations_gcm_ext.c | P | GCM-002 | P07: t_len=2 (4 미만)

## violations_cbc_ext.c (P = 위반, 6건)
violations_cbc_ext.c | P | CBC-003 | P08: rand()로 IV 생성 (CSPRNG 미사용)
violations_cbc_ext.c | P | CBC-004 | P09: IV/키 사용 후 제로화 누락
violations_cbc_ext.c | P | CBC-005 | P10: printf로 padding 오류 상세 노출
violations_cbc_ext.c | P | CBC-061 | P11: iv[8] — 8바이트 IV (16 필요)
violations_cbc_ext.c | P | CBC-061 | P12: iv[32] — 32바이트 IV (16 필요)
violations_cbc_ext.c | P | CBC-005 | P13: return -INVALID_PADDING 상수 노출

## violations_ctr_ext.c (P = 위반, 9건)
violations_ctr_ext.c | P | CTR-003 | P14: rand()로 nonce 생성 (CSPRNG 미사용)
violations_ctr_ext.c | P | CTR-004 | P15: 카운터/키 제로화 누락
violations_ctr_ext.c | P | CTR-LEA-001 | P16: ctr[8] — 8바이트 카운터 (16 필요)
violations_ctr_ext.c | P | CCM-002 | P17: Nlen=6 (7 미만)
violations_ctr_ext.c | P | CCM-002 | P18: nonce_len=14 (13 초과)
violations_ctr_ext.c | P | CCM-003 | P19: Tlen=5 (허용값 아님)
violations_ctr_ext.c | P | CCM-003 | P20: t_len=2 (4 미만)
violations_ctr_ext.c | P | CCM-004 | P21: 인증 실패 시 평문 미폐기
violations_ctr_ext.c | P | OFB-001 | P22: iv[8] — 8바이트 IV (16 필요)

## violations_misc_ext.c (P = 위반, 6건)
violations_misc_ext.c | P | CFB-001 | P23: rand()로 CFB IV 생성
violations_misc_ext.c | P | CMAC-002 | P24: memcmp으로 태그 비교 (타이밍 취약)
violations_misc_ext.c | P | CMAC-003 | P25: K1/K2 사용 후 제로화 누락
violations_misc_ext.c | P | COM-002 | P26: lea_set_key/lea_cbc_encrypt 반환값 무시
violations_misc_ext.c | P | LEA-041 | P27: sbox[] 배열 사용 (ARX 원칙 위반)
violations_misc_ext.c | P | CMAC-002 | P28: strcmp로 MAC 비교 (타이밍 취약)

## safe_code_v4.c (N = 정상 코드, 20건)
safe_code_v4.c | N | GCM-002 | N01: tag_len=16 정상
safe_code_v4.c | N | GCM-002 | N02: t_len=12 정상
safe_code_v4.c | N | GCM-004 | N03: 인증 실패 시 -1 반환 정상
safe_code_v4.c | N | GCM-005 | N04: explicit_bzero로 올바른 제로화
safe_code_v4.c | N | CBC-061 | N05: iv[16] 정상 크기
safe_code_v4.c | N | CBC-005 | N06: return -1만 반환 (정보 미노출)
safe_code_v4.c | N | CTR-LEA-001 | N07: ctr[16] 정상 크기
safe_code_v4.c | N | CCM-002 | N08: Nlen=8 정상 (7~13 범위)
safe_code_v4.c | N | CCM-003 | N09: Tlen=8 정상 ({4,6,8,...,16} 중 하나)
safe_code_v4.c | N | CCM-004 | N10: memset(pt,0,len) 인증 실패 시 처리
safe_code_v4.c | N | OFB-001 | N11: iv[16] 정상 크기
safe_code_v4.c | N | CMAC-002 | N12: crypto_memcmp 상수 시간 비교
safe_code_v4.c | N | CMAC-003 | N13: K1/K2 explicit_bzero 올바른 제로화
safe_code_v4.c | N | COM-002 | N14: 모든 반환값 검사 (ret < 0 체크)
safe_code_v4.c | N | LEA-041 | N15: ARX 연산만 사용 (S-box 없음)
safe_code_v4.c | N | CBC-003 | N16: getrandom으로 IV 생성
safe_code_v4.c | N | CTR-003 | N17: getrandom으로 nonce 생성
safe_code_v4.c | N | CCM-002 | N18: nonce_len=13 정상 (최대)
safe_code_v4.c | N | GCM-003 | N19: init→set_ctr→encrypt→final 올바른 순서
safe_code_v4.c | N | CFB-001 | N20: getrandom으로 CFB IV 생성
"""


def create_zip():
    output_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        "testdata", "accuracy_test_v4.zip"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("src/violations_gcm_ext.c",  VIOLATIONS_GCM_EXT_C)
        zf.writestr("src/violations_cbc_ext.c",  VIOLATIONS_CBC_EXT_C)
        zf.writestr("src/violations_ctr_ext.c",  VIOLATIONS_CTR_EXT_C)
        zf.writestr("src/violations_misc_ext.c", VIOLATIONS_MISC_EXT_C)
        zf.writestr("src/safe_code_v4.c",        SAFE_CODE_V4_C)
        zf.writestr("include/lea.h",             LEA_H)
        zf.writestr("GROUND_TRUTH.md",           GROUND_TRUTH)
    buf.seek(0)
    with open(output_path, "wb") as f:
        f.write(buf.read())

    gt_cases = [l for l in GROUND_TRUTH.splitlines() if "|" in l and not l.startswith("#")]
    p_cases  = [l for l in gt_cases if "| P |" in l]
    n_cases  = [l for l in gt_cases if "| N |" in l]
    print(f"Created: {output_path}")
    print(f"Total: {len(gt_cases)} cases  (P={len(p_cases)}, N={len(n_cases)})")


if __name__ == "__main__":
    create_zip()
