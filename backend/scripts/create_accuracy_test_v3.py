"""
KCMVP 정확도 테스트 데이터 v3 — 확장판
- 총 50건: P(위반) 30건 + N(정상) 20건
- COM-001~006, LEA, CBC, CTR, GCM, ARIA, CMAC 전반 커버
"""
import zipfile, io, os

# ─────────────────────────────────────────────────────
# 파일 1: violations_com.c  (공통 룰 위반 — P01~P14)
# ─────────────────────────────────────────────────────
VIOLATIONS_COM_C = r"""
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "lea.h"

/* ===== P01: COM-003 하드코딩 AES 키 (aes_key) ===== */
void p01_hardcoded_aes_key(LEA_KEY *ctx) {
    uint8_t aes_key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    lea_set_key(ctx, aes_key, 128);
}

/* ===== P02: COM-003 하드코딩 마스터 키 (master_key) ===== */
void p02_hardcoded_master_key(LEA_KEY *ctx) {
    uint8_t master_key[32] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    };
    lea_set_key(ctx, master_key, 256);
}

/* ===== P03: COM-003 하드코딩 세션 키 (session_key) ===== */
void p03_hardcoded_session_key(LEA_KEY *ctx) {
    uint8_t session_key[24] = {
        0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
        0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
        0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
    };
    lea_set_key(ctx, session_key, 192);
}

/* ===== P04: COM-003 하드코딩 IV (iv 변수) ===== */
void p04_hardcoded_iv(LEA_KEY *ctx, uint8_t *pt, size_t len, uint8_t *ct) {
    uint8_t iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    lea_cbc_encrypt(ctx, pt, ct, len, iv);
}

/* ===== P05: COM-003 하드코딩 nonce (enc_nonce) ===== */
void p05_hardcoded_nonce(void) {
    uint8_t enc_nonce[12] = {
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
        0xde, 0xca, 0xf8, 0x88
    };
    (void)enc_nonce;
}

/* ===== P06: COM-001 weak zeroize — memset 사용 (key_material) ===== */
void p06_weak_zeroize_key(uint8_t *key_material, size_t len) {
    /* 위반: explicit_bzero 또는 secure_clear 사용 필요 */
    memset(key_material, 0, len);
}

/* ===== P07: COM-001 weak zeroize — 루프 (session_key) ===== */
void p07_weak_zeroize_loop(uint8_t *session_key, size_t len) {
    /* 위반: volatile 포인터 없는 단순 루프는 컴파일러 최적화로 제거될 수 있음 */
    for (size_t i = 0; i < len; i++) session_key[i] = 0;
}

/* ===== P08: COM-004 rand()로 IV 생성 ===== */
void p08_rand_iv(uint8_t *iv) {
    srand((unsigned int)time(NULL));
    for (int i = 0; i < 16; i++) iv[i] = (uint8_t)(rand() & 0xff);
}

/* ===== P09: COM-004 rand()로 nonce 생성 ===== */
void p09_rand_nonce(uint8_t *nonce) {
    for (int i = 0; i < 12; i++) nonce[i] = (uint8_t)(rand() & 0xff);
}

/* ===== P10: COM-004 rand()로 키 생성 ===== */
void p10_rand_key(uint8_t *key) {
    srand(12345);
    for (int i = 0; i < 16; i++) key[i] = (uint8_t)(rand() >> 4);
}

/* ===== P11: COM-005 update before init ===== */
void p11_update_before_init(LEA_CTX *ctx, uint8_t *data, size_t len) {
    lea_online_update(ctx, data, len);
    lea_online_final(ctx, data, &len);
}

/* ===== P12: COM-005 init without final ===== */
void p12_init_no_final(LEA_CTX *ctx, uint8_t *data, size_t len) {
    lea_online_init(ctx);
    lea_online_update(ctx, data, len);
    /* 위반: lea_online_final 호출 없이 종료 — SSP 미제로화 */
}

/* ===== P13: COM-003 하드코딩 프라이빗 키 (private_key) ===== */
void p13_hardcoded_priv_key(void) {
    uint8_t private_key[32] = {
        0xf5, 0x1e, 0x3a, 0x4c, 0x9b, 0x2d, 0x7e, 0x8f,
        0xa0, 0x1b, 0x3c, 0x5e, 0x7a, 0x9d, 0x2f, 0x4b,
        0x6e, 0x8c, 0x0a, 0x3d, 0x5f, 0x7b, 0x9e, 0x1c,
        0x4a, 0x6d, 0x8b, 0x0e, 0x2c, 0x4f, 0x7a, 0x9c
    };
    (void)private_key;
}

/* ===== P14: COM-003 하드코딩 암호화 키 (encrypt_key) ===== */
void p14_hardcoded_encrypt_key(LEA_KEY *ctx) {
    uint8_t encrypt_key[16] = {
        0x13, 0x11, 0x1d, 0x7f, 0xe3, 0x94, 0x4a, 0x17,
        0xf3, 0x07, 0xa7, 0x8b, 0x4d, 0x2b, 0x30, 0xc5
    };
    lea_set_key(ctx, encrypt_key, 128);
}
"""

# ─────────────────────────────────────────────────────
# 파일 2: violations_mode.c  (모드 룰 위반 — P15~P22)
# ─────────────────────────────────────────────────────
VIOLATIONS_MODE_C = r"""
#include <stdint.h>
#include <string.h>
#include "lea.h"

/* ===== P15: GCM-001 GCM 태그 검증 생략 ===== */
int p15_gcm_no_tag_check(LEA_KEY *ctx, uint8_t *ct, size_t len,
                          uint8_t *nonce, uint8_t *pt) {
    uint8_t tag[16];
    /* 위반: 태그 검증 없이 평문 반환 */
    lea_gcm_decrypt(ctx, ct, pt, len, nonce, tag);
    return 0;
}

/* ===== P16: GCM-001 GCM 태그 비교 없이 처리 ===== */
void p16_gcm_tag_ignored(LEA_KEY *ctx, uint8_t *ct, size_t len,
                          uint8_t *nonce, uint8_t *pt) {
    uint8_t tag_out[16];
    lea_gcm_decrypt(ctx, ct, pt, len, nonce, tag_out);
    /* 위반: tag_out을 읽지도 비교하지도 않음 */
    (void)tag_out;
}

/* ===== P17: CTR-002 static counter 재사용 ===== */
void p17_static_counter(LEA_KEY *ctx, uint8_t *data, size_t len) {
    static uint8_t counter[16] = {0};  /* 위반: static — 재사용됨 */
    lea_ctr_encrypt(ctx, data, data, len, counter);
}

/* ===== P18: CTR-002 global counter 재사용 ===== */
static uint8_t g_ctr_counter[16] = {0x00};  /* 위반: 전역 고정 카운터 */
void p18_global_counter(LEA_KEY *ctx, uint8_t *data, size_t len) {
    lea_ctr_encrypt(ctx, data, data, len, g_ctr_counter);
}

/* ===== P19: CBC-003 고정 IV (전부 0) ===== */
void p19_cbc_zero_iv(LEA_KEY *ctx, uint8_t *pt, size_t len, uint8_t *ct) {
    uint8_t iv[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    lea_cbc_encrypt(ctx, pt, ct, len, iv);
}

/* ===== P20: COM-003 GCM용 하드코딩 nonce (gcm_nonce) ===== */
void p20_hardcoded_gcm_nonce(LEA_KEY *ctx, uint8_t *pt, size_t len, uint8_t *ct) {
    uint8_t gcm_nonce[12] = {
        0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
        0x12, 0x34, 0x56, 0x78
    };
    uint8_t tag[16];
    lea_gcm_decrypt(ctx, pt, ct, len, gcm_nonce, tag);
}

/* ===== P21: COM-003 CTR용 하드코딩 counter_iv ===== */
void p21_hardcoded_ctr_iv(LEA_KEY *ctx, uint8_t *data, size_t len) {
    uint8_t counter_iv[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    lea_ctr_encrypt(ctx, data, data, len, counter_iv);
}

/* ===== P22: COM-004 srand(고정값)으로 key 생성 ===== */
void p22_fixed_seed_key(uint8_t *key) {
    srand(0xdeadbeef);  /* 위반: 고정 시드 */
    for (int i = 0; i < 16; i++) key[i] = (uint8_t)(rand() & 0xff);
}
"""

# ─────────────────────────────────────────────────────
# 파일 3: violations_lea.c  (LEA 알고리즘 위반 — P23~P30)
# ─────────────────────────────────────────────────────
VIOLATIONS_LEA_C = r"""
#include <stdint.h>
#include "lea.h"

/* ===== P23: LEA-007 비표준 키 길이 (160비트) ===== */
void p23_wrong_key_length_160(LEA_KEY *ctx) {
    uint8_t bad_key[20];
    memset(bad_key, 0xAA, sizeof(bad_key));
    lea_set_key(ctx, bad_key, 160);  /* 위반: 128/192/256만 허용 */
}

/* ===== P24: LEA-007 비표준 키 길이 (64비트) ===== */
void p24_wrong_key_length_64(LEA_KEY *ctx) {
    uint8_t short_key[8] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    lea_set_key(ctx, short_key, 64);  /* 위반: 너무 짧은 키 */
}

/* ===== P25: LEA-009 라운드 수 오류 (20라운드) ===== */
#define LEA_ROUNDS_WRONG 20  /* 위반: 128비트는 32라운드 */
void p25_wrong_rounds_20(void) {
    int rounds = LEA_ROUNDS_WRONG;
    (void)rounds;
}

/* ===== P26: LEA-009 라운드 수 오류 (16라운드) ===== */
#define LEA128_ROUNDS 16  /* 위반: 128비트는 32라운드 */
void p26_wrong_rounds_16(void) {
    int r = LEA128_ROUNDS;
    (void)r;
}

/* ===== P27: COM-003 하드코딩 LEA 라운드 키 (round_key) ===== */
void p27_hardcoded_round_key(void) {
    uint32_t round_key[32] = {
        0xab012345, 0xcd678901, 0xef234567, 0x01890123,
        0x23456789, 0x456789ab, 0x6789abcd, 0x89abcdef,
        0xabcdef01, 0xcdef0123, 0xef012345, 0x01234567,
        0x23456789, 0x456789ab, 0x6789abcd, 0x89abcdef,
        0xabcdef01, 0xcdef0123, 0xef012345, 0x01234567,
        0x23456789, 0x456789ab, 0x6789abcd, 0x89abcdef,
        0xabcdef01, 0xcdef0123, 0xef012345, 0x01234567,
        0x23456789, 0x456789ab, 0x6789abcd, 0x89abcdef
    };
    (void)round_key;
}

/* ===== P28: COM-003 하드코딩 LEA 키 (lea_key 변수) ===== */
void p28_hardcoded_lea_key(LEA_KEY *ctx) {
    uint8_t lea_key[16] = {
        0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78,
        0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0
    };
    lea_set_key(ctx, lea_key, 128);
}

/* ===== P29: COM-001 memset으로 키 버퍼 제로화 (key_buf) ===== */
void p29_memset_key(uint8_t *key_buf, size_t len) {
    memset(key_buf, 0, len);  /* 위반 */
}

/* ===== P30: COM-005 final 없이 update만 ===== */
void p30_update_no_final(LEA_CTX *ctx, uint8_t *data, size_t len) {
    lea_online_init(ctx);
    lea_online_update(ctx, data, len);
    /* 위반: final 없음 */
}
"""

# ─────────────────────────────────────────────────────
# 파일 4: safe_code_v3.c  (정상 코드 — N01~N20)
# ─────────────────────────────────────────────────────
SAFE_CODE_V3_C = r"""
#include <stdint.h>
#include <string.h>
#include "lea.h"

/* ===== N01: ARIA S-box — COM-003 오탐 방지 ===== */
static const uint8_t aria_sbox1[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0
};

/* ===== N02: LEA delta 상수 — COM-003 오탐 방지 ===== */
static const uint32_t lea_delta[8] = {
    0xc3efe9db, 0x44626b02, 0x79e27c8a, 0x78df30ec,
    0x715ea49e, 0xc785da0a, 0xe04ef22a, 0xe5c40957
};

/* ===== N03: 테스트 벡터 (test_key) — COM-003 오탐 방지 ===== */
static const uint8_t test_key[16] = {
    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78,
    0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0
};

/* ===== N04: KAT 평문 (kat_plaintext) — COM-003 오탐 방지 ===== */
static const uint8_t kat_plaintext[16] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

/* ===== N05: CRC 테이블 (crc_table) — COM-003 오탐 방지 ===== */
static const uint32_t crc_table[16] = {
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba,
    0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
    0x0edb8832, 0x79dcb8a4, 0xe0d5e91b, 0x97d2d988,
    0x09b64c2b, 0x7eb17cbf, 0xe7b82d08, 0x90bf1d1e
};

/* ===== N06: 룩업 테이블 (lookup_table) — COM-003 오탐 방지 ===== */
static const uint8_t lookup_table[16] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
    0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb
};

/* ===== N07: AES MDS 행렬 (mds_matrix) — COM-003 오탐 방지 ===== */
static const uint8_t mds_matrix[16] = {
    0x02, 0x03, 0x01, 0x01, 0x01, 0x02, 0x03, 0x01,
    0x01, 0x01, 0x02, 0x03, 0x03, 0x01, 0x01, 0x02
};

/* ===== N08: 마스킹 상수 (mask_const) — COM-003 오탐 방지 ===== */
static const uint32_t mask_const[8] = {
    0xffffffff, 0x0f0f0f0f, 0x33333333, 0x55555555,
    0xaaaaaaaa, 0xcccccccc, 0xf0f0f0f0, 0xff00ff00
};

/* ===== N09: 순열 테이블 (perm_table) — COM-003 오탐 방지 ===== */
static const uint8_t perm_table[16] = {
    0x0e, 0x04, 0x0d, 0x01, 0x02, 0x0f, 0x0b, 0x08,
    0x03, 0x0a, 0x06, 0x0c, 0x05, 0x09, 0x00, 0x07
};

/* ===== N10: rand()를 배열 인덱스에 사용 — COM-004 오탐 방지 ===== */
void n10_rand_as_index(void) {
    int arr[16] = {0};
    int idx = rand() % 16;
    arr[idx] = 1;
    (void)arr;
}

/* ===== N11: rand()를 범위 제한 카운터에 사용 — COM-004 오탐 방지 ===== */
void n11_rand_bounded(void) {
    int count = rand() % 100;  /* 반복 횟수 — 비암호 용도 */
    (void)count;
}

/* ===== N12: rand()를 테스트 출력에 사용 — COM-004 오탐 방지 ===== */
void n12_rand_for_test(void) {
    /* 단위 테스트용 랜덤 값 생성 (암호 연산 아님) */
    int val = rand() % 256;
    printf("test val: %d\n", val);
}

/* ===== N13: 올바른 API 순서 (init→update→final) ===== */
void n13_correct_api_order(LEA_CTX *ctx, uint8_t *data, size_t len) {
    lea_online_init(ctx);
    lea_online_update(ctx, data, len);
    lea_online_final(ctx, data, &len);
}

/* ===== N14: init→update×2→final 순서도 올바름 ===== */
void n14_multi_update(LEA_CTX *ctx, uint8_t *d1, size_t l1,
                       uint8_t *d2, size_t l3) {
    lea_online_init(ctx);
    lea_online_update(ctx, d1, l1);
    lea_online_update(ctx, d2, l3);
    lea_online_final(ctx, d1, &l1);
}

/* ===== N15: 올바른 키 제로화 (secure_clear 사용) ===== */
void n15_proper_clear(uint8_t *key_buf, size_t len) {
    /* 올바른 방법: secure_clear 사용 */
    secure_clear(key_buf, len);
}

/* ===== N16: 알고리즘 상수 (round_const) — COM-003 오탐 방지 ===== */
static const uint32_t round_const[4] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
};

/* ===== N17: AES rcon 상수 (rcon) — COM-003 오탐 방지 ===== */
static const uint8_t rcon[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

/* ===== N18: 테스트 IV (test_iv) — COM-003 오탐 방지 ===== */
static const uint8_t test_iv[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

/* ===== N19: 샘플 벡터 (sample_vector) — COM-003 오탐 방지 ===== */
static const uint8_t sample_vector[16] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
};

/* ===== N20: KAT 암호문 벡터 (kat_ct) — COM-003 오탐 방지 ===== */
static const uint8_t kat_ct[16] = {
    0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
    0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97
};
"""

# ─────────────────────────────────────────────────────
# Minimal header
# ─────────────────────────────────────────────────────
LEA_H = r"""
#ifndef LEA_H
#define LEA_H
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

typedef struct { uint32_t rk[8][32]; } LEA_KEY;
typedef struct { uint32_t state[4]; int initialized; } LEA_CTX;

int  lea_set_key(LEA_KEY *ctx, const uint8_t *key, int key_bits);
void lea_encrypt(const LEA_KEY *ctx, const uint8_t *pt, uint8_t *ct);
void lea_decrypt(const LEA_KEY *ctx, const uint8_t *ct, uint8_t *pt);
int  lea_cbc_encrypt(const LEA_KEY *ctx, const uint8_t *pt, uint8_t *ct,
                     size_t len, const uint8_t *iv);
int  lea_cbc_decrypt(const LEA_KEY *ctx, const uint8_t *ct, uint8_t *pt,
                     size_t len, const uint8_t *iv);
int  lea_ctr_encrypt(const LEA_KEY *ctx, const uint8_t *pt, uint8_t *ct,
                     size_t len, uint8_t *counter);
int  lea_gcm_decrypt(const LEA_KEY *ctx, const uint8_t *ct, uint8_t *pt,
                     size_t len, const uint8_t *nonce, uint8_t *tag);
int  lea_online_init(LEA_CTX *ctx);
int  lea_online_update(LEA_CTX *ctx, const uint8_t *data, size_t len);
int  lea_online_final(LEA_CTX *ctx, uint8_t *out, size_t *out_len);
void secure_clear(void *buf, size_t len);

#endif /* LEA_H */
"""

# ─────────────────────────────────────────────────────
# Ground Truth (50건)
# ─────────────────────────────────────────────────────
GROUND_TRUTH = """# Accuracy Test v3 — Ground Truth (50건)
# Format: file | label | expected_rule_id | description

## violations_com.c (P = 실제 위반, 14건)
violations_com.c | P | COM-003 | P01: hardcoded aes_key (16byte, 128bit)
violations_com.c | P | COM-003 | P02: hardcoded master_key (32byte, 256bit)
violations_com.c | P | COM-003 | P03: hardcoded session_key (24byte, 192bit)
violations_com.c | P | COM-003 | P04: hardcoded iv variable + cbc_encrypt
violations_com.c | P | COM-003 | P05: hardcoded enc_nonce (12byte)
violations_com.c | P | COM-001 | P06: weak zeroize key_material via memset
violations_com.c | P | COM-001 | P07: weak zeroize session_key via loop (no volatile)
violations_com.c | P | COM-004 | P08: rand() for IV generation (iv[] = rand())
violations_com.c | P | COM-004 | P09: rand() for nonce generation
violations_com.c | P | COM-004 | P10: rand() for key generation (srand fixed seed)
violations_com.c | P | COM-005 | P11: update before init (no init)
violations_com.c | P | COM-005 | P12: init without final
violations_com.c | P | COM-003 | P13: hardcoded private_key (32byte)
violations_com.c | P | COM-003 | P14: hardcoded encrypt_key (16byte)

## violations_mode.c (P = 실제 위반, 8건)
violations_mode.c | P | GCM-001 | P15: GCM no tag verification (tag ignored)
violations_mode.c | P | GCM-001 | P16: GCM tag_out cast to void
violations_mode.c | P | CTR-002 | P17: static counter reuse
violations_mode.c | P | CTR-002 | P18: global counter reuse
violations_mode.c | P | COM-003 | P19: hardcoded CBC zero IV (all 0x00)
violations_mode.c | P | COM-003 | P20: hardcoded gcm_nonce
violations_mode.c | P | COM-003 | P21: hardcoded counter_iv (CTR mode)
violations_mode.c | P | COM-004 | P22: srand(fixed) for key generation

## violations_lea.c (P = 실제 위반, 8건)
violations_lea.c | P | LEA-007 | P23: wrong key length 160-bit
violations_lea.c | P | LEA-007 | P24: wrong key length 64-bit
violations_lea.c | P | LEA-009 | P25: wrong round count 20
violations_lea.c | P | LEA-009 | P26: wrong round count 16
violations_lea.c | P | COM-003 | P27: hardcoded round_key (32 uint32 values)
violations_lea.c | P | COM-003 | P28: hardcoded lea_key
violations_lea.c | P | COM-001 | P29: memset on key_buf
violations_lea.c | P | COM-005 | P30: init+update without final

## safe_code_v3.c (N = 정상 코드, 20건)
safe_code_v3.c | N | COM-003 | N01: aria_sbox1 — S-box 상수
safe_code_v3.c | N | COM-003 | N02: lea_delta — 알고리즘 델타 상수
safe_code_v3.c | N | COM-003 | N03: test_key — 테스트 벡터
safe_code_v3.c | N | COM-003 | N04: kat_plaintext — KAT 평문
safe_code_v3.c | N | COM-003 | N05: crc_table — CRC 테이블
safe_code_v3.c | N | COM-003 | N06: lookup_table
safe_code_v3.c | N | COM-003 | N07: mds_matrix — AES MDS 행렬
safe_code_v3.c | N | COM-003 | N08: mask_const — 마스킹 상수
safe_code_v3.c | N | COM-003 | N09: perm_table — 순열 테이블
safe_code_v3.c | N | COM-004 | N10: rand() % 16 — 배열 인덱스
safe_code_v3.c | N | COM-004 | N11: rand() % 100 — 반복 카운터
safe_code_v3.c | N | COM-004 | N12: rand() for test/printf
safe_code_v3.c | N | COM-005 | N13: correct init→update→final
safe_code_v3.c | N | COM-005 | N14: correct init→update×2→final
safe_code_v3.c | N | COM-001 | N15: secure_clear() 올바른 사용
safe_code_v3.c | N | COM-003 | N16: round_const — SHA 라운드 상수
safe_code_v3.c | N | COM-003 | N17: rcon — AES rcon 상수
safe_code_v3.c | N | COM-003 | N18: test_iv — 테스트 IV
safe_code_v3.c | N | COM-003 | N19: sample_vector — 샘플 벡터
safe_code_v3.c | N | COM-003 | N20: kat_ct — KAT 암호문 벡터
"""


def create_zip():
    output_path = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                               "testdata", "accuracy_test_v3.zip")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("src/violations_com.c", VIOLATIONS_COM_C)
        zf.writestr("src/violations_mode.c", VIOLATIONS_MODE_C)
        zf.writestr("src/violations_lea.c", VIOLATIONS_LEA_C)
        zf.writestr("src/safe_code_v3.c", SAFE_CODE_V3_C)
        zf.writestr("include/lea.h", LEA_H)
        zf.writestr("GROUND_TRUTH.md", GROUND_TRUTH)

    buf.seek(0)
    with open(output_path, "wb") as f:
        f.write(buf.read())

    gt_cases = [l for l in GROUND_TRUTH.splitlines() if '|' in l and not l.startswith('#')]
    p_cases = [l for l in gt_cases if '| P |' in l]
    n_cases = [l for l in gt_cases if '| N |' in l]
    print(f"Created: {output_path}")
    print(f"Total: {len(gt_cases)} cases (P={len(p_cases)}, N={len(n_cases)})")


if __name__ == "__main__":
    create_zip()
