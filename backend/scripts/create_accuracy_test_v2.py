"""
KCMVP 정확도 테스트 데이터 v2 생성 스크립트.
- 모든 주요 COM 룰셋 + LEA/CBC/CTR/GCM 룰 커버
- Ground Truth: violations.c (위반 케이스), safe_code.c (정상 코드)
"""
import zipfile
import io
import os
import sys

# ─────────────────────────────────────────────────────────────
# Ground Truth P (실제 위반)
# ─────────────────────────────────────────────────────────────
VIOLATIONS_C = r"""
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "lea.h"

/* ===== P01: COM-003 하드코딩 키 (변수명 master_key) ===== */
void p01_hardcoded_key(LEA_KEY *ctx) {
    uint8_t master_key[16] = {
        0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78,
        0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0
    };
    lea_set_key(ctx, master_key, 128);
}

/* ===== P02: COM-001 약한 제로화 (일반 memset 사용) ===== */
void p02_weak_zeroize(uint8_t *key_buf, size_t len) {
    /* 위반: secure_clear 또는 explicit_bzero 사용 필요 */
    memset(key_buf, 0, len);
}

/* ===== P03: COM-004 비암호학적 PRNG로 IV 생성 ===== */
void p03_weak_rng(uint8_t *iv) {
    srand((unsigned int)time(NULL));
    for (int i = 0; i < 16; i++) {
        iv[i] = (uint8_t)(rand() & 0xff);
    }
}

/* ===== P04: COM-005 API 호출 순서 위반 (init 없이 update) ===== */
void p04_api_order_violation(LEA_CTX *ctx, uint8_t *data, size_t len) {
    lea_online_update(ctx, data, len);
    lea_online_final(ctx, data, &len);
}

/* ===== P05: COM-003 하드코딩 IV (변수명 secret_iv) ===== */
void p05_hardcoded_iv(LEA_KEY *ctx, uint8_t *pt, size_t len, uint8_t *ct) {
    uint8_t secret_iv[16] = {
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99
    };
    lea_cbc_encrypt(ctx, pt, ct, len, secret_iv);
}

/* ===== P06: CBC-003 고정 IV (전부 0) ===== */
void p06_fixed_zero_iv(LEA_KEY *ctx, uint8_t *pt, size_t len, uint8_t *ct) {
    uint8_t iv[16] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    lea_cbc_encrypt(ctx, pt, ct, len, iv);
}

/* ===== P07: COM-003 하드코딩 nonce (변수명 enc_nonce) ===== */
void p07_hardcoded_nonce(void) {
    uint8_t enc_nonce[12] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc
    };
    (void)enc_nonce;
}
"""

# ─────────────────────────────────────────────────────────────
# Ground Truth N (정상 코드 — 오탐 유발 패턴)
# ─────────────────────────────────────────────────────────────
SAFE_CODE_C = r"""
#include <stdint.h>
#include <string.h>
#include "lea.h"

/* ===== N01: ARIA S-box — COM-003 오탐 방지 (변수명 aria_sbox) ===== */
static const uint8_t aria_sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0
};

/* ===== N02: LEA delta 상수 — COM-003 오탐 방지 ===== */
static const uint32_t delta[8] = {
    0xc3efe9db, 0x44626b02, 0x79e27c8a, 0x78df30ec,
    0x715ea49e, 0xc785da0a, 0xe04ef22a, 0xe5c40957
};

/* ===== N03: 테스트벡터 — COM-003 오탐 방지 ===== */
static const uint8_t test_pt[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
};

/* ===== N04: rand()를 배열 인덱스에 사용 — COM-004 오탐 방지 ===== */
void n04_rand_as_index(void) {
    int arr[16] = {0};
    int idx = rand() % 16;
    arr[idx] = 1;
    (void)arr;
}

/* ===== N05: 일반 연산 함수 — COM-001 오탐 없음 ===== */
void n05_benign_compute(uint8_t *buf, size_t len) {
    /* 암호 키가 아닌 일반 버퍼 처리 — COM-001 대상 아님 */
    for (size_t i = 0; i < len; i++) buf[i] ^= 0xff;
}

/* ===== N06: 올바른 API 순서 (init→update→final) ===== */
void n06_correct_api_order(LEA_CTX *ctx, uint8_t *data, size_t len) {
    lea_online_init(ctx);
    lea_online_update(ctx, data, len);
    lea_online_final(ctx, data, &len);
}

/* ===== N07: KAT 벡터 — COM-003 오탐 방지 (변수명 kat_key) ===== */
static const uint8_t kat_key[16] = {
    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78,
    0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0
};

/* ===== N08: lookup table — COM-003 오탐 방지 ===== */
static const uint8_t lookup_table[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
    0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb
};
"""

# ─────────────────────────────────────────────────────────────
# LEA-specific violations (추가 테스트)
# ─────────────────────────────────────────────────────────────
LEA_VIOLATIONS_C = r"""
#include <stdint.h>
#include "lea.h"

/* ===== LP01: LEA-007 잘못된 키 길이 (비표준 17바이트) ===== */
void lp01_wrong_key_length(LEA_KEY *ctx) {
    uint8_t bad_key[17];
    memset(bad_key, 0xAB, sizeof(bad_key));
    lea_set_key(ctx, bad_key, 136);  /* 위반: 128/192/256만 허용 */
}

/* ===== LP02: LEA-009 라운드 수 하드코딩 오류 ===== */
#define ROUND_COUNT 20  /* 위반: LEA-128은 24라운드여야 함 */
void lp02_wrong_round_count(void) {
    int rounds = ROUND_COUNT;
    (void)rounds;
}
"""

# ─────────────────────────────────────────────────────────────
# CBC/CTR/GCM additional violations
# ─────────────────────────────────────────────────────────────
MODE_VIOLATIONS_C = r"""
#include <stdint.h>
#include <string.h>
#include "lea.h"

/* ===== MP01: CBC 패딩 검증 생략 ===== */
int mp01_no_padding_check(uint8_t *ct, size_t len, uint8_t *pt) {
    /* PKCS7 패딩 검증 없이 직접 반환 — 위반 */
    memcpy(pt, ct, len);
    return (int)len;
}

/* ===== MP02: CTR 카운터 재사용 위험 ===== */
void mp02_counter_reuse(LEA_KEY *ctx, uint8_t *data, size_t len) {
    static uint8_t counter[16] = {0};  /* static = 재사용 위험 */
    lea_ctr_encrypt(ctx, data, data, len, counter);
}

/* ===== MP03: GCM 태그 검증 생략 ===== */
int mp03_no_tag_verify(LEA_KEY *ctx, uint8_t *ct, size_t len,
                        uint8_t *nonce, uint8_t *pt) {
    uint8_t tag[16];
    /* 태그 생성 후 검증 없이 반환 — 위반 */
    lea_gcm_decrypt(ctx, ct, pt, len, nonce, tag);
    return 0;
}
"""

# ─────────────────────────────────────────────────────────────
# Minimal header file
# ─────────────────────────────────────────────────────────────
LEA_H = r"""
#ifndef LEA_H
#define LEA_H

#include <stdint.h>
#include <stddef.h>

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

# ─────────────────────────────────────────────────────────────
# Ground truth mapping (for confusion matrix evaluation)
# ─────────────────────────────────────────────────────────────
GROUND_TRUTH = """# Accuracy Test v2 — Ground Truth
# Format: file | label | expected_rule_id | description

## violations.c (P = positive / real violations)
violations.c | P | COM-003 | P01: hardcoded master_key (key variable + lea_set_key)
violations.c | P | COM-001 | P02: weak zeroize (plain memset, not secure_clear)
violations.c | P | COM-004 | P03: rand() for IV generation
violations.c | P | COM-005 | P04: lea_online_update before lea_online_init
violations.c | P | COM-003 | P05: hardcoded secret_iv (iv variable + cbc_encrypt)
violations.c | P | COM-003 | P06: hardcoded fixed-zero IV (all zeros, clearly hardcoded)
violations.c | P | COM-003 | P07: hardcoded enc_nonce (nonce variable)

## safe_code.c (N = negative / benign patterns)
safe_code.c  | N | COM-003 | N01: ARIA S-box (aria_sbox variable name)
safe_code.c  | N | COM-003 | N02: LEA delta constants (delta variable name)
safe_code.c  | N | COM-003 | N03: test vector (test_pt variable name)
safe_code.c  | N | COM-004 | N04: rand() as array index (non-crypto use)
safe_code.c  | N | COM-001 | N05: benign compute (not a crypto key variable)
safe_code.c  | N | COM-005 | N06: correct API order (init→update→final)
safe_code.c  | N | COM-003 | N07: KAT key vector (kat_key variable name)
safe_code.c  | N | COM-003 | N08: lookup_table (lookup_table variable name)

## lea_violations.c (P = positive)
lea_violations.c | P | LEA-007 | LP01: wrong key length (17 bytes)
lea_violations.c | P | LEA-009 | LP02: wrong round count define

## mode_violations.c (P = positive)
mode_violations.c | P | CBC-001 | MP01: CBC no padding check
mode_violations.c | P | CTR-002 | MP02: CTR counter reuse (static counter)
mode_violations.c | P | GCM-001 | MP03: GCM no tag verification
"""


def create_zip():
    output_path = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                               "testdata", "accuracy_test_v2.zip")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("src/violations.c", VIOLATIONS_C)
        zf.writestr("src/safe_code.c", SAFE_CODE_C)
        zf.writestr("src/lea_violations.c", LEA_VIOLATIONS_C)
        zf.writestr("src/mode_violations.c", MODE_VIOLATIONS_C)
        zf.writestr("include/lea.h", LEA_H)
        zf.writestr("GROUND_TRUTH.md", GROUND_TRUTH)

    buf.seek(0)
    with open(output_path, "wb") as f:
        f.write(buf.read())
    print(f"Created: {output_path}")
    print(f"Ground truth: {len([l for l in GROUND_TRUTH.splitlines() if '|' in l and not l.startswith('#')])} test cases")


if __name__ == "__main__":
    create_zip()
