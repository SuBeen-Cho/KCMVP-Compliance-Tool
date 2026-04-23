"""
accuracy_test_v7.zip 생성 스크립트

v6(62 cases) + 8 new cases:
  P36 violations_ctr_static.c    CTR-002  static counter → nonce 재사용 위반
  P37 violations_cmac_nokey.c    CMAC-001 0x87 XOR 서브키 파생 없음 → 위반
  P38 violations_com003_key.c    COM-003  변수명 key + 8+개 hex 리터럴 → 하드코딩 키 위반
  N28 safe_ctr_v7.c              CTR-002  stack counter → 재사용 없음
  N29 safe_cmac_v7.c             CMAC-001 올바른 0x87 XOR 서브키 파생 → 정상
  N30 safe_com003_sbox.c         COM-003  S-box 상수 배열 → 오탐이어야 함 (FP 방지 테스트)
  N31 safe_com003_delta.c        COM-003  LEA delta 상수 → 오탐이어야 함 (FP 방지 테스트)
  N32 safe_com003_testvec.c      COM-003  테스트벡터 배열 → 오탐이어야 함 (FP 방지 테스트)
"""

import zipfile
from pathlib import Path

BACKEND_ROOT = Path(__file__).parent.parent
OUT_PATH     = BACKEND_ROOT / "testdata" / "accuracy_test_v7.zip"
V6_ZIP       = BACKEND_ROOT / "testdata" / "accuracy_test_v6.zip"

# ── P36: CTR-002 위반 — static counter in ctr_init ──────────────────
VIOLATIONS_CTR_STATIC = """\
/* P36: CTR-002 — static counter → CTR nonce 재사용 위반 */
#include <string.h>

typedef struct { unsigned char *key; int keylen; } CTRCtx;

void ctr_init(CTRCtx *ctx, unsigned char *iv, unsigned int ivlen) {
    static unsigned char counter[16];   /* VIOLATION: static counter → 재사용 */
    memcpy(counter, iv, ivlen);
    (void)ctx;
}

void ctr_encrypt(CTRCtx *ctx, const unsigned char *pt, unsigned char *ct, unsigned int len) {
    unsigned int i;
    for (i = 0; i < len; i++) {
        ct[i] = pt[i] ^ 0xAA;
    }
    (void)ctx;
}
"""

# ── P37: CMAC-001 위반 — subkey 파생 없음 ────────────────────────────
VIOLATIONS_CMAC_NOKEY = """\
/* P37: CMAC-001 — K1/K2 서브키 파생에서 0x87 XOR 없음 → CMAC 위반 */
#include <stdint.h>
#include <string.h>

void lea_cmac_init(void *ctx, const uint8_t *key, int keylen) {
    uint8_t L[16] = {0};
    uint8_t K1[16] = {0};
    uint8_t K2[16] = {0};
    int i;

    /* L = ENC(Key, 0^128) — 올바름 */
    (void)ctx;
    (void)key;
    (void)keylen;

    /* VIOLATION: K1 = L << 1 만 수행, msb(L) 체크 후 0x87 XOR 없음 */
    for (i = 0; i < 15; i++) {
        K1[i] = (L[i] << 1) | (L[i+1] >> 7);
    }
    K1[15] = L[15] << 1;
    /* if (L[0] & 0x80) K1[15] ^= 0x87;  ← 누락 */

    /* K2 = K1 << 1 도 마찬가지로 0x87 XOR 없음 */
    for (i = 0; i < 15; i++) {
        K2[i] = (K1[i] << 1) | (K1[i+1] >> 7);
    }
    K2[15] = K1[15] << 1;
    /* if (K1[0] & 0x80) K2[15] ^= 0x87;  ← 누락 */

    (void)K2;
}
"""

# ── P38: COM-003 위반 — 변수명 "key" + hex 리터럴 ─────────────────────
VIOLATIONS_COM003_KEY = """\
/* P38: COM-003 — 하드코딩 암호키 위반 */
#include <stdint.h>

/* VIOLATION: 변수명 'aes_key', 함수 인자로 직접 전달 */
static const uint8_t aes_key[16] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

extern void lea_set_key(void *ctx, const uint8_t *key, int len);
extern void *g_ctx;

void init_module(void) {
    lea_set_key(g_ctx, aes_key, 128);  /* 암호키를 소스에 박아 직접 전달 */
}
"""

# ── N28: CTR-002 정상 — stack counter ────────────────────────────────
SAFE_CTR_V7 = """\
/* N28: CTR-002 — stack counter → 재사용 없음 (정상) */
#include <string.h>

typedef struct { unsigned char *key; int keylen; } CTRCtx;

void ctr_init(CTRCtx *ctx, unsigned char *iv, unsigned int ivlen) {
    unsigned char counter[16];   /* stack: 매 호출마다 새로 초기화 */
    memcpy(counter, iv, ivlen);
    (void)ctx;
    (void)counter;
}
"""

# ── N29: CMAC-001 정상 — 0x87 XOR 포함 ──────────────────────────────
SAFE_CMAC_V7 = """\
/* N29: CMAC-001 — 올바른 K1/K2 서브키 파생 (정상) */
#include <stdint.h>
#include <string.h>

void lea_cmac_init(void *ctx, const uint8_t *key, int keylen) {
    uint8_t L[16] = {0};
    uint8_t K1[16] = {0};
    uint8_t K2[16] = {0};
    int i;

    (void)ctx;
    (void)key;
    (void)keylen;

    /* K1 = L << 1, msb(L)==1 이면 K1[15] ^= 0x87 */
    for (i = 0; i < 15; i++) {
        K1[i] = (L[i] << 1) | (L[i+1] >> 7);
    }
    K1[15] = L[15] << 1;
    if (L[0] & 0x80) K1[15] ^= 0x87;   /* CORRECT: Rb XOR */

    /* K2 = K1 << 1, msb(K1)==1 이면 K2[15] ^= 0x87 */
    for (i = 0; i < 15; i++) {
        K2[i] = (K1[i] << 1) | (K1[i+1] >> 7);
    }
    K2[15] = K1[15] << 1;
    if (K1[0] & 0x80) K2[15] ^= 0x87;  /* CORRECT: Rb XOR */

    (void)K2;
}
"""

# ── N30: COM-003 정상 — S-box 상수 (오탐 방지) ──────────────────────
SAFE_COM003_SBOX = """\
/* N30: COM-003 — S-box 치환표 (오탐이면 안 됨) */
#include <stdint.h>

/* AES S-box: 공개 알고리즘 상수, 키가 아님 */
static const uint8_t aes_sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0
};

uint8_t sbox_lookup(uint8_t x) {
    return aes_sbox[x];
}
"""

# ── N31: COM-003 정상 — LEA delta 상수 (오탐 방지) ──────────────────
SAFE_COM003_DELTA = """\
/* N31: COM-003 — LEA delta 알고리즘 상수 (오탐이면 안 됨) */
#include <stdint.h>

/* LEA 공개 delta 상수: 알고리즘 규격에 명시된 값 */
static const uint32_t lea_delta[8] = {
    0xc3efe9db, 0x44626b02, 0x79e27c8a, 0x78df30ec,
    0x715ea49e, 0xc785da0a, 0xe04ef22a, 0xe5c40957
};

uint32_t get_delta(int i) {
    return lea_delta[i & 7];
}
"""

# ── N32: COM-003 정상 — 테스트벡터 (오탐 방지) ──────────────────────
SAFE_COM003_TESTVEC = """\
/* N32: COM-003 — 테스트벡터 배열 (오탐이면 안 됨) */
#include <stdint.h>

/* 공개 표준 테스트벡터: KS X 3246 Annex A */
static const uint8_t test_pt[16] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};
static const uint8_t test_ct[16] = {
    0x9f, 0xc8, 0x4e, 0x35, 0x28, 0xc6, 0xc6, 0x18,
    0x55, 0x32, 0xc7, 0xa7, 0x04, 0x64, 0x8b, 0xfd
};

int run_kat(void) {
    /* 테스트벡터는 상수이므로 소스에 포함 허용 */
    (void)test_pt;
    (void)test_ct;
    return 0;
}
"""

NEW_GT_LINES = """\
violations_ctr_static.c | P | CTR-002 | static counter → CTR nonce 재사용 위반
violations_cmac_nokey.c | P | CMAC-001 | 0x87 XOR 서브키 파생 없음
violations_com003_key.c | P | COM-003 | 변수명 key + 8+hex 리터럴 하드코딩 키
safe_ctr_v7.c | N | CTR-002 | stack counter → 재사용 없음
safe_cmac_v7.c | N | CMAC-001 | 올바른 0x87 XOR 서브키 파생
safe_com003_sbox.c | N | COM-003 | S-box 상수 → 오탐이면 안 됨
safe_com003_delta.c | N | COM-003 | LEA delta 상수 → 오탐이면 안 됨
safe_com003_testvec.c | N | COM-003 | 테스트벡터 배열 → 오탐이면 안 됨
"""


def build_zip():
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    v6_entries: dict[str, bytes] = {}
    with zipfile.ZipFile(V6_ZIP) as zf:
        for name in zf.namelist():
            v6_entries[name] = zf.read(name)

    old_gt = v6_entries.get("GROUND_TRUTH.md", b"").decode("utf-8")
    new_gt  = old_gt.rstrip("\n") + "\n" + NEW_GT_LINES

    new_files = {
        "src/violations_ctr_static.c":  VIOLATIONS_CTR_STATIC,
        "src/violations_cmac_nokey.c":  VIOLATIONS_CMAC_NOKEY,
        "src/violations_com003_key.c":  VIOLATIONS_COM003_KEY,
        "src/safe_ctr_v7.c":            SAFE_CTR_V7,
        "src/safe_cmac_v7.c":           SAFE_CMAC_V7,
        "src/safe_com003_sbox.c":       SAFE_COM003_SBOX,
        "src/safe_com003_delta.c":      SAFE_COM003_DELTA,
        "src/safe_com003_testvec.c":    SAFE_COM003_TESTVEC,
    }

    with zipfile.ZipFile(OUT_PATH, "w", zipfile.ZIP_DEFLATED) as zout:
        for name, data in v6_entries.items():
            if name == "GROUND_TRUTH.md":
                zout.writestr("GROUND_TRUTH.md", new_gt)
            else:
                zout.writestr(name, data)
        for name, content in new_files.items():
            zout.writestr(name, content)

    p = sum(1 for l in new_gt.splitlines() if "| P |" in l)
    n = sum(1 for l in new_gt.splitlines() if "| N |" in l)
    print(f"Created: {OUT_PATH}")
    print(f"Ground Truth: P={p}, N={n}, total={p+n}")


if __name__ == "__main__":
    build_zip()
