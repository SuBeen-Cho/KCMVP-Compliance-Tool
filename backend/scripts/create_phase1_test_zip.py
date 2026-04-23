"""
Phase 1 테스트용 ZIP 생성 스크립트.

생성되는 테스트 케이스:
  FAIL ZIP (phase1_fail.zip):
    - src/hardcoded_key.c     : COM-003 - 하드코딩된 실제 키처럼 보이는 배열
    - src/sbox_table.c        : COM-003 오탐용 - S-box 테이블 (실제 키 아님)
    - src/no_error_check.c    : COM-002 - 에러 처리 패턴 없음
    - src/wrong_api_order.c   : COM-005 - lea_online_* 순서 위반
    - src/no_zeroization.c    : COM-001 - 잔존 정보 제거 없음
    - src/weak_rng.c          : COM-004 - rand() 사용

  PASS ZIP (phase1_pass.zip):
    - src/good_key_usage.c    : COM-003 통과 - 외부 주입 키
    - src/good_error.c        : COM-002 통과 - 에러 처리 있음
    - src/good_api_order.c    : COM-005 통과 - 올바른 온라인 API 순서
    - src/good_zeroization.c  : COM-001 통과 - memset_s 사용
    - src/good_rng.c          : COM-004 통과 - getrandom 사용

실행:
  cd backend
  python scripts/create_phase1_test_zip.py
"""

import zipfile
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
OUT_DIR = BACKEND / "testdata"
ZIP_FAIL = OUT_DIR / "phase1_fail.zip"
ZIP_PASS = OUT_DIR / "phase1_pass.zip"

# ─────────────────────────────────────────────────────────────────
# FAIL 케이스 소스 파일 (일반 str, ZIP 저장 시 UTF-8 인코딩)
# ─────────────────────────────────────────────────────────────────

# COM-003: 하드코딩 키처럼 보이는 16바이트 배열 (L1 regex 탐지 -> L2 판정 대상)
HARDCODED_KEY_C = """\
#include <stdint.h>
#include "lea.h"

/* Real encryption key used in production - do not modify */
static const uint8_t g_encrypt_key[16] = {
    0x2b, 0x7e, 0x15, 0x16,
    0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88,
    0x09, 0xcf, 0x4f, 0x3c
};

void encrypt_data(const uint8_t *plain, uint8_t *cipher) {
    lea_encrypt(g_encrypt_key, plain, cipher);
}
"""

# COM-003 false positive: S-box table (L1 detects -> L2 should filter out)
SBOX_TABLE_C = """\
#include <stdint.h>

/* AES S-box lookup table - public algorithm constant */
static const uint8_t aes_sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0
};

uint8_t sbox_lookup(uint8_t idx) {
    return aes_sbox[idx];
}
"""

# COM-002: No error handling - no return -1, no error codes
NO_ERROR_CHECK_C = """\
#include <stdint.h>
#include "lea.h"

/* Encryption without error handling */
void process_data(const uint8_t *key, const uint8_t *plain, uint8_t *cipher) {
    lea_encrypt(key, plain, cipher);
    /* Return value not checked */
    /* No error code returned */
}

int main(void) {
    uint8_t key[16] = {0};
    uint8_t plain[16] = {0};
    uint8_t cipher[16] = {0};
    process_data(key, plain, cipher);
    return 0;
}
"""

# COM-005: lea_online_* out-of-order (update called before init)
WRONG_API_ORDER_C = """\
#include <stdint.h>
#include "lea.h"

/* Wrong order: update called before init */
int stream_encrypt_bad(const uint8_t *key, const uint8_t *data, size_t len, uint8_t *out) {
    LEA_ONLINE_CTX ctx;

    /* update called without init - wrong order */
    lea_online_update(&ctx, data, len, out);
    lea_online_final(&ctx, out);

    return 0;
}

/* Case: exits without calling final */
int stream_encrypt_no_final(const uint8_t *key, const uint8_t *data, size_t len, uint8_t *out) {
    LEA_ONLINE_CTX ctx;
    lea_online_init(&ctx, key, 16);
    lea_online_update(&ctx, data, len, out);
    /* lea_online_final not called - SSP not zeroized */
    return 0;
}
"""

# COM-001: No zeroization after use
NO_ZEROIZATION_C = """\
#include <stdint.h>
#include <string.h>
#include "lea.h"

void encrypt_and_forget(const uint8_t *plain, uint8_t *cipher) {
    uint8_t session_key[16];
    uint8_t round_keys[11][16];

    derive_session_key(session_key);
    lea_key_schedule(session_key, round_keys);

    lea_encrypt_with_rk(round_keys, plain, cipher);

    /* Function returns without zeroizing session_key or round_keys */
}
"""

# COM-004: Uses rand() for IV generation
WEAK_RNG_C = """\
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

/* Non-cryptographic RNG for IV - security vulnerability */
void generate_iv_bad(uint8_t *iv, size_t iv_len) {
    srand((unsigned int)time(NULL));
    for (size_t i = 0; i < iv_len; i++) {
        iv[i] = (uint8_t)(rand() % 256);
    }
}

/* Nonce also uses rand() */
uint32_t get_nonce(void) {
    return (uint32_t)rand();
}
"""

# ─────────────────────────────────────────────────────────────────
# PASS 케이스 소스 파일
# ─────────────────────────────────────────────────────────────────

# COM-003 pass: key injected from outside
GOOD_KEY_USAGE_C = """\
#include <stdint.h>
#include "lea.h"

/* Key injected from external source (KMS/file) at runtime */
int encrypt_with_external_key(
    const uint8_t *key, size_t key_len,
    const uint8_t *plain, uint8_t *cipher
) {
    if (!key || key_len != 16) {
        return -1;
    }
    return lea_encrypt(key, plain, cipher);
}
"""

# COM-002 pass: proper error handling
GOOD_ERROR_C = """\
#include <stdint.h>
#include "lea.h"

#define LEA_OK    0
#define LEA_ERR  -1

int safe_encrypt(const uint8_t *key, const uint8_t *plain, uint8_t *cipher) {
    if (!key || !plain || !cipher) {
        return LEA_ERR;
    }
    int ret = lea_encrypt(key, plain, cipher);
    if (ret != LEA_OK) {
        return -1;
    }
    return LEA_OK;
}
"""

# COM-005 pass: correct online API order
GOOD_API_ORDER_C = """\
#include <stdint.h>
#include "lea.h"

int stream_encrypt_good(
    const uint8_t *key,
    const uint8_t *data, size_t len,
    uint8_t *out
) {
    LEA_ONLINE_CTX ctx;
    int ret;

    /* Correct order: init -> update -> final */
    ret = lea_online_init(&ctx, key, 16);
    if (ret != 0) return -1;

    ret = lea_online_update(&ctx, data, len, out);
    if (ret != 0) return -1;

    ret = lea_online_final(&ctx, out);
    if (ret != 0) return -1;

    return 0;
}
"""

# COM-001 pass: zeroization with memset_s
GOOD_ZEROIZATION_C = """\
#include <stdint.h>
#include <string.h>
#include "lea.h"

void encrypt_secure(const uint8_t *plain, uint8_t *cipher) {
    uint8_t session_key[16];
    uint8_t round_keys[11][16];

    derive_session_key(session_key);
    lea_key_schedule(session_key, round_keys);
    lea_encrypt_with_rk(round_keys, plain, cipher);

    /* Zeroize sensitive data after use */
    memset_s(session_key, sizeof(session_key), 0, sizeof(session_key));
    memset_s(round_keys, sizeof(round_keys), 0, sizeof(round_keys));
}
"""

# COM-004 pass: uses getrandom (CSPRNG)
GOOD_RNG_C = """\
#include <stdint.h>
#include <sys/random.h>

/* Secure IV generation using CSPRNG */
int generate_iv_secure(uint8_t *iv, size_t iv_len) {
    ssize_t n = getrandom(iv, iv_len, 0);
    if (n < 0 || (size_t)n != iv_len) {
        return -1;
    }
    return 0;
}
"""

# Common header
LEA_H = """\
#ifndef LEA_H
#define LEA_H
#include <stdint.h>
#include <stddef.h>

typedef struct { uint8_t state[64]; } LEA_ONLINE_CTX;

int  lea_encrypt(const uint8_t *key, const uint8_t *plain, uint8_t *cipher);
int  lea_encrypt_with_rk(const uint8_t rk[][16], const uint8_t *plain, uint8_t *cipher);
void lea_key_schedule(const uint8_t *key, uint8_t rk[][16]);
int  lea_online_init(LEA_ONLINE_CTX *ctx, const uint8_t *key, size_t key_len);
int  lea_online_update(LEA_ONLINE_CTX *ctx, const uint8_t *in, size_t len, uint8_t *out);
int  lea_online_final(LEA_ONLINE_CTX *ctx, uint8_t *out);
void derive_session_key(uint8_t *key);

#endif
"""


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    # FAIL ZIP
    fail_contents = {
        "src/hardcoded_key.c":  HARDCODED_KEY_C,
        "src/sbox_table.c":     SBOX_TABLE_C,
        "src/no_error_check.c": NO_ERROR_CHECK_C,
        "src/wrong_api_order.c": WRONG_API_ORDER_C,
        "src/no_zeroization.c": NO_ZEROIZATION_C,
        "src/weak_rng.c":       WEAK_RNG_C,
        "include/lea.h":        LEA_H,
    }
    with zipfile.ZipFile(ZIP_FAIL, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, data in fail_contents.items():
            zf.writestr(path, data.encode("utf-8"))
    print(f"생성됨: {ZIP_FAIL.resolve()}")
    print(f"  파일: {list(fail_contents.keys())}")

    # PASS ZIP
    pass_contents = {
        "src/good_key_usage.c":   GOOD_KEY_USAGE_C,
        "src/good_error.c":       GOOD_ERROR_C,
        "src/good_api_order.c":   GOOD_API_ORDER_C,
        "src/good_zeroization.c": GOOD_ZEROIZATION_C,
        "src/good_rng.c":         GOOD_RNG_C,
        "include/lea.h":          LEA_H,
    }
    with zipfile.ZipFile(ZIP_PASS, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, data in pass_contents.items():
            zf.writestr(path, data.encode("utf-8"))
    print(f"생성됨: {ZIP_PASS.resolve()}")
    print(f"  파일: {list(pass_contents.keys())}")


if __name__ == "__main__":
    main()
