"""
LEA 룰셋 검증용 테스트 ZIP 생성 스크립트.
KISA LEA v1.3 참조 구현을 기반으로, 의도적 위반을 삽입한 테스트 코드를 생성한다.

- backend/testdata/lea_rule_test.zip 에 출력
- 각 파일에 어떤 룰 위반이 포함되어 있는지 주석으로 표기

실행 (backend 디렉터리에서):
  python scripts/create_lea_test_zip.py
"""
import zipfile
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
OUT_DIR = BACKEND / "testdata"
OUT_DIR.mkdir(parents=True, exist_ok=True)
ZIP_PATH = OUT_DIR / "lea_rule_test.zip"

# ---------------------------------------------------------------------------
# 1) src/lea_core.c — 핵심 알고리즘 (다수의 missing/regex 위반 삽입)
# ---------------------------------------------------------------------------
LEA_CORE_C = r"""
/*
 * LEA Core — 테스트용 변조 코드
 *
 * [의도적 위반 목록]
 *   LEA-011 (missing): delta 상수값 제거 (0xc3efe9db 등 8개 상수 없음)
 *   LEA-012 (missing): 766995 주석 없음
 *   LEA-013 (missing): T = K 또는 memcpy(T, K 패턴 없음
 *   LEA-027 (missing): ROL9 → ROL8 로 변조
 *   LEA-028 (missing): ROR5 → ROR4 로 변조
 *   LEA-029 (missing): ROR3 → ROR2 로 변조
 *   LEA-041 (regex) : s_box 사용 추가 — LEA는 S-box 없는 ARX 구조
 *   LEA-054 (missing): #include "lea_locl.h" 제거
 *   COM-001 (missing): memset / explicit_bzero 등 잔존 정보 제거 함수 없음
 *   COM-003 (regex) : 하드코딩된 키 배열 추가
 */

#include "lea.h"
#include <string.h>

/* ── LEA-041 위반: S-box 사용 (LEA는 S-box가 없어야 함) ── */
static const unsigned char s_box[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,
    0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76
};

/* ── COM-003 위반: 하드코딩된 키 ── */
static const unsigned char HARDCODED_KEY[16] = {
    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78,
    0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0
};

/* ── LEA-011 위반: delta 상수가 규격값이 아닌 더미값으로 대체됨 ── */
static const unsigned int delta[8][36] = {
    {0xAAAAAAAA, 0xBBBBBBBB, 0xCCCCCCCC, 0xDDDDDDDD,
     0xEEEEEEEE, 0xFFFFFFFF, 0x11111111, 0x22222222,
     0x33333333, 0x44444444, 0x55555555, 0x66666666,
     0x77777777, 0x88888888, 0x99999999, 0x00000000,
     0xAAAAAAAA, 0xBBBBBBBB, 0xCCCCCCCC, 0xDDDDDDDD,
     0xEEEEEEEE, 0xFFFFFFFF, 0x11111111, 0x22222222,
     0x33333333, 0x44444444, 0x55555555, 0x66666666,
     0x77777777, 0x88888888, 0x99999999, 0x00000000,
     0xAAAAAAAA, 0xBBBBBBBB, 0xCCCCCCCC, 0xDDDDDDDD},
    {0x11111111, 0x22222222, 0x33333333, 0x44444444,
     0x55555555, 0x66666666, 0x77777777, 0x88888888,
     0x99999999, 0xAAAAAAAA, 0xBBBBBBBB, 0xCCCCCCCC,
     0xDDDDDDDD, 0xEEEEEEEE, 0xFFFFFFFF, 0x00000000,
     0x11111111, 0x22222222, 0x33333333, 0x44444444,
     0x55555555, 0x66666666, 0x77777777, 0x88888888,
     0x99999999, 0xAAAAAAAA, 0xBBBBBBBB, 0xCCCCCCCC,
     0xDDDDDDDD, 0xEEEEEEEE, 0xFFFFFFFF, 0x00000000,
     0x11111111, 0x22222222, 0x33333333, 0x44444444},
    {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
    {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
    {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
    {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
    {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
    {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
};

#define ROR(W,i) (((W) >> (i)) | ((W) << (32 - (i))))
#define ROL(W,i) (((W) << (i)) | ((W) >> (32 - (i))))

/* ── LEA-013 위반: T = K 초기화 패턴이 없음 (직접 mk를 참조) ── */
void lea_set_key(LEA_KEY *key, const unsigned char *mk, unsigned int mk_len)
{
    if (!key || !mk)
        return;

    const unsigned int *_mk = (const unsigned int *)mk;

    switch (mk_len) {
    case 16:
        key->rk[  0] = ROL(_mk[0] + delta[0][ 0], 1);
        key->rk[  6] = ROL(key->rk[  0] + delta[1][ 1], 1);
        key->rk[ 12] = ROL(key->rk[  6] + delta[2][ 2], 1);

        key->rk[  1] = key->rk[3] = key->rk[5] = ROL(_mk[1] + delta[0][1], 3);
        key->rk[  2] = ROL(_mk[2] + delta[0][2], 6);
        key->rk[  4] = ROL(_mk[3] + delta[0][3], 11);
        break;

    case 24:
        key->rk[  0] = ROL(_mk[0] + delta[0][ 0], 1);
        key->rk[  1] = ROL(_mk[1] + delta[0][ 1], 3);
        key->rk[  2] = ROL(_mk[2] + delta[0][ 2], 6);
        key->rk[  3] = ROL(_mk[3] + delta[0][ 3], 11);
        break;

    case 32:
        key->rk[  0] = ROL(_mk[0] + delta[0][ 0], 1);
        key->rk[  1] = ROL(_mk[1] + delta[0][ 1], 3);
        key->rk[  2] = ROL(_mk[2] + delta[0][ 2], 6);
        key->rk[  3] = ROL(_mk[3] + delta[0][ 3], 11);
        break;

    default:
        return;
    }
    key->round = (mk_len >> 1) + 16;
}

/* ── LEA-027 위반: ROL9→ROL8, LEA-028 위반: ROR5→ROR4, LEA-029 위반: ROR3→ROR2 ── */
void lea_encrypt(unsigned char *ct, const unsigned char *pt, const LEA_KEY *key)
{
    unsigned int X0, X1, X2, X3;
    const unsigned int *_pt = (const unsigned int *)pt;
    unsigned int *_ct = (unsigned int *)ct;

    X0 = _pt[0]; X1 = _pt[1]; X2 = _pt[2]; X3 = _pt[3];

    /* 원래: ROR3, ROR5, ROL9 → 변조: ROR2, ROR4, ROL8 */
    X3 = ROR((X2 ^ key->rk[  4]) + (X3 ^ key->rk[  5]), 2);   /* ROR3→ROR2 */
    X2 = ROR((X1 ^ key->rk[  2]) + (X2 ^ key->rk[  3]), 4);   /* ROR5→ROR4 */
    X1 = ROL((X0 ^ key->rk[  0]) + (X1 ^ key->rk[  1]), 8);   /* ROL9→ROL8 */
    X0 = ROR((X3 ^ key->rk[ 10]) + (X0 ^ key->rk[ 11]), 2);
    X3 = ROR((X2 ^ key->rk[  8]) + (X3 ^ key->rk[  9]), 4);
    X2 = ROL((X1 ^ key->rk[  6]) + (X2 ^ key->rk[  7]), 8);

    _ct[0] = X0; _ct[1] = X1; _ct[2] = X2; _ct[3] = X3;
}

void lea_decrypt(unsigned char *pt, const unsigned char *ct, const LEA_KEY *key)
{
    unsigned int X0, X1, X2, X3;
    unsigned int *_pt = (unsigned int *)pt;
    const unsigned int *_ct = (const unsigned int *)ct;

    X0 = _ct[0]; X1 = _ct[1]; X2 = _ct[2]; X3 = _ct[3];

    /* 복호화도 동일하게 변조 */
    X0 = (ROR(X0, 8) - (X3 ^ key->rk[  6])) ^ key->rk[  7];   /* ROL9→ROL8 기반 역연산 */
    X1 = (ROL(X1, 4) - (X0 ^ key->rk[  8])) ^ key->rk[  9];   /* ROR5→ROR4 기반 역연산 */
    X2 = (ROL(X2, 2) - (X1 ^ key->rk[ 10])) ^ key->rk[ 11];   /* ROR3→ROR2 기반 역연산 */

    _pt[0] = X0; _pt[1] = X1; _pt[2] = X2; _pt[3] = X3;
}

/* ── COM-001 위반: 함수 종료 시 키/상태 메모리를 제거하지 않음 ── */
void lea_run_no_cleanup(const unsigned char *key_bytes)
{
    LEA_KEY key;
    unsigned char pt[16] = {0};
    unsigned char ct[16] = {0};

    lea_set_key(&key, key_bytes, 16);
    lea_encrypt(ct, pt, &key);
    /* memset(&key, 0, sizeof(key)); ← 이 줄이 없으므로 COM-001 위반 */
}
"""

# ---------------------------------------------------------------------------
# 2) include/lea.h — 공개 API 헤더 (API 명칭 위반)
# ---------------------------------------------------------------------------
LEA_H = r"""
/*
 * LEA Public Header — 테스트용 변조
 *
 * [의도적 위반 목록]
 *   LEA-051 (missing): lea_set_key → lea_key_setup 으로 변경
 *   LEA-052 (missing): typedef LEA_KEY → LeaKeyCtx 로 변경
 *   LEA-053 (missing): return -N 음수 반환 코드 없음
 *   CBC-LEA-004 (missing): lea_cbc_enc/dec → cbc_encrypt/decrypt
 *   CTR-LEA-004 (missing): lea_ctr_enc/dec → ctr_encrypt/decrypt
 *   LEA-055 (missing): lea_t_(sse2|avx2|xop|neon) 참조 없음
 */

#ifndef _LEA_HEADER_
#define _LEA_HEADER_

/* LEA-052 위반: 원래 'LEA_KEY' 이어야 하지만 다른 이름 사용 */
typedef struct lea_key_ctx_st {
    unsigned int rk[192];
    unsigned int round;
} LeaKeyCtx;

/* 호환성을 위한 매크로는 일부러 넣지 않음 */
#define LEA_KEY LeaKeyCtx

/* LEA-051 위반: 원래 'lea_set_key' 이어야 함 */
void lea_key_setup(LeaKeyCtx *key, const unsigned char *mk, unsigned int mk_len);

void lea_encrypt(unsigned char *ct, const unsigned char *pt, const LeaKeyCtx *key);
void lea_decrypt(unsigned char *pt, const unsigned char *ct, const LeaKeyCtx *key);

/* LEA-051 위반: lea_set_key 심볼이 존재하지 않음 → 여기서 재선언 필요하지만 빠짐 */

/* CBC-LEA-004 위반: 원래 lea_cbc_enc / lea_cbc_dec 이어야 함 */
void cbc_encrypt(unsigned char *ct, const unsigned char *pt, unsigned int pt_len,
                 const unsigned char *iv, const LeaKeyCtx *key);
void cbc_decrypt(unsigned char *pt, const unsigned char *ct, unsigned int ct_len,
                 const unsigned char *iv, const LeaKeyCtx *key);

/* CTR-LEA-004 위반: 원래 lea_ctr_enc / lea_ctr_dec 이어야 함 */
void ctr_encrypt(unsigned char *ct, const unsigned char *pt, unsigned int pt_len,
                 unsigned char *ctr, const LeaKeyCtx *key);
void ctr_decrypt(unsigned char *pt, const unsigned char *ct, unsigned int ct_len,
                 unsigned char *ctr, const LeaKeyCtx *key);

void lea_ecb_enc(unsigned char *ct, const unsigned char *pt, unsigned int pt_len,
                 const LeaKeyCtx *key);
void lea_ecb_dec(unsigned char *pt, const unsigned char *ct, unsigned int ct_len,
                 const LeaKeyCtx *key);

/* LEA-053 위반: API 에러 반환 규약(return -1 등)이 없음
 *   모든 함수가 void 반환 → 에러 상태를 호출자에게 알릴 수 없음 */

/* LEA-055 위반: SIMD 가속 구현 파일 참조 없음
 *   lea_t_sse2, lea_t_avx2, lea_t_neon 등의 심볼이 없음 */

#endif
"""

# ---------------------------------------------------------------------------
# 3) src/lea_cbc.c — CBC 모드 (패딩 오라클, IV 크기 위반)
# ---------------------------------------------------------------------------
LEA_CBC_C = r"""
/*
 * LEA-CBC Mode — 테스트용 변조
 *
 * [의도적 위반 목록]
 *   CBC-005 (regex) : 패딩 오류 메시지 출력 → 패딩 오라클 공격 취약
 *   CBC-LEA-001 (regex): IV 버퍼 크기가 16이 아닌 32로 선언
 *   CBC-LEA-002 (regex): s_box 참조 존재
 */

#include "lea.h"
#include <stdio.h>
#include <string.h>

/* CBC-LEA-001 위반: IV 크기가 16바이트가 아닌 32바이트 */
static unsigned char default_iv[32] = {0};
void cbc_init_iv(void) {
    uint8_t iv[32];
    memset(iv, 0, 32);
}

/* CBC-LEA-002 위반: LEA에서는 S-box를 사용하지 않아야 함 */
static unsigned char s_box[16] = {0x0, 0x1, 0x2, 0x3};

void cbc_encrypt(unsigned char *ct, const unsigned char *pt, unsigned int pt_len,
                 const unsigned char *iv, const LEA_KEY *key)
{
    unsigned int blocks = pt_len >> 4;
    unsigned int i;

    if (!ct || !pt || !iv || !key)
        return;
    if ((pt_len == 0) || (pt_len & 0xf))
        return;

    for (i = 0; i < blocks; i++, pt += 16, ct += 16) {
        unsigned int j;
        for (j = 0; j < 16; j++)
            ct[j] = pt[j] ^ iv[j];
        lea_encrypt(ct, ct, key);
        iv = ct;
    }
}

/* CBC-005 위반: 패딩 오류를 상세하게 출력 → 패딩 오라클 공격에 취약 */
int cbc_decrypt_with_padding(unsigned char *pt, const unsigned char *ct,
                             unsigned int ct_len, const unsigned char *iv,
                             const LEA_KEY *key)
{
    unsigned int blocks = ct_len >> 4;
    unsigned int i;

    if (!pt || !ct || !iv || !key)
        return 0;

    for (i = 0; i < blocks; i++, pt += 16, ct += 16) {
        lea_decrypt(pt, ct, key);
    }

    unsigned char pad_val = pt[-1];
    if (pad_val == 0 || pad_val > 16) {
        printf("Padding error: invalid padding value %d\n", pad_val);
        fprintf(stderr, "Padding error detected in CBC decryption\n");
        return 0;
    }
    return 1;
}
"""

# ---------------------------------------------------------------------------
# 4) src/lea_ctr.c — CTR 모드 (카운터 크기 위반)
# ---------------------------------------------------------------------------
LEA_CTR_C = r"""
/*
 * LEA-CTR Mode — 테스트용 변조
 *
 * [의도적 위반 목록]
 *   CTR-LEA-001 (regex): 카운터 버퍼가 16바이트가 아닌 32바이트
 *   CTR-LEA-002 (regex): s_box 참조 존재
 */

#include "lea.h"
#include <string.h>

/* CTR-LEA-001 위반: 카운터 크기 32바이트 (16이어야 함) */
static void ctr128_inc(unsigned char *counter) {
    unsigned int n = 16;
    unsigned char c;
    do {
        --n;
        c = counter[n];
        ++c;
        counter[n] = c;
        if (c) return;
    } while (n);
}

/* CTR-LEA-002 위반: LEA에는 S-box가 없어야 함 */
static const unsigned char s_box[4] = {0x00, 0x01, 0x02, 0x03};

void ctr_encrypt(unsigned char *ct, const unsigned char *pt, unsigned int pt_len,
                 unsigned char *ctr, const LEA_KEY *key)
{
    /* CTR-LEA-001 위반: unsigned char ctr[32] — 16이 아닌 32 */
    unsigned char ctr_block[32];
    unsigned char block[16];
    unsigned int remain = pt_len >> 4;

    if (!ctr || !key)
        return;

    uint8_t ctr[32];

    while (remain >= 1) {
        lea_encrypt(block, ctr, key);
        unsigned int j;
        for (j = 0; j < 16; j++)
            ct[j] = block[j] ^ pt[j];
        ctr128_inc(ctr);
        remain--;
        pt += 16;
        ct += 16;
    }
}

void ctr_decrypt(unsigned char *pt, const unsigned char *ct, unsigned int ct_len,
                 unsigned char *ctr, const LEA_KEY *key)
{
    ctr_encrypt(pt, ct, ct_len, ctr, key);
}
"""

# ---------------------------------------------------------------------------
# 5) include/lea_locl.h — 내부 헤더 (정상 참조용, 위반 없음)
# ---------------------------------------------------------------------------
LEA_LOCL_H = r"""
/*
 * LEA Internal Header — 이 파일은 정상 참조용
 * uint32_t 사용 및 ROL/ROR 매크로 정의 확인을 위한 파일
 */

#ifndef _LEA_LOCL_H_
#define _LEA_LOCL_H_

#include "lea.h"

#define ROR(W,i) (((W) >> (i)) | ((W) << (32 - (i))))
#define ROL(W,i) (((W) << (i)) | ((W) >> (32 - (i))))

#define loadU32(v) (v)

void lea_encrypt(unsigned char *ct, const unsigned char *pt, const LEA_KEY *key);
void lea_decrypt(unsigned char *pt, const unsigned char *ct, const LEA_KEY *key);

#endif
"""

# ---------------------------------------------------------------------------
# 6) include/config.h — 설정 헤더 (최소 구성)
# ---------------------------------------------------------------------------
CONFIG_H = r"""
#ifndef _CONFIG_H_
#define _CONFIG_H_

#define IS_LITTLE_ENDIAN 1

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

#endif
"""

# ---------------------------------------------------------------------------
CONTENTS = {
    "src/lea_core.c":       LEA_CORE_C,
    "src/lea_cbc.c":        LEA_CBC_C,
    "src/lea_ctr.c":        LEA_CTR_C,
    "include/lea.h":        LEA_H,
    "include/lea_locl.h":   LEA_LOCL_H,
    "include/config.h":     CONFIG_H,
}

# ---------------------------------------------------------------------------
# 예상 위반 목록 (테스트 확인용)
# ---------------------------------------------------------------------------
EXPECTED_VIOLATIONS = {
    "src/lea_core.c": [
        "LEA-011 (missing) — delta 상수 0xc3efe9db 등 8개 규격값 없음",
        "LEA-012 (missing) — 766995 (√766965 유도 근거) 주석 없음",
        "LEA-013 (missing) — T = K 초기화 패턴 없음",
        "LEA-027 (missing) — ROL9 (<<9 >>23) 패턴 없음 → ROL8로 변조",
        "LEA-028 (missing) — ROR5 (>>5 <<27) 패턴 없음 → ROR4로 변조",
        "LEA-029 (missing) — ROR3 (>>3 <<29) 패턴 없음 → ROR2로 변조",
        "LEA-041 (regex)  — s_box 사용 감지됨",
        "LEA-054 (missing) — #include lea_locl.h 없음",
        "COM-001 (missing) — memset/explicit_bzero 등 메모리 제거 없음",
        "COM-003 (regex)  — 하드코딩된 키(0x... 8개 이상) 감지됨",
    ],
    "include/lea.h": [
        "LEA-051 (missing) — lea_set_key 심볼 없음 (lea_key_setup으로 변경됨)",
        "LEA-052 (missing) — typedef/struct LEA_KEY 직접 정의 없음",
        "LEA-053 (missing) — return -N 음수 반환 없음",
        "LEA-055 (missing) — lea_t_(sse2|avx2|xop|neon) 참조 없음",
        "CBC-LEA-004 (missing) — lea_cbc_(enc|dec) 심볼 없음",
        "CTR-LEA-004 (missing) — lea_ctr_(enc|dec) 심볼 없음",
    ],
    "src/lea_cbc.c": [
        "CBC-005 (regex)     — 패딩 오류 메시지 출력 (Padding error 문자열)",
        "CBC-LEA-001 (regex) — IV 버퍼 uint8_t iv[32] (16이 아님)",
        "CBC-LEA-002 (regex) — s_box 참조 존재",
    ],
    "src/lea_ctr.c": [
        "CTR-LEA-001 (regex) — uint8_t ctr[32] (16이 아님)",
        "CTR-LEA-002 (regex) — s_box 참조 존재",
    ],
    "include/lea_locl.h": [
        "(위반 없음 — 정상 참조 파일)",
    ],
    "include/config.h": [
        "(위반 없음 — 설정 헤더)",
    ],
}


def main() -> None:
    with zipfile.ZipFile(ZIP_PATH, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, data in CONTENTS.items():
            zf.writestr(path, data.lstrip("\n").encode("utf-8"))

    print(f"✅ 생성됨: {ZIP_PATH.resolve()}")
    print(f"   파일 수: {len(CONTENTS)}")
    print()

    total_violations = 0
    for fname, violations in EXPECTED_VIOLATIONS.items():
        real = [v for v in violations if not v.startswith("(")]
        total_violations += len(real)
        print(f"📄 {fname}")
        for v in violations:
            print(f"   • {v}")
        print()

    print(f"🔍 예상 위반 총 {total_violations}건")
    print("   (missing 유형과 regex 유형만 카운트; ast/semantic은 미포함)")


if __name__ == "__main__":
    main()
