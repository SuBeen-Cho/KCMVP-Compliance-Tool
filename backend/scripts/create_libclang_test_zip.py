#!/usr/bin/env python3
"""
libclang 개선점 검증용 테스트 ZIP 생성 스크립트
================================================

생성 파일: testdata/testdata_libclang.zip

포함된 케이스:
  CASE-1  lea_key_correct.c   — 표준 delta + typedef  → LEA-010 위반 없음 (정상)
  CASE-2  lea_key_wrong.c     — 비표준 delta 0xdeadbeef → LEA-010 위반 탐지
  CASE-3  lea_encrypt.c       — 포인터 연산 XOR+ADD    → LEA-031 FP 제거 검증
  CASE-4  lea_decrypt_bad.c   — 뺄셈 없는 복호화       → LEA-034 위반 탐지
  CASE-5  lea_clear.c         — memset 키 제로화        → COM-001 정상 탐지
  CASE-6  lea_cbc.c           — IV 재사용 CBC 패턴       → CBC-001 위반 탐지
  include/lea_types.h         — typedef uint32_t/uint8_t → type_aliases 수집 검증

Before vs After 비교 포인트:
  CASE-2: BEFORE(symbol_graph=None) → 0 violations (FN)
          AFTER (array_inits 활용)  → 1 violation (정확 탐지)
  CASE-3: BEFORE → 포인터 타입 식별 불가 (FP 가능)
          AFTER  → typedef 해소로 FP 자동 제거
  CASE-4: BEFORE → "pt:uint32_t" (typedef 미해소)
          AFTER  → "pt:unsigned int" (typedef 해소)

사용법:
  cd backend
  python scripts/create_libclang_test_zip.py
  → testdata/testdata_libclang.zip 생성
"""

import io
import sys
import zipfile
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
OUTPUT = BACKEND / "testdata" / "testdata_libclang.zip"


# ─── CASE-1: 표준 delta + typedef (LEA-010 정상 케이스) ──────────
LEA_KEY_CORRECT = """\
#include "lea_types.h"
#include <string.h>

/* KS X 3246 표준 delta 상수 (128비트 키용) */
static const uint32_t delta_128[4] = {
    0xc3efe9db, 0x44626b02, 0x79e27c8a, 0x78df30ec
};

/* 256비트 키용 delta 상수 */
static const uint32_t delta_256[8] = {
    0xc3efe9db, 0x44626b02, 0x79e27c8a, 0x78df30ec,
    0x715ea49e, 0xc785da0a, 0xe04ef22a, 0xe5c40957
};

static uint32_t ROL32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

/* 표준 키 스케줄: ARX 구조 + 표준 delta 사용 */
void lea_set_key(uint32_t RK[32][6], const uint8_t *mk, int mk_len) {
    uint32_t T[4];
    int i;

    T[0] = ((uint32_t)mk[0]  << 24) | ((uint32_t)mk[1]  << 16)
         | ((uint32_t)mk[2]  <<  8) |  (uint32_t)mk[3];
    T[1] = ((uint32_t)mk[4]  << 24) | ((uint32_t)mk[5]  << 16)
         | ((uint32_t)mk[6]  <<  8) |  (uint32_t)mk[7];
    T[2] = ((uint32_t)mk[8]  << 24) | ((uint32_t)mk[9]  << 16)
         | ((uint32_t)mk[10] <<  8) |  (uint32_t)mk[11];
    T[3] = ((uint32_t)mk[12] << 24) | ((uint32_t)mk[13] << 16)
         | ((uint32_t)mk[14] <<  8) |  (uint32_t)mk[15];

    for (i = 0; i < 32; i++) {
        T[0] = ROL32(T[0] + ROL32(delta_128[i % 4], i), 1);
        T[1] = ROL32(T[1] + ROL32(delta_128[(i+1) % 4], i), 3);
        T[2] = ROL32(T[2] + ROL32(delta_128[(i+2) % 4], i), 6);
        T[3] = ROL32(T[3] + ROL32(delta_128[(i+3) % 4], i), 11);

        RK[i][0] = T[0];
        RK[i][1] = T[1];
        RK[i][2] = T[2];
        RK[i][3] = T[1];
        RK[i][4] = T[3];
        RK[i][5] = T[1];
    }
}
"""

# ─── CASE-2: 비표준 delta (LEA-010 위반 케이스) ──────────────────
LEA_KEY_WRONG = """\
#include "lea_types.h"
#include <string.h>

/*
 * 경고: 이 파일은 의도적으로 비표준 delta 상수를 사용합니다.
 * Before/After 비교 테스트용 — LEA-010 위반이 탐지되어야 함.
 */

/* 비표준 delta — KS X 3246 표준값 아님 */
static const uint32_t delta_128[4] = {
    0xdeadbeef, 0xcafebabe, 0x12345678, 0xabcdef01
};

static uint32_t ROL32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

void lea_set_key_bad(uint32_t RK[32][6], const uint8_t *mk, int mk_len) {
    uint32_t T[4];
    int i;

    T[0] = ((uint32_t)mk[0] << 24) | ((uint32_t)mk[1] << 16)
         | ((uint32_t)mk[2] <<  8) |  (uint32_t)mk[3];
    T[1] = ((uint32_t)mk[4] << 24) | ((uint32_t)mk[5] << 16)
         | ((uint32_t)mk[6] <<  8) |  (uint32_t)mk[7];
    T[2] = ((uint32_t)mk[8] << 24) | ((uint32_t)mk[9] << 16)
         | ((uint32_t)mk[10]<<  8) |  (uint32_t)mk[11];
    T[3] = ((uint32_t)mk[12]<< 24) | ((uint32_t)mk[13]<< 16)
         | ((uint32_t)mk[14]<<  8) |  (uint32_t)mk[15];

    for (i = 0; i < 32; i++) {
        T[0] = ROL32(T[0] + ROL32(delta_128[i % 4], i), 1);
        T[1] = ROL32(T[1] + ROL32(delta_128[(i+1) % 4], i), 3);
        RK[i][0] = T[0];
        RK[i][1] = T[1];
    }
}
"""

# ─── CASE-3: 포인터 연산 (LEA-031 FP 케이스) ─────────────────────
LEA_ENCRYPT = """\
#include "lea_types.h"

/*
 * 포인터 기반 바이트 연산 — LEA-031 FP 검증용
 *
 * unsigned char* 타입의 포인터 연산에서 XOR+ADD 패턴이 나타나지만
 * 이것은 정수 LEA 연산이 아닌 바이트 레벨 포인터 연산이다.
 * AFTER: type_aliases로 포인터 타입 식별 → FP 자동 제거
 * BEFORE: 포인터 타입 정보 없음 → FP 발생 가능
 */
void lea_xor_block_ptr(uint8_t *dst, const uint8_t *src, const uint8_t *key,
                       int len) {
    int i;
    for (i = 0; i < len; i++) {
        /* 포인터 바이트 연산: dst = src XOR (key + offset) */
        dst[i] = src[i] ^ (key[i] + (uint8_t)i);
    }
}

/*
 * 올바른 LEA 암호화 — XOR→ADD 순서 정확
 */
void lea_encrypt(uint32_t *ct, const uint32_t *pt,
                 const uint32_t RK[32][6]) {
    uint32_t x0 = pt[0], x1 = pt[1], x2 = pt[2], x3 = pt[3];
    int i;

    for (i = 0; i < 32; i++) {
        uint32_t t0, t1, t2, t3;
        /* 올바른 순서: XOR 먼저, 그 다음 ADD */
        t0 = ((x0 ^ RK[i][0]) + (x1 ^ RK[i][1])) ;
        t1 = ((x1 ^ RK[i][2]) + (x2 ^ RK[i][3])) ;
        t2 = ((x2 ^ RK[i][4]) + (x3 ^ RK[i][5])) ;
        t3 = x0;
        x0 = t0; x1 = t1; x2 = t2; x3 = t3;
    }

    ct[0] = x0; ct[1] = x1; ct[2] = x2; ct[3] = x3;
}
"""

# ─── CASE-4: 뺄셈 없는 복호화 (LEA-034 위반 케이스) ─────────────
LEA_DECRYPT_BAD = """\
#include "lea_types.h"

/*
 * 의도적으로 잘못된 복호화 — LEA-034 위반 검증용
 *
 * 올바른 LEA 역연산에는 모듈러 뺄셈(-)이 있어야 하지만
 * 이 구현에서는 뺄셈 대신 덧셈을 사용하고 있음.
 *
 * BEFORE 메시지: "파라미터 타입: pt:uint32_t, ct:uint32_t"
 * AFTER  메시지: "파라미터 타입: pt:unsigned int, ct:unsigned int"
 *                (type_aliases로 typedef 해소됨)
 */
void lea_decrypt(uint32_t *pt, const uint32_t *ct,
                 const uint32_t RK[32][6]) {
    uint32_t x0 = ct[0], x1 = ct[1], x2 = ct[2], x3 = ct[3];
    int i;

    for (i = 31; i >= 0; i--) {
        uint32_t t0, t1, t2, t3;
        /*
         * 잘못된 역연산: 뺄셈(-) 없이 XOR만 사용
         * 올바른 구현은: t = (x ^ RK) - y 형태여야 함
         */
        t3 = x0;
        t0 = (x0 ^ RK[i][1]) + x1;   /* 뺄셈 없음 — 오류 */
        t1 = (x1 ^ RK[i][3]) + x2;   /* 뺄셈 없음 — 오류 */
        t2 = (x2 ^ RK[i][5]) + x3;   /* 뺄셈 없음 — 오류 */
        x0 = t0; x1 = t1; x2 = t2; x3 = t3;
    }

    pt[0] = x0; pt[1] = x1; pt[2] = x2; pt[3] = x3;
}
"""

# ─── CASE-5: memset 제로화 (COM-001 탐지 케이스) ─────────────────
LEA_CLEAR = """\
#include "lea_types.h"
#include <string.h>

/*
 * 올바른 키 제로화 — COM-001 정상 케이스
 *
 * memset()으로 라운드키 배열을 0으로 초기화.
 * libclang: memset을 정확한 심볼로 탐지
 * pycparser 환경(fake_libc): __builtin___memset_chk 확장 → 수정된 버그로 탐지됨
 */
void lea_clear_key(uint32_t RK[32][6]) {
    memset(RK, 0, sizeof(uint32_t) * 32 * 6);
}

void lea_secure_cleanup(uint32_t *RK, uint8_t *key_buf, int key_len) {
    /* 라운드키 제로화 */
    memset(RK, 0, sizeof(uint32_t) * 32 * 6);
    /* 원본 키 버퍼 제로화 */
    memset(key_buf, 0, (size_t)key_len);
}
"""

# ─── CASE-6: IV 재사용 CBC (CBC-001 위반 케이스) ──────────────────
LEA_CBC = """\
#include "lea_types.h"
#include <string.h>

/*
 * CBC 모드 암호화 — IV 재사용 위반 케이스
 *
 * CBC-001: IV는 매 암호화마다 새로 생성해야 하지만
 * 이 구현에서는 고정 IV를 전역변수로 재사용함.
 */

/* 위반: 고정 IV — 매 암호화마다 동일한 값 사용 */
static const uint8_t fixed_iv[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

static void xor_block(uint8_t *dst, const uint8_t *a, const uint8_t *b) {
    int i;
    for (i = 0; i < 16; i++) dst[i] = a[i] ^ b[i];
}

extern void lea_encrypt(uint32_t *ct, const uint32_t *pt,
                        const uint32_t RK[32][6]);

/*
 * CBC 암호화 — IV 재사용 문제 있음
 * 올바른 구현: iv 파라미터를 매번 새로운 난수로 받아야 함
 */
void lea_cbc_enc(uint8_t *ct, const uint8_t *pt, int pt_len,
                 const uint32_t RK[32][6]) {
    uint8_t prev[16];
    int i;

    /* fixed_iv 재사용 — CBC-001 위반 */
    memcpy(prev, fixed_iv, 16);

    for (i = 0; i < pt_len; i += 16) {
        uint8_t block[16];
        xor_block(block, pt + i, prev);
        lea_encrypt((uint32_t *)ct + i/4,
                    (const uint32_t *)block, RK);
        memcpy(prev, ct + i, 16);
    }
}

/*
 * CBC 복호화 — 동일하게 fixed_iv 재사용
 */
void lea_cbc_dec(uint8_t *pt, const uint8_t *ct, int ct_len,
                 const uint32_t RK[32][6]) {
    uint8_t prev[16];
    int i;

    /* fixed_iv 재사용 — CBC-001 위반 */
    memcpy(prev, fixed_iv, 16);

    for (i = 0; i < ct_len; i += 16) {
        uint8_t block[16];
        lea_encrypt((uint32_t *)block,
                    (const uint32_t *)(ct + i), RK);
        xor_block(pt + i, block, prev);
        memcpy(prev, ct + i, 16);
    }
}
"""

# ─── include/lea_types.h: typedef 명시 (type_aliases 수집용) ─────
LEA_TYPES_H = """\
#ifndef LEA_TYPES_H
#define LEA_TYPES_H

/*
 * LEA 암호모듈 타입 정의
 *
 * typedef 선언 — libclang의 type_aliases 수집 검증용:
 *   uint32_t → unsigned int
 *   uint8_t  → unsigned char
 *   uint64_t → unsigned long long
 *
 * Before(pycparser): type_aliases = {} (빈 딕셔너리)
 * After (libclang):  type_aliases = {
 *                      "uint32_t": "unsigned int",
 *                      "uint8_t":  "unsigned char",
 *                      "uint64_t": "unsigned long long"
 *                    }
 */

typedef unsigned int       uint32_t;
typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned long long uint64_t;

/* LEA 블록/키 크기 상수 */
#define LEA_BLOCK_SIZE  16   /* 바이트 */
#define LEA_KEY_128     16
#define LEA_KEY_192     24
#define LEA_KEY_256     32
#define LEA_ROUNDS      32

#endif /* LEA_TYPES_H */
"""

# ─── Makefile (심볼 그래프 크로스 파일 호출 확인용) ──────────────
MAKEFILE = """\
# LEA 암호모듈 빌드 설정
# libclang 크로스 파일 call_graph 검증용

CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -Iinclude
SRCS    = src/lea_key_correct.c src/lea_encrypt.c \\
          src/lea_decrypt_bad.c src/lea_clear.c   \\
          src/lea_cbc.c
OBJS    = $(SRCS:.c=.o)
TARGET  = lea_module

all: $(TARGET)

$(TARGET): $(OBJS)
\t$(CC) -o $@ $^

%.o: %.c
\t$(CC) $(CFLAGS) -c $< -o $@

clean:
\trm -f $(OBJS) $(TARGET)
"""

# ─── README (테스트 목적 설명) ───────────────────────────────────
README = """\
# libclang Before/After 검증용 테스트 코드

이 ZIP은 libclang 심볼 그래프 개선점을 검증하기 위한 최소한의 LEA 구현체입니다.

## 파일별 테스트 목적

| 파일 | 관련 규칙 | 기대 결과 |
|------|-----------|-----------|
| src/lea_key_correct.c | LEA-010 | 표준 delta → 위반 없음 |
| src/lea_key_wrong.c   | LEA-010 | 비표준 delta → 위반 탐지 (AFTER만) |
| src/lea_encrypt.c     | LEA-031 | 포인터 FP → AFTER에서 제거 |
| src/lea_decrypt_bad.c | LEA-034 | 뺄셈 없음 → 위반, 메시지에 실제 타입명 |
| src/lea_clear.c       | COM-001 | memset 제로화 → 정상 탐지 |
| src/lea_cbc.c         | CBC-001 | IV 재사용 → 위반 탐지 |
| include/lea_types.h   | (공통)  | typedef 명시 → type_aliases 수집 검증 |

## Before vs After 핵심 차이

1. **LEA-010**: BEFORE=0 violations (FN), AFTER=1 violation (array_inits 활용)
2. **LEA-031**: BEFORE=포인터 타입 불명, AFTER=FP 제거 (type_aliases 활용)
3. **LEA-034**: BEFORE="pt:uint32_t", AFTER="pt:unsigned int" (typedef 해소)
"""


def main() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("src/lea_key_correct.c", LEA_KEY_CORRECT)
        zf.writestr("src/lea_key_wrong.c",   LEA_KEY_WRONG)
        zf.writestr("src/lea_encrypt.c",     LEA_ENCRYPT)
        zf.writestr("src/lea_decrypt_bad.c", LEA_DECRYPT_BAD)
        zf.writestr("src/lea_clear.c",       LEA_CLEAR)
        zf.writestr("src/lea_cbc.c",         LEA_CBC)
        zf.writestr("include/lea_types.h",   LEA_TYPES_H)
        zf.writestr("Makefile",              MAKEFILE)
        zf.writestr("README.md",             README)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_bytes(buf.getvalue())

    print(f"생성 완료: {OUTPUT}")
    print(f"  크기: {OUTPUT.stat().st_size:,} bytes")
    print()
    print("포함된 파일:")
    with zipfile.ZipFile(OUTPUT) as zf:
        for info in zf.infolist():
            print(f"  {info.filename:<35}  {info.file_size:>6,} B")
    print()
    print("사용법:")
    print("  python scripts/test_libclang_before_after.py")


if __name__ == "__main__":
    main()
