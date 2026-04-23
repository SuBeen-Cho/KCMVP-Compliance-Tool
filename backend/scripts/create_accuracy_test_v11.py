"""
accuracy_test_v11.zip 생성

v10(88 cases) + 8 new cases:
  LEA-003 (2P + 2N):
    P45 violations_lea003_wrong.c   LEA-003  키 스케줄에서 라운드 수 20 사용
    P46 violations_lea003_rounds.c  LEA-003  라운드 수 16 사용 (잘못된 값)
    N45 safe_lea003_24.c            LEA-003  128비트 → 24라운드 정상
    N46 safe_lea003_macro.c         LEA-003  매크로 상수 사용 → 판단 불가(safe)

  COM-001 (2P + 2N):
    P47 violations_com001_loop.c    COM-001  memset 사용 + 제로화 누락 (loop 없음)
    P48 violations_com001_plain.c   COM-001  key 변수에 memset만 사용 (unsafe)
    N47 safe_com001_loop.c          COM-001  for(i=0;i<N;i++) key[i]=0; 제로화 루프
    N48 safe_com001_memsets.c       COM-001  memset_s로 안전 제로화
"""
import zipfile
from pathlib import Path

BACKEND_ROOT = Path(__file__).parent.parent
OUT_PATH = BACKEND_ROOT / "testdata" / "accuracy_test_v11.zip"
V10_ZIP  = BACKEND_ROOT / "testdata" / "accuracy_test_v10.zip"

# ── P45: 키 스케줄에서 라운드 수 20 사용 ─────────────────────────────
VIOLATIONS_LEA003_WRONG = """\
/* P45: LEA-003 — 키 스케줄 라운드 수 20 (올바른 값: 24/28/32) */
#include <stdint.h>

#define BLOCK_WORDS 4

void lea_key_schedule(uint32_t *key, uint32_t *rk) {
    int i;
    /* VIOLATION: 128비트 키에 24 라운드가 맞으나 20으로 잘못 설정 */
    for (i = 0; i < 20; i++) {
        rk[i * 6 + 0] = key[0] + i;
        rk[i * 6 + 1] = key[1] ^ i;
        rk[i * 6 + 2] = key[2] + i;
        rk[i * 6 + 3] = key[3] ^ i;
    }
}
"""

# ── P46: 라운드 수 16 사용 ────────────────────────────────────────────
VIOLATIONS_LEA003_ROUNDS = """\
/* P46: LEA-003 — key_setup에서 라운드 16 (유효 값: 24/28/32) */
#include <stdint.h>

void key_setup(uint8_t *key, int keylen, uint32_t *rk) {
    int i;
    /* VIOLATION: 어떤 키 길이도 16 라운드를 쓰지 않음 */
    for (i = 0; i < 16; i++) {
        rk[i] = ((uint32_t)key[i % keylen]) << (i & 7);
    }
}
"""

# ── N45: 128비트 → 24 라운드 정상 ───────────────────────────────────
SAFE_LEA003_24 = """\
/* N45: LEA-003 — lea_key_schedule: 128비트 키에 24 라운드 (정상) */
#include <stdint.h>

#define LEA_ROUNDS_128 24

void lea_key_schedule_128(uint32_t *key, uint32_t *rk) {
    int i;
    for (i = 0; i < 24; i++) {  /* CORRECT: 128비트 → 24 라운드 */
        rk[i * 6 + 0] = key[0] ^ (i * 0x9e3779b9);
        rk[i * 6 + 1] = key[1] ^ (i * 0x9e3779b9);
    }
}
"""

# ── N46: 매크로 상수 사용 → checker 판단 불가 → 정상 처리 ─────────────
SAFE_LEA003_MACRO = """\
/* N46: LEA-003 — 매크로 상수 LEA_ROUNDS 사용 → checker는 safe(판단불가) 처리 */
#include <stdint.h>

/* 실제로는 컴파일 시점에 24/28/32로 확장됨 */
#ifndef LEA_ROUNDS
#define LEA_ROUNDS 24
#endif

void lea_key_expand(uint32_t *key, uint32_t *rk) {
    int i;
    for (i = 0; i < LEA_ROUNDS; i++) {  /* 매크로 상수 사용 → 정상 */
        rk[i] = key[i % 4] ^ (i * 0x9e3779b9u);
    }
}
"""

# ── P47: memset 사용하지만 안전 제로화 없음 ─────────────────────────────
VIOLATIONS_COM001_LOOP = """\
/* P47: COM-001 — 암호화 후 rk 제로화 없음 (memset만 있고 안전 제로화 누락) */
#include <stdint.h>
#include <string.h>

void lea_encrypt(uint8_t *key, uint8_t *pt, uint8_t *ct) {
    uint32_t rk[192];  /* 라운드키 — 사용 후 제로화 필요 */
    int i;
    /* 키 스케줄 */
    for (i = 0; i < 24; i++) rk[i] = ((uint32_t*)key)[i % 4] ^ i;
    /* 암호화 수행 */
    memset(ct, 0, 16);
    /* VIOLATION: rk 배열 사용 후 안전 제로화(memset_s/explicit_bzero) 없음 */
}
"""

# ── P48: 일반 memset으로만 key 제거 시도 ─────────────────────────────
VIOLATIONS_COM001_PLAIN = """\
/* P48: COM-001 — 일반 memset으로 key 제거 (컴파일러 최적화에 의해 제거될 수 있음) */
#include <stdint.h>
#include <string.h>

void process_key(uint8_t *key, int keylen) {
    uint8_t session_key[32];
    memcpy(session_key, key, keylen);
    /* ... 키 사용 ... */
    memset(session_key, 0, sizeof(session_key));  /* VIOLATION: 최적화로 제거 가능 */
}
"""

# ── N47: 직접 제로화 루프 사용 → 정상 ──────────────────────────────────
SAFE_COM001_LOOP = """\
/* N47: COM-001 — for 루프로 key 직접 제로화 (정상) */
#include <stdint.h>
#include <string.h>

void lea_encrypt_safe(uint8_t *key, uint8_t *pt, uint8_t *ct) {
    uint32_t rk[192];
    int i;
    for (i = 0; i < 24; i++) rk[i] = ((uint32_t*)key)[i % 4] ^ i;
    memset(ct, 0, 16);
    /* CORRECT: 명시적 제로화 루프 */
    for (i = 0; i < 192; i++) rk[i] = 0;
}
"""

# ── N48: memset_s로 안전 제로화 ─────────────────────────────────────
SAFE_COM001_MEMSETS = """\
/* N48: COM-001 — memset_s로 안전 제로화 (정상) */
#include <stdint.h>
#include <string.h>

void lea_decrypt_safe(uint8_t *key, uint8_t *ct, uint8_t *pt) {
    uint32_t rk[192];
    int i;
    for (i = 0; i < 24; i++) rk[i] = ((uint32_t*)key)[i % 4] ^ i;
    /* 복호화 수행 */
    pt[0] ^= ct[0];
    /* CORRECT: memset_s로 안전 제로화 */
    memset_s(rk, sizeof(rk), 0, sizeof(rk));
}
"""

NEW_GT_LINES = """\
violations_lea003_wrong.c | P | LEA-003 | 키 스케줄 라운드 수 20 (잘못된 값)
violations_lea003_rounds.c | P | LEA-003 | key_setup 라운드 수 16 (잘못된 값)
safe_lea003_24.c | N | LEA-003 | 128비트 → 24 라운드 정상
safe_lea003_macro.c | N | LEA-003 | 매크로 상수 사용 → 판단 불가(safe)
violations_com001_loop.c | P | COM-001 | memset 있지만 안전 제로화 누락
violations_com001_plain.c | P | COM-001 | 일반 memset으로 key 제거 (unsafe)
safe_com001_loop.c | N | COM-001 | for 루프 직접 제로화 정상
safe_com001_memsets.c | N | COM-001 | memset_s 안전 제로화 정상
"""


def build_zip():
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    v10_entries: dict[str, bytes] = {}
    with zipfile.ZipFile(V10_ZIP) as zf:
        for name in zf.namelist():
            v10_entries[name] = zf.read(name)

    old_gt = v10_entries.get("GROUND_TRUTH.md", b"").decode("utf-8")
    new_gt = old_gt.rstrip("\n") + "\n" + NEW_GT_LINES

    new_files = {
        "src/violations_lea003_wrong.c":  VIOLATIONS_LEA003_WRONG,
        "src/violations_lea003_rounds.c": VIOLATIONS_LEA003_ROUNDS,
        "src/safe_lea003_24.c":           SAFE_LEA003_24,
        "src/safe_lea003_macro.c":        SAFE_LEA003_MACRO,
        "src/violations_com001_loop.c":   VIOLATIONS_COM001_LOOP,
        "src/violations_com001_plain.c":  VIOLATIONS_COM001_PLAIN,
        "src/safe_com001_loop.c":         SAFE_COM001_LOOP,
        "src/safe_com001_memsets.c":      SAFE_COM001_MEMSETS,
    }

    with zipfile.ZipFile(OUT_PATH, "w", zipfile.ZIP_DEFLATED) as zout:
        for name, data in v10_entries.items():
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
