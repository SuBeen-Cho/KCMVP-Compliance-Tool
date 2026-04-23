"""
accuracy_test_v6.zip 생성 스크립트

v5(54 cases) + 8 new AST structural cases:
  P32 violations_gcm_nonce.c   GCM-001  static nonce → nonce 재사용 위반
  P33 violations_ccm_nonce.c   CCM-001  static nonce → nonce 재사용 위반
  P34 violations_lea_timing.c  LEA-042  데이터 의존 조건 분기(key[i]!=0)
  P35 violations_lea_mct.c     LEA-046  MCT 이중 루프 10×100 (100×1000 아님)
  N24 safe_gcm_v6.c            GCM-001  fresh non-static nonce → 정상
  N25 safe_ccm_v6.c            CCM-001  fresh non-static nonce → 정상
  N26 safe_lea_timing_v6.c     LEA-042  상수 시간 비교 (no key branch) → 정상
  N27 safe_lea_mct_v6.c        LEA-046  MCT 이중 루프 100×1000 → 정상
"""

import io
import zipfile
from pathlib import Path

BACKEND_ROOT = Path(__file__).parent.parent
OUT_PATH = BACKEND_ROOT / "testdata" / "accuracy_test_v6.zip"

# ── 위반 파일들 ────────────────────────────────────────────────────

VIOLATIONS_GCM_NONCE = """\
/* P32: GCM-001 — static nonce 재사용 위반 */
#include <string.h>

typedef struct { unsigned char *key; int keylen; } GCMCtx;

/* static 선언된 nonce → 함수 재호출 시 덮어쓰이므로 재사용 발생 */
void gcm_init(GCMCtx *ctx, unsigned char *pt, unsigned int ptlen) {
    static unsigned char nonce[12];   /* VIOLATION: static nonce */
    unsigned char ciphertext[256];
    memcpy(ciphertext, pt, ptlen);
    (void)ctx;
    (void)nonce;
}
"""

VIOLATIONS_CCM_NONCE = """\
/* P33: CCM-001 — static nonce 재사용 위반 */
#include <string.h>

typedef struct { unsigned char *key; int keylen; } CCMCtx;

/* static 선언된 nonce → CTR 키스트림 반복으로 기밀성 파괴 */
void ccm_init(CCMCtx *ctx, unsigned char *pt, unsigned int ptlen) {
    static unsigned char nonce[8];   /* VIOLATION: static nonce */
    unsigned char ciphertext[256];
    memcpy(ciphertext, pt, ptlen);
    (void)ctx;
    (void)nonce;
}
"""

VIOLATIONS_LEA_TIMING = """\
/* P34: LEA-042 — 데이터 의존 조건 분기 (타이밍 공격 취약) */
#include <stdint.h>
#include <string.h>

#define LEA_KEYLEN 16

void lea_encrypt(uint32_t *ct, const uint32_t *pt, const uint8_t *key) {
    int i;
    /* VIOLATION: key[i] 값에 따라 분기 → 타이밍 정보 누출 */
    for (i = 0; i < LEA_KEYLEN; i++) {
        if (key[i] != 0) {     /* data-dependent branch on key material */
            ct[0] ^= key[i];
        }
    }
    ct[1] = pt[0] + ct[0];
    ct[2] = pt[1] ^ ct[1];
    ct[3] = pt[2] + ct[2];
}
"""

VIOLATIONS_LEA_MCT = """\
/* P35: LEA-046 — MCT 이중 루프가 10x100 (100x1000 이어야 함) */
#include <stdint.h>
#include <string.h>

#define BLOCK_LEN 16

void lea_mct(uint8_t *key, uint8_t *pt, uint8_t *ct) {
    int i, j;
    uint8_t tmp[BLOCK_LEN];
    /* VIOLATION: 외부 루프 10, 내부 루프 100 → 100×1000 이어야 함 */
    for (i = 0; i < 10; i++) {           /* should be i < 100 */
        for (j = 0; j < 100; j++) {      /* should be j < 1000 */
            memcpy(tmp, pt, BLOCK_LEN);
            memcpy(ct, tmp, BLOCK_LEN);
        }
        /* key update after outer loop */
        key[0] ^= ct[0];
    }
}
"""

# ── 정상 파일들 ────────────────────────────────────────────────────

SAFE_GCM_V6 = """\
/* N24: GCM-001 — 매번 fresh nonce 생성 (static 아님) → 정상 */
#include <string.h>

typedef struct { unsigned char *key; int keylen; } GCMCtx;

/* stack 할당 nonce + getrandom → 재사용 없음 */
void gcm_init(GCMCtx *ctx, unsigned char *pt, unsigned int ptlen) {
    unsigned char nonce[12];   /* stack: no reuse */
    unsigned char ciphertext[256];
    /* getrandom(nonce, 12, 0); */   /* fresh random nonce each call */
    memcpy(ciphertext, pt, ptlen);
    (void)ctx;
    (void)nonce;
}
"""

SAFE_CCM_V6 = """\
/* N25: CCM-001 — 매번 fresh nonce 생성 → 정상 */
#include <string.h>

typedef struct { unsigned char *key; int keylen; } CCMCtx;

void ccm_init(CCMCtx *ctx, unsigned char *pt, unsigned int ptlen) {
    unsigned char nonce[8];    /* stack: no reuse */
    unsigned char ciphertext[256];
    /* getrandom(nonce, 8, 0); */    /* fresh random nonce each call */
    memcpy(ciphertext, pt, ptlen);
    (void)ctx;
    (void)nonce;
}
"""

SAFE_LEA_TIMING_V6 = """\
/* N26: LEA-042 — 상수 시간 비교 (조건 분기 없음) → 정상 */
#include <stdint.h>
#include <string.h>

#define LEA_KEYLEN 16

/* Constant-time: 분기 없이 XOR 연산만 사용 */
void lea_encrypt(uint32_t *ct, const uint32_t *pt, const uint8_t *key) {
    int i;
    uint32_t mask = 0;
    /* no data-dependent branch on key — constant time */
    for (i = 0; i < LEA_KEYLEN; i++) {
        mask ^= key[i];   /* XOR only, no conditional branch */
    }
    ct[0] = pt[0] ^ mask;
    ct[1] = pt[1] + ct[0];
    ct[2] = pt[2] ^ ct[1];
    ct[3] = pt[3] + ct[2];
}
"""

SAFE_LEA_MCT_V6 = """\
/* N27: LEA-046 — MCT 이중 루프 100×1000 → 정상 */
#include <stdint.h>
#include <string.h>

#define BLOCK_LEN 16

void lea_mct(uint8_t *key, uint8_t *pt, uint8_t *ct) {
    int i, j;
    uint8_t tmp[BLOCK_LEN];
    /* CORRECT: 외부 100, 내부 1000 */
    for (i = 0; i < 100; i++) {          /* correct outer bound */
        for (j = 0; j < 1000; j++) {     /* correct inner bound */
            memcpy(tmp, pt, BLOCK_LEN);
            memcpy(ct, tmp, BLOCK_LEN);
        }
        /* key update: Key ^= CT[999] (128-bit) */
        key[0] ^= ct[0];
    }
}
"""

# ── 기존 v5 GROUND_TRUTH.md 불러오기 ─────────────────────────────

V5_ZIP = BACKEND_ROOT / "testdata" / "accuracy_test_v5.zip"

NEW_GT_LINES = """\
violations_gcm_nonce.c | P | GCM-001 | static nonce → GCM nonce 재사용 위반
violations_ccm_nonce.c | P | CCM-001 | static nonce → CCM nonce 재사용 위반
violations_lea_timing.c | P | LEA-042 | key[i]!=0 조건 분기 → 타이밍 공격 취약
violations_lea_mct.c | P | LEA-046 | MCT 루프 10x100 → 100x1000 이어야 함
safe_gcm_v6.c | N | GCM-001 | stack nonce → 재사용 없음
safe_ccm_v6.c | N | CCM-001 | stack nonce → 재사용 없음
safe_lea_timing_v6.c | N | LEA-042 | XOR only → 상수 시간 연산
safe_lea_mct_v6.c | N | LEA-046 | 100x1000 루프 → 정상 MCT 구조
"""

# ── ZIP 생성 ──────────────────────────────────────────────────────

def build_zip():
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    # v5에서 src/ 파일 + GROUND_TRUTH.md 복사
    v5_entries: dict[str, bytes] = {}
    with zipfile.ZipFile(V5_ZIP) as zf:
        for name in zf.namelist():
            v5_entries[name] = zf.read(name)

    # 기존 GROUND_TRUTH.md 에 새 케이스 추가
    old_gt = v5_entries.get("GROUND_TRUTH.md", b"").decode("utf-8")
    new_gt = old_gt.rstrip("\n") + "\n" + NEW_GT_LINES

    new_files = {
        "src/violations_gcm_nonce.c":   VIOLATIONS_GCM_NONCE,
        "src/violations_ccm_nonce.c":   VIOLATIONS_CCM_NONCE,
        "src/violations_lea_timing.c":  VIOLATIONS_LEA_TIMING,
        "src/violations_lea_mct.c":     VIOLATIONS_LEA_MCT,
        "src/safe_gcm_v6.c":            SAFE_GCM_V6,
        "src/safe_ccm_v6.c":            SAFE_CCM_V6,
        "src/safe_lea_timing_v6.c":     SAFE_LEA_TIMING_V6,
        "src/safe_lea_mct_v6.c":        SAFE_LEA_MCT_V6,
    }

    with zipfile.ZipFile(OUT_PATH, "w", zipfile.ZIP_DEFLATED) as zout:
        for name, data in v5_entries.items():
            if name == "GROUND_TRUTH.md":
                zout.writestr("GROUND_TRUTH.md", new_gt)
            else:
                zout.writestr(name, data)
        for name, content in new_files.items():
            zout.writestr(name, content)

    print(f"Created: {OUT_PATH}")

    # Ground truth 요약 출력
    p = sum(1 for l in new_gt.splitlines() if "| P |" in l)
    n = sum(1 for l in new_gt.splitlines() if "| N |" in l)
    print(f"Ground Truth: P={p}, N={n}, total={p+n}")


if __name__ == "__main__":
    build_zip()
