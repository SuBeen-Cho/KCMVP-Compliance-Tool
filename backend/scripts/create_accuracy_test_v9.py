"""
accuracy_test_v9.zip 생성

v8(78 cases) + 4 new LEA-057 cases:
  P41 violations_lea057_nokey.c  LEA-057  MCT 외부 루프에서 키 XOR 갱신 없음
  P42 violations_lea057_inner.c  LEA-057  키 갱신이 외부 루프에 없고 내부에만 있음 (잘못된 위치)
  N39 safe_lea057_xor.c          LEA-057  key[k] ^= ct[k] 갱신 있음 → 정상
  N40 safe_lea057_assign.c       LEA-057  key[k] = key[k] ^ ct[k] 갱신 있음 → 정상
"""
import zipfile
from pathlib import Path

BACKEND_ROOT = Path(__file__).parent.parent
OUT_PATH = BACKEND_ROOT / "testdata" / "accuracy_test_v9.zip"
V8_ZIP   = BACKEND_ROOT / "testdata" / "accuracy_test_v8.zip"

# ── P41: MCT — 키 XOR 갱신 완전 없음 ───────────────────────────────
VIOLATIONS_LEA057_NOKEY = """\
/* P41: LEA-057 — MCT 외부 루프에 키 XOR 갱신 없음 */
#include <stdint.h>
#include <string.h>

#define BLOCK_LEN 16

void lea_mct(uint8_t *key, uint8_t *pt, uint8_t *ct) {
    int i, j;
    for (i = 0; i < 100; i++) {
        for (j = 0; j < 1000; j++) {
            memcpy(ct, pt, BLOCK_LEN);
            memcpy(pt, ct, BLOCK_LEN);
        }
        /* VIOLATION: 외부 루프 후 key ^= ct 갱신이 없음 */
    }
}
"""

# ── P42: MCT — 키 갱신이 내부 루프 안에만 있음 (외부 루프에서 없음) ──
# 참고: 내부 루프에서 key ^= ct 를 반복하면 의미가 다름 (outer 갱신 누락)
# 아예 없는 케이스 P41이 더 명확하므로, 이 케이스는 key가 상수로만 쓰임
VIOLATIONS_LEA057_INNER = """\
/* P42: LEA-057 — 외부 루프 키 갱신 없이 내부에서만 ct 복사 */
#include <stdint.h>
#include <string.h>

#define BLOCK_LEN 16
#define KEY_LEN   16

void lea_ecb_mct(uint8_t *key, uint8_t *pt, uint8_t *ct) {
    int i, j, k;
    for (i = 0; i < 100; i++) {
        for (j = 0; j < 1000; j++) {
            memcpy(ct, pt, BLOCK_LEN);
            memcpy(pt, ct, BLOCK_LEN);
            /* 내부 루프: key 갱신 없음 */
        }
        /* VIOLATION: 외부 루프에서 key XOR 갱신 누락 */
        /* 올바른 형태: for(k=0;k<KEY_LEN;k++) key[k] ^= ct[k]; */
    }
}
"""

# ── N39: MCT 정상 — key[k] ^= ct[k] ────────────────────────────────
SAFE_LEA057_XOR = """\
/* N39: LEA-057 — MCT 정상: key[k] ^= ct[k] 갱신 있음 */
#include <stdint.h>
#include <string.h>

#define BLOCK_LEN 16
#define KEY_LEN   16

void lea_mct(uint8_t *key, uint8_t *pt, uint8_t *ct) {
    int i, j, k;
    for (i = 0; i < 100; i++) {
        for (j = 0; j < 1000; j++) {
            memcpy(ct, pt, BLOCK_LEN);
            memcpy(pt, ct, BLOCK_LEN);
        }
        /* CORRECT: 외부 루프 후 키 XOR 갱신 */
        for (k = 0; k < KEY_LEN; k++) {
            key[k] ^= ct[k];
        }
    }
}
"""

# ── N40: MCT 정상 — key[k] = key[k] ^ ct[k] ────────────────────────
SAFE_LEA057_ASSIGN = """\
/* N40: LEA-057 — MCT 정상: key[k] = key[k] ^ ct[k] 형태 갱신 */
#include <stdint.h>
#include <string.h>

#define BLOCK_LEN 16
#define KEY_LEN   16

void lea_ecb_mct(uint8_t *key, uint8_t *pt, uint8_t *ct) {
    int i, j, k;
    for (i = 0; i < 100; i++) {
        for (j = 0; j < 1000; j++) {
            memcpy(ct, pt, BLOCK_LEN);
            memcpy(pt, ct, BLOCK_LEN);
        }
        /* CORRECT: 명시적 XOR 대입 */
        for (k = 0; k < KEY_LEN; k++) {
            key[k] = key[k] ^ ct[k];
        }
    }
}
"""

NEW_GT_LINES = """\
violations_lea057_nokey.c | P | LEA-057 | MCT 외부 루프 키 XOR 갱신 없음
violations_lea057_inner.c | P | LEA-057 | MCT 외부 루프 키 갱신 없음 (내부에만)
safe_lea057_xor.c | N | LEA-057 | key[k] ^= ct[k] 갱신 있음
safe_lea057_assign.c | N | LEA-057 | key[k] = key[k] ^ ct[k] 갱신 있음
"""


def build_zip():
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    v8_entries: dict[str, bytes] = {}
    with zipfile.ZipFile(V8_ZIP) as zf:
        for name in zf.namelist():
            v8_entries[name] = zf.read(name)

    old_gt = v8_entries.get("GROUND_TRUTH.md", b"").decode("utf-8")
    new_gt = old_gt.rstrip("\n") + "\n" + NEW_GT_LINES

    new_files = {
        "src/violations_lea057_nokey.c": VIOLATIONS_LEA057_NOKEY,
        "src/violations_lea057_inner.c": VIOLATIONS_LEA057_INNER,
        "src/safe_lea057_xor.c":         SAFE_LEA057_XOR,
        "src/safe_lea057_assign.c":      SAFE_LEA057_ASSIGN,
    }

    with zipfile.ZipFile(OUT_PATH, "w", zipfile.ZIP_DEFLATED) as zout:
        for name, data in v8_entries.items():
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
