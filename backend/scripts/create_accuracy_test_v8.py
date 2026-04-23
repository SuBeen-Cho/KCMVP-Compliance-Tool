"""
accuracy_test_v8.zip 생성

v7(70 cases) + 8 new LEA-047 cases:
  P39 violations_lea047_ecb.c   LEA-047  ECB-MCT에서 PT←CT 갱신 없음
  P40 violations_lea047_cbc.c   LEA-047  CBC-MCT에서 IV 갱신 없음
  N33 safe_ccm_v6.c             LEA-047  CCMCtx 포함이지만 MCT 함수 없음 → 정상
  N34 safe_gcm_v6.c             LEA-047  GCMCtx 포함이지만 MCT 함수 없음 → 정상
  N35 safe_lea_mct_v6.c         LEA-047  올바른 MCT 루프 → 정상 (LEA-046도 N)
  N36 safe_lea047_ecb.c         LEA-047  ECB-MCT PT←CT 갱신 있음 → 정상
  N37 safe_lea047_cbc.c         LEA-047  CBC-MCT IV 갱신 있음 → 정상
  N38 safe_lea047_ctr.c         LEA-047  CTR-MCT 카운터 증가 있음 → 정상
"""
import zipfile
from pathlib import Path

BACKEND_ROOT = Path(__file__).parent.parent
OUT_PATH     = BACKEND_ROOT / "testdata" / "accuracy_test_v8.zip"
V7_ZIP       = BACKEND_ROOT / "testdata" / "accuracy_test_v7.zip"

# ── P39: ECB-MCT — PT←CT 갱신 없음 ─────────────────────────────────
VIOLATIONS_LEA047_ECB = """\
/* P39: LEA-047 — ECB-MCT: 내부 루프 후 PT←CT 갱신 없음 */
#include <stdint.h>
#include <string.h>

#define BLOCK_LEN 16

void lea_ecb_mct(uint8_t *key, uint8_t *pt, uint8_t *ct) {
    int i, j;
    uint8_t tmp[BLOCK_LEN];

    for (i = 0; i < 100; i++) {
        for (j = 0; j < 1000; j++) {
            memcpy(tmp, pt, BLOCK_LEN);
            memcpy(ct, tmp, BLOCK_LEN);
            /* VIOLATION: ECB-MCT는 내부 루프 후 PT = CT[j] 해야 함
               여기서는 PT 갱신 없이 다음 반복으로 넘어감 */
        }
        /* key update */
        key[0] ^= ct[0];
    }
}
"""

# ── P40: CBC-MCT — IV 갱신 없음 ─────────────────────────────────────
VIOLATIONS_LEA047_CBC = """\
/* P40: LEA-047 — CBC-MCT: IV 갱신 없음 */
#include <stdint.h>
#include <string.h>

#define BLOCK_LEN 16

void lea_cbc_mct(uint8_t *key, uint8_t *iv, uint8_t *pt, uint8_t *ct) {
    int i, j;
    uint8_t tmp[BLOCK_LEN];

    for (i = 0; i < 100; i++) {
        for (j = 0; j < 1000; j++) {
            /* CBC 암호화 */
            int k;
            for (k = 0; k < BLOCK_LEN; k++) tmp[k] = pt[k] ^ iv[k];
            memcpy(ct, tmp, BLOCK_LEN);
            /* VIOLATION: CBC-MCT는 IV = CT[j-1] 갱신이 있어야 함
               여기서는 IV 갱신 없음 */
            memcpy(pt, ct, BLOCK_LEN);
        }
        key[0] ^= ct[0];
    }
}
"""

# ── N36: ECB-MCT 정상 — PT←CT 갱신 있음 ────────────────────────────
SAFE_LEA047_ECB = """\
/* N36: LEA-047 — ECB-MCT 정상: 내부 루프 후 PT = CT[j] */
#include <stdint.h>
#include <string.h>

#define BLOCK_LEN 16

void lea_ecb_mct(uint8_t *key, uint8_t *pt, uint8_t *ct) {
    int i, j;
    uint8_t tmp[BLOCK_LEN];

    for (i = 0; i < 100; i++) {
        for (j = 0; j < 1000; j++) {
            memcpy(tmp, pt, BLOCK_LEN);
            memcpy(ct, tmp, BLOCK_LEN);
            memcpy(pt, ct, BLOCK_LEN);  /* CORRECT: PT ← CT (ECB-MCT 갱신) */
        }
        key[0] ^= ct[0];  /* key update */
    }
}
"""

# ── N37: CBC-MCT 정상 — IV 갱신 있음 ───────────────────────────────
SAFE_LEA047_CBC = """\
/* N37: LEA-047 — CBC-MCT 정상: IV 갱신 포함 */
#include <stdint.h>
#include <string.h>

#define BLOCK_LEN 16

void lea_cbc_mct(uint8_t *key, uint8_t *iv, uint8_t *pt, uint8_t *ct) {
    int i, j, k;
    uint8_t tmp[BLOCK_LEN];
    uint8_t prev_ct[BLOCK_LEN];

    for (i = 0; i < 100; i++) {
        for (j = 0; j < 1000; j++) {
            for (k = 0; k < BLOCK_LEN; k++) tmp[k] = pt[k] ^ iv[k];
            memcpy(ct, tmp, BLOCK_LEN);
            memcpy(prev_ct, iv, BLOCK_LEN);
            memcpy(iv, ct, BLOCK_LEN);  /* CORRECT: IV ← CT[j] (CBC-MCT 갱신) */
            memcpy(pt, ct, BLOCK_LEN);
        }
        key[0] ^= ct[0];
    }
}
"""

# ── N38: CTR-MCT 정상 — 카운터 증가 있음 ───────────────────────────
SAFE_LEA047_CTR = """\
/* N38: LEA-047 — CTR-MCT 정상: 카운터 증가 포함 */
#include <stdint.h>
#include <string.h>

#define BLOCK_LEN 16

void lea_ctr_mct(uint8_t *key, uint8_t *ctr, uint8_t *pt, uint8_t *ct) {
    int i, j, k;
    uint8_t ks[BLOCK_LEN];

    for (i = 0; i < 100; i++) {
        for (j = 0; j < 1000; j++) {
            memcpy(ks, ctr, BLOCK_LEN);
            for (k = 0; k < BLOCK_LEN; k++) ct[k] = pt[k] ^ ks[k];
            /* CORRECT: CTR-MCT 카운터 증가 */
            for (k = BLOCK_LEN - 1; k >= 0; k--) {
                if (++ctr[k]) break;  /* 128비트 카운터 증가 */
            }
        }
        key[0] ^= ct[0];
    }
}
"""

NEW_GT_LINES = """\
violations_lea047_ecb.c | P | LEA-047 | ECB-MCT PT←CT 갱신 없음
violations_lea047_cbc.c | P | LEA-047 | CBC-MCT IV 갱신 없음
safe_ccm_v6.c | N | LEA-047 | CCMCtx 포함이지만 MCT 함수 없음
safe_gcm_v6.c | N | LEA-047 | GCMCtx 포함이지만 MCT 함수 없음
safe_lea_mct_v6.c | N | LEA-047 | 올바른 MCT 루프 구조
safe_lea047_ecb.c | N | LEA-047 | ECB-MCT PT←CT 갱신 있음
safe_lea047_cbc.c | N | LEA-047 | CBC-MCT IV 갱신 있음
safe_lea047_ctr.c | N | LEA-047 | CTR-MCT 카운터 증가 있음
"""


def build_zip():
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    v7_entries: dict[str, bytes] = {}
    with zipfile.ZipFile(V7_ZIP) as zf:
        for name in zf.namelist():
            v7_entries[name] = zf.read(name)

    old_gt = v7_entries.get("GROUND_TRUTH.md", b"").decode("utf-8")
    new_gt  = old_gt.rstrip("\n") + "\n" + NEW_GT_LINES

    new_files = {
        "src/violations_lea047_ecb.c": VIOLATIONS_LEA047_ECB,
        "src/violations_lea047_cbc.c": VIOLATIONS_LEA047_CBC,
        "src/safe_lea047_ecb.c":       SAFE_LEA047_ECB,
        "src/safe_lea047_cbc.c":       SAFE_LEA047_CBC,
        "src/safe_lea047_ctr.c":       SAFE_LEA047_CTR,
    }

    with zipfile.ZipFile(OUT_PATH, "w", zipfile.ZIP_DEFLATED) as zout:
        for name, data in v7_entries.items():
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
