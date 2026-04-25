"""
accuracy_test_v10.zip 생성

v9(82 cases) + 6 new CTR-001 cases:
  P43 violations_ctr001_dec.c    CTR-001  ctr_decrypt에서 lea_decrypt 호출
  P44 violations_ctr001_encdec.c CTR-001  ctr_encrypt도 lea_decrypt 호출
  N41 safe_ctr001_enc.c          CTR-001  ctr_encrypt/decrypt 모두 lea_encrypt 사용 → 정상
  N42 safe_ctr001_sym.c          CTR-001  대칭 CTR 구조 (암=복호화 동일 함수) → 정상
  N43 safe_ctr001_noctr.c        CTR-001  CTR 함수 없음 → None(L3) → 정상 취급
  N44 safe_ctr001_xor.c          CTR-001  XOR만으로 구현 (ENC 함수 명시 없음) → 정상
"""
import zipfile
from pathlib import Path

BACKEND_ROOT = Path(__file__).parent.parent
OUT_PATH = BACKEND_ROOT / "testdata" / "accuracy_test_v10.zip"
V9_ZIP   = BACKEND_ROOT / "testdata" / "accuracy_test_v9.zip"

# ── P43: ctr_decrypt에서 lea_decrypt 호출 ───────────────────────────
VIOLATIONS_CTR001_DEC = """\
/* P43: CTR-001 — ctr_decrypt가 내부에서 lea_decrypt 호출 (ENC 써야 함) */
#include <stdint.h>
#include <string.h>

#define BLOCK_LEN 16

void lea_encrypt(uint8_t *key, uint8_t *pt, uint8_t *ct);
void lea_decrypt(uint8_t *key, uint8_t *ct, uint8_t *pt);

void ctr_encrypt(uint8_t *key, uint8_t *ctr, uint8_t *pt, uint8_t *ct, int len) {
    uint8_t ks[BLOCK_LEN];
    lea_encrypt(key, ctr, ks);  /* CORRECT: ENC 사용 */
    int i;
    for (i = 0; i < len; i++) ct[i] = pt[i] ^ ks[i];
    ctr[15]++;
}

void ctr_decrypt(uint8_t *key, uint8_t *ctr, uint8_t *ct, uint8_t *pt, int len) {
    uint8_t ks[BLOCK_LEN];
    lea_decrypt(key, ctr, ks);  /* VIOLATION: CTR는 복호화도 ENC 사용해야 함 */
    int i;
    for (i = 0; i < len; i++) pt[i] = ct[i] ^ ks[i];
    ctr[15]++;
}
"""

# ── P44: ctr_encrypt도 lea_decrypt 사용 ─────────────────────────────
VIOLATIONS_CTR001_ENCDEC = """\
/* P44: CTR-001 — ctr_encrypt/decrypt 모두 lea_decrypt 호출 */
#include <stdint.h>

#define BLOCK_LEN 16

void lea_decrypt(uint8_t *key, uint8_t *ct, uint8_t *pt);

void ctr_encrypt(uint8_t *key, uint8_t *ctr, uint8_t *pt, uint8_t *ct, int len) {
    uint8_t ks[BLOCK_LEN];
    lea_decrypt(key, ctr, ks);  /* VIOLATION */
    int i;
    for (i = 0; i < len; i++) ct[i] = pt[i] ^ ks[i];
}

void ctr_decrypt(uint8_t *key, uint8_t *ctr, uint8_t *ct, uint8_t *pt, int len) {
    uint8_t ks[BLOCK_LEN];
    lea_decrypt(key, ctr, ks);  /* VIOLATION */
    int i;
    for (i = 0; i < len; i++) pt[i] = ct[i] ^ ks[i];
}
"""

# ── N41: 정상 — 암·복호화 모두 lea_encrypt 사용 ─────────────────────
SAFE_CTR001_ENC = """\
/* N41: CTR-001 — ctr_encrypt/decrypt 모두 lea_encrypt 사용 (정상) */
#include <stdint.h>

#define BLOCK_LEN 16

void lea_encrypt(uint8_t *key, uint8_t *pt, uint8_t *ct);

void ctr_encrypt(uint8_t *key, uint8_t *ctr, uint8_t *pt, uint8_t *ct, int len) {
    uint8_t ks[BLOCK_LEN];
    lea_encrypt(key, ctr, ks);  /* CORRECT */
    int i;
    for (i = 0; i < len; i++) ct[i] = pt[i] ^ ks[i];
    ctr[15]++;
}

void ctr_decrypt(uint8_t *key, uint8_t *ctr, uint8_t *ct, uint8_t *pt, int len) {
    uint8_t ks[BLOCK_LEN];
    lea_encrypt(key, ctr, ks);  /* CORRECT: 복호화도 ENC 사용 */
    int i;
    for (i = 0; i < len; i++) pt[i] = ct[i] ^ ks[i];
    ctr[15]++;
}
"""

# ── N42: 정상 — 단일 함수로 암=복호화 (대칭 CTR) ────────────────────
SAFE_CTR001_SYM = """\
/* N42: CTR-001 — 단일 ctr_encrypt 함수, 복호화 별도 없음 (대칭) */
#include <stdint.h>

#define BLOCK_LEN 16

void lea_encrypt(uint8_t *key, uint8_t *in, uint8_t *out);

/* CTR 모드: 암호화=복호화이므로 하나의 함수 */
void lea_ctr(uint8_t *key, uint8_t *ctr, uint8_t *in, uint8_t *out, int len) {
    uint8_t ks[BLOCK_LEN];
    lea_encrypt(key, ctr, ks);  /* CORRECT */
    int i;
    for (i = 0; i < len; i++) out[i] = in[i] ^ ks[i];
    ctr[15]++;
}
"""

# ── N43: CTR 함수 없음 → checker returns None → L3 판단 ──────────────
SAFE_CTR001_NOCTR = """\
/* N43: CTR-001 — CTR 관련 함수 없음, checker는 None 반환 → 정상 취급 */
#include <stdint.h>

void lea_encrypt(uint8_t *key, uint8_t *pt, uint8_t *ct) {
    /* LEA 블록 암호화 구현 */
    (void)key; (void)pt; (void)ct;
}

void lea_decrypt(uint8_t *key, uint8_t *ct, uint8_t *pt) {
    /* LEA 블록 복호화 구현 */
    (void)key; (void)ct; (void)pt;
}
"""

# ── N44: XOR만으로 구현, ENC 함수 명시 없음 → 위반 없음 ───────────────
SAFE_CTR001_XOR = """\
/* N44: CTR-001 — 내부 ENC 함수 이름이 일반적 (block_cipher), lea_decrypt 호출 없음 */
#include <stdint.h>

#define BLOCK_LEN 16

void block_cipher_enc(uint8_t *key, uint8_t *in, uint8_t *out);

void ctr_encrypt(uint8_t *key, uint8_t *ctr, uint8_t *pt, uint8_t *ct, int len) {
    uint8_t ks[BLOCK_LEN];
    block_cipher_enc(key, ctr, ks);  /* 일반 ENC 함수 사용 (정상) */
    int i;
    for (i = 0; i < len; i++) ct[i] = pt[i] ^ ks[i];
    ctr[15]++;
}

void ctr_decrypt(uint8_t *key, uint8_t *ctr, uint8_t *ct, uint8_t *pt, int len) {
    uint8_t ks[BLOCK_LEN];
    block_cipher_enc(key, ctr, ks);  /* CORRECT */
    int i;
    for (i = 0; i < len; i++) pt[i] = ct[i] ^ ks[i];
    ctr[15]++;
}
"""

NEW_GT_LINES = """\
violations_ctr001_dec.c | P | CTR-001 | ctr_decrypt에서 lea_decrypt 호출
violations_ctr001_encdec.c | P | CTR-001 | 암·복호화 모두 lea_decrypt 호출
safe_ctr001_enc.c | N | CTR-001 | 암·복호화 모두 lea_encrypt 사용
safe_ctr001_sym.c | N | CTR-001 | 단일 lea_ctr 함수로 대칭 구현
safe_ctr001_noctr.c | N | CTR-001 | CTR 함수 없음 → checker None → 정상
safe_ctr001_xor.c | N | CTR-001 | block_cipher_enc 사용 (lea_decrypt 없음)
"""


def build_zip():
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    v9_entries: dict[str, bytes] = {}
    with zipfile.ZipFile(V9_ZIP) as zf:
        for name in zf.namelist():
            v9_entries[name] = zf.read(name)

    old_gt = v9_entries.get("GROUND_TRUTH.md", b"").decode("utf-8")
    new_gt = old_gt.rstrip("\n") + "\n" + NEW_GT_LINES

    new_files = {
        "src/violations_ctr001_dec.c":    VIOLATIONS_CTR001_DEC,
        "src/violations_ctr001_encdec.c": VIOLATIONS_CTR001_ENCDEC,
        "src/safe_ctr001_enc.c":          SAFE_CTR001_ENC,
        "src/safe_ctr001_sym.c":          SAFE_CTR001_SYM,
        "src/safe_ctr001_noctr.c":        SAFE_CTR001_NOCTR,
        "src/safe_ctr001_xor.c":          SAFE_CTR001_XOR,
    }

    with zipfile.ZipFile(OUT_PATH, "w", zipfile.ZIP_DEFLATED) as zout:
        for name, data in v9_entries.items():
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
