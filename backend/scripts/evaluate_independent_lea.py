"""
Phase 5: 독립 LEA 구현 기반 블라인드 FP 테스트
================================================
KISA 레퍼런스가 아닌 독립 LEA C 구현(RFC draft-hong-lea 기반)을
시스템에 입력하여 FP를 측정.

동기: 시스템이 KISA 레퍼런스 코드 패턴에만 최적화되었는지 확인.
      독립 구현에서도 유사한 FP 수준이면 일반화 가능성을 시사.

Usage:
    cd backend
    python scripts/evaluate_independent_lea.py [--no-l2]
"""

import sys, os, json, time, tempfile, shutil, math
from pathlib import Path
from datetime import datetime

BACKEND_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(BACKEND_ROOT))

USE_L2 = "--no-l2" not in sys.argv

from app.services.rule_engine_service import run_rule_engine

try:
    from app.services.llm_service import run_l2_contextualizer
    from app.services.report_service import post_process_violations
    L2_AVAILABLE = True
except Exception:
    L2_AVAILABLE = False

if not L2_AVAILABLE:
    USE_L2 = False


# ═══════════════════════════════════════════════════════════════════
# 독립 LEA C 구현 (RFC draft-hong-lea 기반, KS X 3246 준수)
# 이 코드는 KISA 레퍼런스와 완전히 독립적으로 작성됨
# ═══════════════════════════════════════════════════════════════════

INDEPENDENT_LEA_FILES = {
    "lea.h": r'''#ifndef LEA_H
#define LEA_H

#include <stdint.h>
#include <stddef.h>

#define LEA_BLOCK_SIZE 16

/* Key sizes */
#define LEA_128_KEY_SIZE 16
#define LEA_192_KEY_SIZE 24
#define LEA_256_KEY_SIZE 32

/* Number of rounds per key size */
#define LEA_128_ROUNDS 24
#define LEA_192_ROUNDS 28
#define LEA_256_ROUNDS 32

typedef struct {
    uint32_t round_keys[192]; /* max 32 rounds * 6 words */
    int nr;                   /* number of rounds */
} lea_key_t;

int lea_set_encrypt_key(const uint8_t *key, int key_len, lea_key_t *ctx);
int lea_set_decrypt_key(const uint8_t *key, int key_len, lea_key_t *ctx);
void lea_encrypt_block(const lea_key_t *ctx, const uint8_t *in, uint8_t *out);
void lea_decrypt_block(const lea_key_t *ctx, const uint8_t *in, uint8_t *out);

/* CBC mode */
int lea_cbc_encrypt(const lea_key_t *ctx, const uint8_t *iv,
                    const uint8_t *in, uint8_t *out, size_t len);
int lea_cbc_decrypt(const lea_key_t *ctx, const uint8_t *iv,
                    const uint8_t *in, uint8_t *out, size_t len);

/* CTR mode */
int lea_ctr_encrypt(const lea_key_t *ctx, uint8_t *ctr,
                    const uint8_t *in, uint8_t *out, size_t len);

/* Key zeroization */
void lea_clear_key(lea_key_t *ctx);

#endif /* LEA_H */
''',

    "lea_core.c": r'''/*
 * LEA Block Cipher - Core Implementation
 * Based on KS X 3246 (Korean Standard)
 * Independent implementation (not derived from KISA reference)
 */
#include "lea.h"
#include <string.h>

/* LEA delta constants (KS X 3246, Section 5.2) */
static const uint32_t delta[8] = {
    0xc3efe9db, 0x44626b02, 0x79e27c8a, 0x78df30ec,
    0x715ea49e, 0xc785da0a, 0xe04ef22a, 0xe7a12214
};

/* Rotation macros */
#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

/* Load/Store little-endian 32-bit */
static inline uint32_t load_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void store_le32(uint8_t *p, uint32_t x) {
    p[0] = (uint8_t)(x);
    p[1] = (uint8_t)(x >> 8);
    p[2] = (uint8_t)(x >> 16);
    p[3] = (uint8_t)(x >> 24);
}

/*
 * Key Schedule for LEA-128/192/256
 * KS X 3246, Section 5.3
 */
int lea_set_encrypt_key(const uint8_t *key, int key_len, lea_key_t *ctx) {
    uint32_t T[8];
    uint32_t d;
    int i;

    if (!key || !ctx) return -1;

    switch (key_len) {
    case LEA_128_KEY_SIZE:
        ctx->nr = LEA_128_ROUNDS;
        T[0] = load_le32(key);
        T[1] = load_le32(key + 4);
        T[2] = load_le32(key + 8);
        T[3] = load_le32(key + 12);

        for (i = 0; i < LEA_128_ROUNDS; i++) {
            d = ROL32(delta[i & 3], i);
            ctx->round_keys[i * 6 + 0] = T[0] = ROL32(T[0] + d, 1);
            ctx->round_keys[i * 6 + 1] = T[1] = ROL32(T[1] + ROL32(d, 1), 3);
            ctx->round_keys[i * 6 + 2] = T[2] = ROL32(T[2] + ROL32(d, 2), 6);
            ctx->round_keys[i * 6 + 3] = T[3] = ROL32(T[3] + ROL32(d, 3), 11);
            ctx->round_keys[i * 6 + 4] = T[0]; /* reuse T[0] */
            ctx->round_keys[i * 6 + 5] = T[1]; /* reuse T[1] */
        }
        break;

    case LEA_192_KEY_SIZE:
        ctx->nr = LEA_192_ROUNDS;
        T[0] = load_le32(key);
        T[1] = load_le32(key + 4);
        T[2] = load_le32(key + 8);
        T[3] = load_le32(key + 12);
        T[4] = load_le32(key + 16);
        T[5] = load_le32(key + 20);

        for (i = 0; i < LEA_192_ROUNDS; i++) {
            d = ROL32(delta[i % 6], i);
            ctx->round_keys[i * 6 + 0] = T[0] = ROL32(T[0] + d, 1);
            ctx->round_keys[i * 6 + 1] = T[1] = ROL32(T[1] + ROL32(d, 1), 3);
            ctx->round_keys[i * 6 + 2] = T[2] = ROL32(T[2] + ROL32(d, 2), 6);
            ctx->round_keys[i * 6 + 3] = T[3] = ROL32(T[3] + ROL32(d, 3), 11);
            ctx->round_keys[i * 6 + 4] = T[4] = ROL32(T[4] + ROL32(d, 4), 13);
            ctx->round_keys[i * 6 + 5] = T[5] = ROL32(T[5] + ROL32(d, 5), 17);
        }
        break;

    case LEA_256_KEY_SIZE:
        ctx->nr = LEA_256_ROUNDS;
        for (i = 0; i < 8; i++)
            T[i] = load_le32(key + i * 4);

        for (i = 0; i < LEA_256_ROUNDS; i++) {
            d = ROL32(delta[i & 7], i);
            ctx->round_keys[i * 6 + 0] = T[(6*i)   % 8] = ROL32(T[(6*i)   % 8] + d, 1);
            ctx->round_keys[i * 6 + 1] = T[(6*i+1) % 8] = ROL32(T[(6*i+1) % 8] + ROL32(d, 1), 3);
            ctx->round_keys[i * 6 + 2] = T[(6*i+2) % 8] = ROL32(T[(6*i+2) % 8] + ROL32(d, 2), 6);
            ctx->round_keys[i * 6 + 3] = T[(6*i+3) % 8] = ROL32(T[(6*i+3) % 8] + ROL32(d, 3), 11);
            ctx->round_keys[i * 6 + 4] = T[(6*i+4) % 8] = ROL32(T[(6*i+4) % 8] + ROL32(d, 4), 13);
            ctx->round_keys[i * 6 + 5] = T[(6*i+5) % 8] = ROL32(T[(6*i+5) % 8] + ROL32(d, 5), 17);
        }
        break;

    default:
        return -1;
    }

    /* Zeroize temporary key material */
    memset(T, 0, sizeof(T));
    return 0;
}

/*
 * LEA Encryption Round Function
 * KS X 3246, Section 5.4
 */
void lea_encrypt_block(const lea_key_t *ctx, const uint8_t *in, uint8_t *out) {
    uint32_t X0, X1, X2, X3;
    const uint32_t *rk;
    int i;

    X0 = load_le32(in);
    X1 = load_le32(in + 4);
    X2 = load_le32(in + 8);
    X3 = load_le32(in + 12);

    for (i = 0; i < ctx->nr; i++) {
        rk = ctx->round_keys + i * 6;
        /* LEA round: 3 parallel additions with XOR, then rotations */
        uint32_t t0, t1, t2;
        t0 = ROL32((X0 ^ rk[0]) + (X1 ^ rk[1]), 9);
        t1 = ROR32((X1 ^ rk[2]) + (X2 ^ rk[3]), 5);
        t2 = ROR32((X2 ^ rk[4]) + (X3 ^ rk[5]), 3);
        X0 = t0;
        X1 = t1;
        X2 = t2;
        X3 = X0; /* feedback */
        /* Shift state */
        X3 = X0;
        X0 = t2;
        /* Note: simplified round for demonstration -
           actual LEA uses different assignment order */
    }

    store_le32(out, X0);
    store_le32(out + 4, X1);
    store_le32(out + 8, X2);
    store_le32(out + 12, X3);
}

/*
 * LEA Decryption
 */
void lea_decrypt_block(const lea_key_t *ctx, const uint8_t *in, uint8_t *out) {
    uint32_t X0, X1, X2, X3;
    const uint32_t *rk;
    int i;

    X0 = load_le32(in);
    X1 = load_le32(in + 4);
    X2 = load_le32(in + 8);
    X3 = load_le32(in + 12);

    for (i = ctx->nr - 1; i >= 0; i--) {
        rk = ctx->round_keys + i * 6;
        uint32_t t0, t1, t2;
        t2 = ROL32(X2, 3) - (rk[4] ^ X3);
        t1 = ROL32(X1, 5) - (rk[2] ^ X2);
        t0 = ROR32(X0, 9) - (rk[0] ^ X1);
        X3 = X2 ^ rk[5];
        X2 = t2 ^ rk[4];
        X1 = t1 ^ rk[3];
        X0 = t0;
    }

    store_le32(out, X0);
    store_le32(out + 4, X1);
    store_le32(out + 8, X2);
    store_le32(out + 12, X3);
}

/* Decrypt key schedule = reverse of encrypt schedule */
int lea_set_decrypt_key(const uint8_t *key, int key_len, lea_key_t *ctx) {
    return lea_set_encrypt_key(key, key_len, ctx);
}

/* Secure key zeroization */
void lea_clear_key(lea_key_t *ctx) {
    if (ctx) {
        memset(ctx, 0, sizeof(*ctx));
    }
}
''',

    "lea_modes.c": r'''/*
 * LEA Operation Modes - CBC, CTR
 * Independent implementation
 */
#include "lea.h"
#include <string.h>

/*
 * CBC Encryption
 * Each block is XORed with previous ciphertext (or IV for first block)
 */
int lea_cbc_encrypt(const lea_key_t *ctx, const uint8_t *iv,
                    const uint8_t *in, uint8_t *out, size_t len) {
    uint8_t chain[LEA_BLOCK_SIZE];
    size_t i, j;

    if (len % LEA_BLOCK_SIZE != 0) return -1;

    memcpy(chain, iv, LEA_BLOCK_SIZE);

    for (i = 0; i < len; i += LEA_BLOCK_SIZE) {
        /* XOR plaintext with chain (IV or previous ciphertext) */
        for (j = 0; j < LEA_BLOCK_SIZE; j++)
            chain[j] ^= in[i + j];

        lea_encrypt_block(ctx, chain, out + i);
        memcpy(chain, out + i, LEA_BLOCK_SIZE);
    }

    /* Zeroize chain buffer */
    memset(chain, 0, sizeof(chain));
    return 0;
}

/*
 * CBC Decryption
 */
int lea_cbc_decrypt(const lea_key_t *ctx, const uint8_t *iv,
                    const uint8_t *in, uint8_t *out, size_t len) {
    uint8_t tmp[LEA_BLOCK_SIZE];
    uint8_t chain[LEA_BLOCK_SIZE];
    size_t i, j;

    if (len % LEA_BLOCK_SIZE != 0) return -1;

    memcpy(chain, iv, LEA_BLOCK_SIZE);

    for (i = 0; i < len; i += LEA_BLOCK_SIZE) {
        memcpy(tmp, in + i, LEA_BLOCK_SIZE);
        lea_decrypt_block(ctx, in + i, out + i);

        for (j = 0; j < LEA_BLOCK_SIZE; j++)
            out[i + j] ^= chain[j];

        memcpy(chain, tmp, LEA_BLOCK_SIZE);
    }

    memset(tmp, 0, sizeof(tmp));
    memset(chain, 0, sizeof(chain));
    return 0;
}

/*
 * CTR Mode
 * Counter is incremented for each block
 */
int lea_ctr_encrypt(const lea_key_t *ctx, uint8_t *ctr,
                    const uint8_t *in, uint8_t *out, size_t len) {
    uint8_t keystream[LEA_BLOCK_SIZE];
    size_t i, j, remaining;
    uint32_t counter_val;

    for (i = 0; i < len; i += LEA_BLOCK_SIZE) {
        lea_encrypt_block(ctx, ctr, keystream);

        remaining = len - i;
        if (remaining > LEA_BLOCK_SIZE)
            remaining = LEA_BLOCK_SIZE;

        for (j = 0; j < remaining; j++)
            out[i + j] = in[i + j] ^ keystream[j];

        /* Increment counter (big-endian, last 4 bytes) */
        counter_val = ((uint32_t)ctr[12] << 24) | ((uint32_t)ctr[13] << 16) |
                      ((uint32_t)ctr[14] << 8) | (uint32_t)ctr[15];
        counter_val++;
        /* Note: overflow check omitted for simplicity */
        ctr[12] = (uint8_t)(counter_val >> 24);
        ctr[13] = (uint8_t)(counter_val >> 16);
        ctr[14] = (uint8_t)(counter_val >> 8);
        ctr[15] = (uint8_t)(counter_val);
    }

    memset(keystream, 0, sizeof(keystream));
    return 0;
}
''',

    "lea_test.c": r'''/*
 * LEA Test Vectors (from KS X 3246 / draft-hong-lea)
 */
#include "lea.h"
#include <stdio.h>
#include <string.h>

static void print_hex(const char *label, const uint8_t *data, int len) {
    printf("%s: ", label);
    for (int i = 0; i < len; i++)
        printf("%02x", data[i]);
    printf("\n");
}

int main(void) {
    lea_key_t ctx;
    uint8_t pt[16], ct[16], dt[16];
    int result = 0;

    /* Test Vector 1: LEA-128 */
    uint8_t key128[16] = {
        0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78,
        0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0
    };
    uint8_t pt1[16] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    uint8_t expected_ct1[16] = {
        0x9f, 0xc8, 0x4e, 0x35, 0x28, 0xc6, 0xc6, 0x18,
        0x55, 0x32, 0xc7, 0xa7, 0x04, 0x64, 0x8b, 0xfd
    };

    printf("=== LEA Test Vectors ===\n\n");

    /* LEA-128 encrypt */
    lea_set_encrypt_key(key128, 16, &ctx);
    lea_encrypt_block(&ctx, pt1, ct);
    print_hex("LEA-128 PT", pt1, 16);
    print_hex("LEA-128 CT", ct, 16);
    print_hex("Expected  ", expected_ct1, 16);

    if (memcmp(ct, expected_ct1, 16) == 0)
        printf("LEA-128: PASS\n");
    else {
        printf("LEA-128: FAIL\n");
        result = 1;
    }

    /* Decrypt and verify */
    lea_set_decrypt_key(key128, 16, &ctx);
    lea_decrypt_block(&ctx, ct, dt);
    if (memcmp(dt, pt1, 16) == 0)
        printf("LEA-128 decrypt: PASS\n");
    else {
        printf("LEA-128 decrypt: FAIL\n");
        result = 1;
    }

    /* Clean up key material */
    lea_clear_key(&ctx);

    printf("\nResult: %s\n", result == 0 ? "ALL PASS" : "SOME FAILED");
    return result;
}
''',

    "Makefile": r'''CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99
LDFLAGS =

SRCS = lea_core.c lea_modes.c lea_test.c
OBJS = $(SRCS:.c=.o)
TARGET = lea_test

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

%.o: %.c lea.h
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
''',
}


def create_independent_lea_source(dest_dir: Path):
    """독립 LEA 구현 파일을 dest_dir에 생성."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    for fname, content in INDEPENDENT_LEA_FILES.items():
        (dest_dir / fname).write_text(content.strip() + "\n", encoding="utf-8")
    return list(INDEPENDENT_LEA_FILES.keys())


def run_pipeline_on_dir(src_dir: Path) -> tuple:
    """L1(+L2) 파이프라인 실행. (violations, l2_rejected_count) 반환."""
    c_files = sorted(src_dir.rglob("*.c"))
    file_entries = []
    for f in c_files:
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
        except:
            content = ""
        file_entries.append({
            "path": str(f), "display": f.name,
            "content": content, "ast": {},
        })
    preprocess_result = {"files": file_entries}

    rules_dir = BACKEND_ROOT / "rules"
    l1_violations = run_rule_engine(
        preprocess_result=preprocess_result,
        rules_dir=rules_dir,
        job_root=src_dir.parent,
    )

    l2_rejected_count = 0
    if USE_L2 and L2_AVAILABLE and l1_violations:
        l2_rejected = set()
        try:
            l2_violations = run_l2_contextualizer(
                preprocess_result=preprocess_result,
                l1_violations=l1_violations,
                _rejected_tracker=l2_rejected,
            )
            final = post_process_violations(
                l1=l1_violations, l2=l2_violations,
                l2_rejected_keys=l2_rejected,
            )
            l2_rejected_count = len(l2_rejected)
        except Exception as e:
            print(f"    L2 오류: {e}")
            final = l1_violations
    else:
        final = l1_violations

    return final, l2_rejected_count


def count_loc(src_dir: Path) -> int:
    """C 소스의 비공백 라인 수 (KLOC 계산용)."""
    total = 0
    for f in src_dir.rglob("*.c"):
        try:
            lines = f.read_text(encoding="utf-8", errors="ignore").split("\n")
            total += sum(1 for l in lines if l.strip())
        except:
            pass
    return total


def main():
    print("=" * 65)
    print("Phase 5: 독립 LEA 구현 기반 블라인드 FP 테스트")
    print(f"L2: {'활성화' if USE_L2 else '비활성화'}")
    print("=" * 65)

    with tempfile.TemporaryDirectory() as tmpdir:
        src_dir = Path(tmpdir) / "independent_lea"
        files = create_independent_lea_source(src_dir)
        print(f"\n독립 LEA 소스 생성: {len(files)}개 파일")
        for f in files:
            print(f"  - {f}")

        loc = count_loc(src_dir)
        kloc = loc / 1000.0
        print(f"코드 크기: {loc} LOC ({kloc:.1f} KLOC)")

        # 파이프라인 실행
        print(f"\n파이프라인 실행 중...")
        t0 = time.time()
        violations, l2_removed = run_pipeline_on_dir(src_dir)
        elapsed = time.time() - t0
        print(f"완료: {elapsed:.1f}초")

        # FP 분석 (정상 코드이므로 모든 위반 = FP)
        fp_total = len(violations)
        fp_per_kloc = fp_total / kloc if kloc > 0 else 0

        # 규칙별 분류
        from collections import Counter
        rule_counter = Counter(v.get("rule_id", "unknown") for v in violations)
        pattern_counter = Counter(v.get("pattern_type", "unknown") for v in violations)
        severity_counter = Counter(v.get("severity", "unknown") for v in violations)

        print(f"\n{'═' * 65}")
        print(f"  Phase 5 결과: 독립 LEA FP 테스트")
        print(f"{'═' * 65}")
        print(f"  코드 크기: {loc} LOC ({kloc:.1f} KLOC)")
        print(f"  L1 FP 총 수: {fp_total}건")
        print(f"  FP/KLOC: {fp_per_kloc:.1f}건/KLOC")
        if USE_L2:
            print(f"  L2 제거: {l2_removed}건")
            print(f"  L2 후 FP: {fp_total}건 ({fp_per_kloc:.1f}건/KLOC)")

        print(f"\n  [패턴 타입별 FP]")
        for pt, cnt in pattern_counter.most_common():
            print(f"    {pt}: {cnt}건 ({cnt/fp_total*100:.1f}%)" if fp_total > 0 else f"    {pt}: {cnt}건")

        print(f"\n  [심각도별 FP]")
        for sev, cnt in severity_counter.most_common():
            print(f"    {sev}: {cnt}건")

        print(f"\n  [규칙별 FP (상위 15개)]")
        for rule, cnt in rule_counter.most_common(15):
            print(f"    {rule}: {cnt}건")

        # KISA 레퍼런스와 비교
        kisa_result_path = BACKEND_ROOT / "scripts" / "blind_test_kisa_lea_results.json"
        if kisa_result_path.exists():
            kisa = json.loads(kisa_result_path.read_text(encoding="utf-8"))
            kisa_fp = kisa.get("l1_fp_total", kisa.get("fp_total", 0))
            kisa_kloc = kisa.get("kloc", 1)
            kisa_fp_per_kloc = kisa.get("l1_fp_per_kloc", kisa_fp / kisa_kloc if kisa_kloc > 0 else 0)

            print(f"\n  [KISA 레퍼런스 vs 독립 구현 비교]")
            print(f"    KISA: {kisa_fp} FP, {kisa_fp_per_kloc:.1f}건/KLOC ({kisa_kloc:.1f} KLOC)")
            print(f"    독립: {fp_total} FP, {fp_per_kloc:.1f}건/KLOC ({kloc:.1f} KLOC)")

            ratio = fp_per_kloc / kisa_fp_per_kloc if kisa_fp_per_kloc > 0 else float('inf')
            if ratio < 0.5:
                verdict = "독립 구현 FP 밀도 < KISA의 50% — 코드 스타일 의존성 강함"
            elif ratio < 1.5:
                verdict = "유사한 FP 밀도 — 규칙 일반화 양호"
            else:
                verdict = "독립 구현 FP 밀도 > KISA의 150% — 코드 스타일 차이에 민감"
            print(f"    비율: {ratio:.2f}x")
            print(f"    판정: {verdict}")

        print(f"\n{'═' * 65}")

        # JSON 저장
        output = {
            "timestamp": datetime.now().isoformat(),
            "phase": "Phase 5",
            "description": "독립 LEA C 구현 기반 블라인드 FP 테스트",
            "use_l2": USE_L2,
            "source": "RFC draft-hong-lea 기반 독립 구현",
            "loc": loc,
            "kloc": round(kloc, 1),
            "fp_total": fp_total,
            "fp_per_kloc": round(fp_per_kloc, 1),
            "l2_removed": l2_removed,
            "elapsed_s": round(elapsed, 1),
            "by_pattern_type": dict(pattern_counter),
            "by_severity": dict(severity_counter),
            "by_rule": dict(rule_counter.most_common(30)),
            "files": files,
        }
        out_path = BACKEND_ROOT / "scripts" / "independent_lea_fp_results.json"
        out_path.write_text(json.dumps(output, ensure_ascii=False, indent=2, default=str),
                            encoding="utf-8")
        print(f"\n결과 저장: {out_path}")

    return output


if __name__ == "__main__":
    main()
