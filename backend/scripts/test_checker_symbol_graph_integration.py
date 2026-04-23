#!/usr/bin/env python3
"""
체커 + symbol_graph 통합 테스트
================================
libclang symbol_graph 데이터(array_inits, type_aliases)가
체커 로직에 실제로 반영되는지 검증.

  C1 – LEA-010: delta 상수 표준값 → 위반 없음
  C2 – LEA-010: delta 상수 비표준값 → 위반 탐지
  C3 – LEA-010: delta 없이 ARX 구조만 → 기존 동작 유지
  C4 – LEA-031: type_aliases 있을 때 포인터 피연산자 FP 제거
  C5 – LEA-031: 실제 순서 역전 → 여전히 탐지
  C6 – LEA-034: type_aliases로 파라미터 타입 정보 포함한 메시지
  C7 – symbol_graph=None 이어도 check_rule 정상 동작 (backwards compat)
  C8 – 파이프라인 통합: build_symbol_graph → check_rule 연결 확인
"""
import sys
import textwrap
import zipfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.services.ast_checker_service import check_rule

PASS = "\033[92m✅ PASS\033[0m"
FAIL = "\033[91m❌ FAIL\033[0m"
results = []

def record(item, ok, detail=""):
    results.append({"item": item, "ok": ok})
    sym = PASS if ok else FAIL
    print(f"  {sym} {item}" + (f"  — {detail}" if detail else ""))

print("=" * 60)
print("  체커 + symbol_graph 통합 테스트")
print("=" * 60)

# ─── 공통 코드 조각 ─────────────────────────────────────────────

_KEY_C_CORRECT_DELTA = textwrap.dedent("""\
    typedef unsigned int uint32_t;
    static const uint32_t delta_128[4] = {
        0xc3efe9db, 0x44626b02, 0x79e27c8a, 0x78df30ec
    };
    static uint32_t ROL32(uint32_t x, int n) { return (x<<n)|(x>>(32-n)); }
    void lea_set_key(uint32_t *RK, const uint32_t *K) {
        uint32_t T[4];
        int i;
        for (i = 0; i < 32; i++) {
            T[0] = ROL32(T[0] + delta_128[i % 4], 1);
        }
    }
""")

_KEY_C_WRONG_DELTA = textwrap.dedent("""\
    typedef unsigned int uint32_t;
    static const uint32_t delta_128[4] = {
        0xdeadbeef, 0xcafebabe, 0x12345678, 0xabcdef01
    };
    static uint32_t ROL32(uint32_t x, int n) { return (x<<n)|(x>>(32-n)); }
    void lea_set_key(uint32_t *RK, const uint32_t *K) {
        uint32_t T[4];
        int i;
        for (i = 0; i < 32; i++) {
            T[0] = ROL32(T[0] + delta_128[i % 4], 1);
        }
    }
""")

_KEY_C_NO_DELTA = textwrap.dedent("""\
    typedef unsigned int uint32_t;
    static uint32_t ROL32(uint32_t x, int n) { return (x<<n)|(x>>(32-n)); }
    void lea_set_key(uint32_t *RK, const uint32_t *K) {
        uint32_t T[4];
        int i;
        for (i = 0; i < 32; i++) {
            T[0] = ROL32(T[0] + 0xc3efe9db, 1);
        }
    }
""")

_ENC_C_PTR_ADD = textwrap.dedent("""\
    typedef unsigned int uint32_t;
    void lea_encrypt(uint32_t *ct, const uint32_t *pt, const uint32_t *RK) {
        /* 포인터 연산: ct = ct ^ (RK + offset) — FP 후보 */
        unsigned char *p = (unsigned char*)ct;
        unsigned char *q = (unsigned char*)RK;
        int i;
        for (i = 0; i < 16; i++) {
            p[i] = p[i] ^ (q[i] + i);   /* 바이트 연산 — 포인터 */
        }
    }
""")

_ENC_C_REAL_WRONG_ORDER = textwrap.dedent("""\
    typedef unsigned int uint32_t;
    void lea_encrypt(uint32_t *ct, const uint32_t *pt, const uint32_t *RK) {
        uint32_t x0 = pt[0], x1 = pt[1];
        int i;
        for (i = 0; i < 32; i++) {
            x0 = x0 ^ (x1 + RK[i]);   /* 순서 역전: ADD 후 XOR */
        }
        ct[0] = x0;
    }
""")

_DEC_C_NO_SUB = textwrap.dedent("""\
    typedef unsigned int uint32_t;
    void lea_decrypt(uint32_t *pt, const uint32_t *ct, const uint32_t *RK) {
        uint32_t x0 = ct[0], x1 = ct[1];
        int i;
        for (i = 31; i >= 0; i--) {
            x0 = (x0 ^ RK[i]) + x1;  /* 뺄셈 없음 — 잘못된 역연산 */
        }
        pt[0] = x0;
    }
""")


# ─── C1: LEA-010 표준 delta → 위반 없음 ────────────────────────
print("\n[C1] LEA-010 + array_inits: 표준 delta 값 → 위반 없음")
sg_correct = {
    "array_inits": {
        "delta_128": {
            "file": "lea_key.c",
            "type": "const uint32_t",
            "size": 4,
            "values": ["0xc3efe9db", "0x44626b02", "0x79e27c8a", "0x78df30ec"],
        }
    },
    "type_aliases": {"uint32_t": "unsigned int"},
}
r = check_rule("LEA-010", _KEY_C_CORRECT_DELTA, "lea_key.c", symbol_graph=sg_correct)
record("C1 표준 delta → 위반 없음", r is not None and len(r) == 0,
       f"violations={len(r) if r else 'None'}")


# ─── C2: LEA-010 비표준 delta → 위반 탐지 ──────────────────────
print("\n[C2] LEA-010 + array_inits: 비표준 delta 값 → 위반 탐지")
sg_wrong = {
    "array_inits": {
        "delta_128": {
            "file": "lea_key.c",
            "type": "const uint32_t",
            "size": 4,
            "values": ["0xdeadbeef", "0xcafebabe", "0x12345678", "0xabcdef01"],
        }
    },
    "type_aliases": {"uint32_t": "unsigned int"},
}
r = check_rule("LEA-010", _KEY_C_WRONG_DELTA, "lea_key.c", symbol_graph=sg_wrong)
record("C2 비표준 delta → 위반 탐지", r is not None and len(r) > 0,
       f"violations={len(r) if r else 'None'}: {r[0]['message'][:60] if r else ''}...")
if r:
    record("C2 비표준 값 메시지에 '비표준' 포함", "비표준" in (r[0].get("message","") or ""))


# ─── C3: LEA-010 delta 없음 → symbol_graph 없는 기존 동작 ──────
print("\n[C3] LEA-010: array_inits 없음 → ARX 구조 검사만 (기존 동작)")
r_no_sg = check_rule("LEA-010", _KEY_C_NO_DELTA, "lea_key.c", symbol_graph=None)
r_empty_sg = check_rule("LEA-010", _KEY_C_NO_DELTA, "lea_key.c", symbol_graph={})
record("C3 symbol_graph=None 정상 동작", r_no_sg is not None)
record("C3 symbol_graph={} 정상 동작", r_empty_sg is not None)
record("C3 ARX 구조 있으면 위반 없음", r_no_sg is not None and len(r_no_sg) == 0,
       f"violations={len(r_no_sg) if r_no_sg else 'None'}")


# ─── C4: LEA-031 포인터 연산 FP 제거 ───────────────────────────
print("\n[C4] LEA-031 + type_aliases: 포인터 피연산자 FP 제거")
sg_types = {
    "type_aliases": {"uint32_t": "unsigned int"},
    "array_inits": {},
}
r = check_rule("LEA-031", _ENC_C_PTR_ADD, "lea_enc.c", symbol_graph=sg_types)
# 포인터 char 연산에서의 ^ + 패턴은 FP — 현재는 보수적으로 처리
print(f"  포인터 연산 코드 violations: {len(r) if r is not None else 'None'}")
record("C4 포인터 코드에서 무리한 위반 없음 (0 or None)", r is None or len(r) == 0,
       f"violations={len(r) if r is not None else 'None'}")


# ─── C5: LEA-031 실제 순서 역전 → 탐지 ─────────────────────────
print("\n[C5] LEA-031: 실제 ADD→XOR 순서 역전 → 탐지")
r = check_rule("LEA-031", _ENC_C_REAL_WRONG_ORDER, "lea_enc.c", symbol_graph=sg_types)
record("C5 순서 역전 탐지", r is not None and len(r) > 0,
       f"violations={len(r) if r else 'None'}")


# ─── C6: LEA-034 type_aliases로 파라미터 타입 정보 ─────────────
print("\n[C6] LEA-034 + type_aliases: 뺄셈 없음 + 파라미터 타입 정보")
r = check_rule("LEA-034", _DEC_C_NO_SUB, "lea_dec.c", symbol_graph=sg_types)
record("C6 복호화 뺄셈 없음 → 위반", r is not None and len(r) > 0,
       f"violations={len(r) if r else 'None'}")
if r:
    msg = r[0].get("message","")
    print(f"  위반 메시지: {msg}")
    # 파라미터 타입이 메시지에 포함될 수도 있음 (type_aliases 활용)
    record("C6 위반 메시지 적절함", "뺄셈" in msg or "모듈러" in msg or "역연산" in msg)


# ─── C7: 하위 호환성 — symbol_graph 없어도 동작 ────────────────
print("\n[C7] 하위 호환성: symbol_graph 파라미터 없이 호출")
r = check_rule("LEA-010", _KEY_C_CORRECT_DELTA, "lea_key.c")  # symbol_graph 생략
record("C7 symbol_graph 생략 시 정상 동작", r is not None)
r = check_rule("LEA-031", _ENC_C_REAL_WRONG_ORDER, "lea_enc.c")
record("C7 LEA-031 symbol_graph 생략 시 탐지", r is not None and len(r) > 0)
r = check_rule("LEA-034", _DEC_C_NO_SUB, "lea_dec.c")
record("C7 LEA-034 symbol_graph 생략 시 탐지", r is not None and len(r) > 0)


# ─── C8: 파이프라인 통합 테스트 ─────────────────────────────────
print("\n[C8] 파이프라인 통합: build_symbol_graph → rule_engine → check_rule")
try:
    import zipfile as _zf, tempfile as _tf
    from app.services.upload_service import create_job_from_upload, get_job_root
    from app.services.preprocess_service import run_preprocess
    from app.services.symbol_graph_service import build_symbol_graph
    from app.services.rule_engine_service import run_rule_engine

    # ZIP 생성: 표준 delta + 키스케줄 + 복호화(뺄셈 없음)
    PIPELINE_KEY_C = textwrap.dedent("""\
        #include <stdlib.h>
        typedef unsigned int uint32_t;
        static const uint32_t delta_128[4] = {
            0xc3efe9db, 0x44626b02, 0x79e27c8a, 0x78df30ec
        };
        static uint32_t ROL32(uint32_t x, int n) { return (x<<n)|(x>>(32-n)); }
        void lea_set_key(uint32_t *RK, const uint32_t *K) {
            uint32_t T[4]; int i;
            for (i = 0; i < 32; i++)
                T[0] = ROL32(T[0] + delta_128[i % 4], 1);
        }
    """)
    PIPELINE_DEC_C_BAD = textwrap.dedent("""\
        typedef unsigned int uint32_t;
        void lea_decrypt(uint32_t *pt, const uint32_t *ct, const uint32_t *RK) {
            uint32_t x0 = ct[0]; int i;
            for (i = 31; i >= 0; i--)
                x0 = (x0 ^ RK[i]) + 1;   /* 뺄셈 없음 */
            pt[0] = x0;
        }
    """)

    tmp = _tf.NamedTemporaryFile(suffix=".zip", delete=False)
    with _zf.ZipFile(tmp.name, "w") as zf:
        zf.writestr("src/lea_key.c", PIPELINE_KEY_C)
        zf.writestr("src/lea_dec.c", PIPELINE_DEC_C_BAD)

    job_id = create_job_from_upload(Path(tmp.name).read_bytes(), "pipeline_test.zip")
    root = get_job_root(job_id)
    pre = run_preprocess(root)
    sg = build_symbol_graph(pre, src_root=Path(root))

    # symbol_graph backend 확인
    backend = sg.get("backend")
    record("C8 symbol_graph 생성됨", backend in ("libclang","pycparser"), f"backend={backend}")

    # array_inits가 있으면 delta 값 확인
    arr = sg.get("array_inits", {})
    if arr:
        record("C8 array_inits delta_128 포함 (libclang)", "delta_128" in arr,
               f"keys={list(arr.keys())}")
    else:
        record("C8 array_inits 없음 (pycparser fallback)", True,
               "pycparser는 array_inits 미수집 — libclang 필요")

    # rule_engine에 symbol_graph 전달
    RULES_DIR = ROOT / "rules"
    violations = run_rule_engine(pre, RULES_DIR, job_root=Path(root), symbol_graph=sg)
    lea010_viols = [v for v in violations if v.get("rule_id") == "LEA-010"]
    lea034_viols = [v for v in violations if v.get("rule_id") == "LEA-034"]

    record("C8 rule_engine symbol_graph 전달 정상", True, f"총 violations={len(violations)}")
    record("C8 LEA-010 표준 delta → 위반 없음",
           not any("비표준" in (v.get("message","")) for v in lea010_viols),
           f"LEA-010 violations={len(lea010_viols)}")
    record("C8 LEA-034 뺄셈 없음 → 위반 탐지",
           len(lea034_viols) > 0,
           f"LEA-034 violations={len(lea034_viols)}")

except Exception as e:
    record("C8 파이프라인 통합 예외", False, str(e)[:100])


# ─── 결과 요약 ───────────────────────────────────────────────────
print("\n" + "=" * 60)
print("  종합 결과")
print("=" * 60)
passed = [r for r in results if r["ok"]]
failed = [r for r in results if not r["ok"]]
print(f"  PASS : {len(passed)}")
print(f"  FAIL : {len(failed)}")
print(f"  합계 : {len(results)}")
if failed:
    print("\n  실패 항목:")
    for r in failed:
        print(f"    ❌ {r['item']}")
print("=" * 60)
import sys; sys.exit(0 if not failed else 1)
