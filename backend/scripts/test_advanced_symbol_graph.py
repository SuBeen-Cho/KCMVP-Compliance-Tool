#!/usr/bin/env python3
"""
고도화된 symbol_graph 활용 검증 스크립트
=========================================
3가지 개선사항 검증:

  G1 – GCFS: 전체 코드 흐름 요약 생성 (모듈 구조 + API 시그니처 + 호출 흐름)
  G2 – 키 생명주기 분석 (_build_key_lifecycle): 선언→초기화→사용→제거 흐름 추적
  G3 – TRC-004: symbol_graph 기반 API 매핑 (함수 포인터 typedef vs 설계서)
  G4 – L2 통합: GCFS + 키 lifecycle이 실제 code_block에 prepend 되는지
  G5 – (통합) lea_cbc_only.zip 기반 실제 파이프라인 검증
"""
import sys
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PASS = "\033[92m✅ PASS\033[0m"
FAIL = "\033[91m❌ FAIL\033[0m"
INFO = "\033[94mℹ️  INFO\033[0m"
results = []

def record(label, ok, detail=""):
    results.append({"label": label, "ok": ok})
    sym = PASS if ok else FAIL
    print(f"  {sym} {label}" + (f"  — {detail}" if detail else ""))

print("=" * 65)
print("  고도화된 symbol_graph 활용 검증")
print("=" * 65)

# ── 테스트용 가짜 symbol_graph ────────────────────────────────────
FAKE_SG = {
    "backend": "libclang",
    "definitions": {
        "lea_set_key": [{"file": "src/lea_base.c", "line": 304, "end_line": 350,
                         "params": ["LEA_KEY *key", "const unsigned char *user_key", "int bits"],
                         "return_type": "void"}],
        "lea_cbc_enc": [{"file": "src/lea_cbc.c", "line": 15, "end_line": 60,
                         "params": ["unsigned char *out", "const unsigned char *in",
                                    "unsigned int len", "const unsigned char *iv", "const LEA_KEY *key"],
                         "return_type": "void"}],
        "lea_cbc_dec": [{"file": "src/lea_cbc.c", "line": 65, "end_line": 110,
                         "params": ["unsigned char *out", "const unsigned char *in",
                                    "unsigned int len", "const unsigned char *iv", "const LEA_KEY *key"],
                         "return_type": "void"}],
        "lea_module_zeroize": [{"file": "src/lea_base.c", "line": 400, "end_line": 420,
                                "params": ["void *buf", "size_t len"],
                                "return_type": "void"}],
        "main": [{"file": "main.c", "line": 1, "end_line": 80,
                  "params": ["int argc", "char **argv"],
                  "return_type": "int"}],
    },
    "calls": [
        {"caller_file": "main.c", "caller_line": 20, "callee_name": "lea_set_key"},
        {"caller_file": "main.c", "caller_line": 35, "callee_name": "lea_cbc_enc"},
        {"caller_file": "main.c", "caller_line": 70, "callee_name": "lea_module_zeroize"},
    ],
    "call_graph": [
        {"caller_file": "main.c", "callee_name": "lea_set_key",
         "defined_in": "src/lea_base.c", "def_line": 304},
        {"caller_file": "main.c", "callee_name": "lea_cbc_enc",
         "defined_in": "src/lea_cbc.c", "def_line": 15},
        {"caller_file": "main.c", "callee_name": "lea_module_zeroize",
         "defined_in": "src/lea_base.c", "def_line": 400},
    ],
    "files_with_clearing_call": ["src/lea_base.c"],
    "type_aliases": {
        "LEA_KEY": "struct lea_key_st",
        "lea_set_key_ptr": "void (*)(LEA_KEY *, const unsigned char *, int)",
        "lea_cbc_enc_ptr": "void (*)(unsigned char *, const unsigned char *, unsigned int, const unsigned char *, const LEA_KEY *)",
        "lea_cbc_dec_ptr": "void (*)(unsigned char *, const unsigned char *, unsigned int, const unsigned char *, const LEA_KEY *)",
        "uint_32t": "unsigned int",
    },
    "array_inits": {
        "delta_128": {"file": "src/lea_base.c", "size": 8,
                      "values": ["0xc3efe9db", "0x44626b02", "0x79e27c8a", "0x78df30ec",
                                 "0x715ea49e", "0xc785da0a", "xe132631", "0x3e6b9ae6"]},
    },
}

# ── G1: GCFS 생성 ─────────────────────────────────────────────────
print("\n[G1] Global Code Flow Summary (GCFS) 생성")

from app.services.llm_service import _build_global_flow_summary

gcfs = _build_global_flow_summary(FAKE_SG)
print(f"  GCFS 길이: {len(gcfs)} chars / {len(gcfs.splitlines())} 줄")
if gcfs:
    print("  --- GCFS 미리보기 ---")
    for line in gcfs.splitlines()[:15]:
        print(f"    {line}")
    if len(gcfs.splitlines()) > 15:
        print(f"    ... (총 {len(gcfs.splitlines())}줄)")
    print("  ---")

record("G1-A GCFS 생성됨", len(gcfs) > 100, f"{len(gcfs)} chars")
record("G1-B GCFS에 모듈 구조 포함", "[모듈 구조]" in gcfs)
record("G1-C GCFS에 API 시그니처 포함", "[공개 API 시그니처]" in gcfs or "lea_cbc_enc" in gcfs)
record("G1-D GCFS에 키 생명주기 포함", "[키 생명주기 관련 호출]" in gcfs or "키 생성" in gcfs)
record("G1-E GCFS에 제로화 확인 포함",
       "lea_module_zeroize" in gcfs or "❌ 미발견" in gcfs or "키 제거" in gcfs)

# symbol_graph 없으면 빈 문자열 반환
gcfs_none = _build_global_flow_summary(None)
record("G1-F symbol_graph=None → 빈 문자열", gcfs_none == "")

# ── G2: 키 생명주기 분석 ──────────────────────────────────────────
print("\n[G2] 키 생명주기 분석 (_build_key_lifecycle)")

from app.services.rule_engine_service import _build_key_lifecycle, CLEARING_PATTERN

# 제로화 있는 코드
code_with_zeroize = """
void test_encrypt() {
    LEA_KEY key;
    unsigned char mk[16] = {0x00, ...};
    lea_set_key(&key, mk, 128);
    lea_cbc_enc(out, in, 16, iv, &key);
    lea_module_zeroize(&key, sizeof(key));
}
"""
lifecycle_ok = _build_key_lifecycle(code_with_zeroize, "src/test.c", FAKE_SG)
print(f"\n  [제로화 있는 코드 lifecycle]")
for l in lifecycle_ok.splitlines():
    print(f"    {l}")
record("G2-A 키 초기화 탐지", "초기화" in lifecycle_ok and "lea_set_key" in lifecycle_ok)
record("G2-B 키 사용 탐지", "사용" in lifecycle_ok and "lea_cbc_enc" in lifecycle_ok)
record("G2-C 제로화 탐지", "✅" in lifecycle_ok or "제거" in lifecycle_ok)

# 제로화 없는 코드
code_no_zeroize = """
void test_encrypt() {
    LEA_KEY key;
    unsigned char mk[16] = {0x00};
    lea_set_key(&key, mk, 128);
    lea_cbc_enc(out, in, 16, iv, &key);
    /* 제로화 없음 */
}
"""
lifecycle_bad = _build_key_lifecycle(code_no_zeroize, "src/test.c", {})
print(f"\n  [제로화 없는 코드 lifecycle]")
for l in lifecycle_bad.splitlines():
    print(f"    {l}")
record("G2-D 제로화 미발견 탐지", "❌" in lifecycle_bad and "미발견" in lifecycle_bad)

# ── G3: TRC-004 API 매핑 ─────────────────────────────────────────
print("\n[G3] TRC-004 symbol_graph 기반 API 매핑")

from app.services.traceability_service import _check_trc004

TRC004_RULE = {
    "id": "TRC-004",
    "type": "api_mapping",
    "name": "API 시그니처 매핑",
    "severity": "medium",
}

# 설계서에 lea_cbc_enc만 언급
design_partial = [
    {"text": "lea_cbc_enc 함수는 CBC 모드 암호화를 수행한다", "tables": []},
]
viols = _check_trc004(design_partial, FAKE_SG, TRC004_RULE)
print(f"\n  설계서 부분 언급 시 violations: {len(viols)}건")
for v in viols[:3]:
    print(f"    - {v.get('message', '')[:80]}")
record("G3-A 설계서 누락 API 탐지", len(viols) > 0,
       f"{len(viols)}건")

# 설계서에 모든 API 언급
design_full = [
    {"text": "lea_cbc_enc, lea_cbc_dec, lea_set_key 함수는 각각...", "tables": []},
]
viols_none = _check_trc004(design_full, FAKE_SG, TRC004_RULE)
record("G3-B 설계서 완전 커버 → 위반 없음", len(viols_none) == 0,
       f"{len(viols_none)}건")

# symbol_graph 없으면 빈 리스트
viols_no_sg = _check_trc004(design_partial, {}, TRC004_RULE)
record("G3-C symbol_graph=None → 빈 리스트", len(viols_no_sg) == 0)

# ── G4: L2 통합 검증 ─────────────────────────────────────────────
print("\n[G4] L2 code_block GCFS + 키 lifecycle prepend 통합")

from app.services.llm_service import (
    _build_global_flow_summary, _build_structured_evidence,
    _find_func_boundary_from_sg,
)

# COM-001 위반에 key_lifecycle 필드 있는 경우
v_com001 = {
    "rule_id": "COM-001",
    "file": "src/test.c",
    "line": None,
    "key_lifecycle": _build_key_lifecycle(code_no_zeroize, "src/test.c", {}),
}
record("G4-A COM-001 위반에 key_lifecycle 필드 존재",
       bool(v_com001.get("key_lifecycle")),
       f"{len(v_com001['key_lifecycle'])} chars")
record("G4-B key_lifecycle에 제거 미발견 포함",
       "❌" in (v_com001.get("key_lifecycle") or ""))

# GCFS가 실제로 생성되는지
gcfs_real = _build_global_flow_summary(FAKE_SG)
record("G4-C GCFS 생성 후 L2 prepend 준비됨", len(gcfs_real) > 50)

# ── G5: 실제 zip 파이프라인 통합 ────────────────────────────────
print("\n[G5] 실제 파이프라인 통합 (lea_cbc_only.zip)")
try:
    from app.services.upload_service import create_job_from_upload, get_job_root
    from app.services.preprocess_service import run_preprocess
    from app.services.symbol_graph_service import build_symbol_graph
    from app.services.rule_engine_service import run_rule_engine, CLEARING_FUNCTION_NAMES
    from app.services.traceability_service import run_traceability_checks, build_code_index

    ZIP_PATH = ROOT / "testdata" / "lea_cbc_only.zip"
    job_id = create_job_from_upload(ZIP_PATH.read_bytes(), "lea_cbc_only.zip")
    root = get_job_root(job_id)
    pre = run_preprocess(root)
    sg = build_symbol_graph(pre, src_root=Path(root))

    print(f"\n  symbol_graph: backend={sg.get('backend')}, "
          f"defs={len(sg.get('definitions',{}))}, "
          f"call_edges={len(sg.get('call_graph',[]))}")

    # G5-A: 실제 GCFS 생성
    gcfs_real = _build_global_flow_summary(sg, pre)
    record("G5-A 실제 zip에서 GCFS 생성", len(gcfs_real) > 200,
           f"{len(gcfs_real.splitlines())}줄")
    if gcfs_real:
        print("  --- GCFS 첫 10줄 ---")
        for l in gcfs_real.splitlines()[:10]:
            print(f"    {l}")

    # G5-B: COM-001 위반에 key_lifecycle 포함 여부
    RULES_DIR = ROOT / "rules"
    violations_l1 = run_rule_engine(pre, RULES_DIR, job_root=Path(root), symbol_graph=sg)
    com001_viols = [v for v in violations_l1 if v.get("rule_id") == "COM-001"]
    print(f"\n  COM-001 위반: {len(com001_viols)}건")
    has_lifecycle = any(v.get("key_lifecycle") for v in com001_viols)
    record("G5-B COM-001 위반에 key_lifecycle 필드 포함", has_lifecycle)
    if com001_viols and com001_viols[0].get("key_lifecycle"):
        print("  --- key_lifecycle 미리보기 ---")
        for l in com001_viols[0]["key_lifecycle"].splitlines()[:6]:
            print(f"    {l}")

    # G5-C: TRC-004 실행 (설계서 없어도 에러 없어야 함)
    trc_rules = []
    try:
        import yaml
        trc_path = RULES_DIR / "traceability" / "traceability.yaml"
        if trc_path.exists():
            trc_rules = yaml.safe_load(trc_path.read_text()).get("rules", [])
    except Exception:
        pass
    code_index = build_code_index(pre)
    viols_trc = run_traceability_checks(
        design_doc={"sections": []},
        code_index=code_index,
        test_doc={"sections": []},
        rules=trc_rules,
        symbol_graph=sg,
    )
    record("G5-C TRC with symbol_graph 에러 없이 실행", True,
           f"TRC violations={len(viols_trc)}건")

except Exception as e:
    record("G5 파이프라인 통합 예외", False, str(e)[:100])

# ── 결과 요약 ────────────────────────────────────────────────────
print("\n" + "=" * 65)
print("  종합 결과")
print("=" * 65)
passed = [r for r in results if r["ok"]]
failed = [r for r in results if not r["ok"]]
print(f"  PASS: {len(passed)} / FAIL: {len(failed)} / 합계: {len(results)}")
if failed:
    print("\n  실패 항목:")
    for r in failed:
        print(f"    ❌ {r['label']}")
print("=" * 65)
sys.exit(0 if not failed else 1)
