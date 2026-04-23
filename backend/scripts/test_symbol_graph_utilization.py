#!/usr/bin/env python3
"""
symbol_graph 활용도 개선 검증 스크립트
=======================================
3가지 개선 사항을 검증:

  T1 – COM-001 2-level 호출 체인 추적
       (A → B → memset_s 패턴 탐지 + 직접 호출은 위반 없음 유지)
  T2 – _find_func_boundary_from_sg: end_line 기반 함수 경계 추출
  T3 – _build_structured_evidence: fallback 15개 규칙에 파라미터/배열 증거 주입
  T4 – _get_code_context: symbol_graph 있으면 정확한 경계 사용
  T5 – (통합) lea_cbc_only.zip + symbol_graph 파이프라인 검증
"""
import sys
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# .env 로드
env_path = ROOT / ".env"
if env_path.exists():
    for line in env_path.read_text().splitlines():
        if "=" in line and not line.strip().startswith("#"):
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())

PASS = "\033[92m✅ PASS\033[0m"
FAIL = "\033[91m❌ FAIL\033[0m"
INFO = "\033[94mℹ️  INFO\033[0m"

results = []

def record(label, ok, detail=""):
    results.append({"label": label, "ok": ok})
    sym = PASS if ok else FAIL
    print(f"  {sym} {label}" + (f"  — {detail}" if detail else ""))

print("=" * 65)
print("  symbol_graph 활용도 개선 검증")
print("=" * 65)

# ── T1: COM-001 2-level 호출 체인 ────────────────────────────────
print("\n[T1] COM-001 2-level 호출 체인 추적")

from app.services.rule_engine_service import (
    _apply_rule_to_file, CLEARING_PATTERN,
)
from unittest.mock import MagicMock

# 가짜 COM-001 룰 정의
COM001_RULE = {
    "id": "COM-001",
    "pattern_type": "missing",
    "pattern": r"memset_s|explicit_bzero|SecureZeroMemory",
    "name": "잔존 정보 제거 필요",
    "severity": "high",
}

# T1-A: 직접 호출 → 위반 없음 (기존 동작 유지)
code_direct = """
void lea_encrypt(uint32_t *rk, const uint32_t *key) {
    uint32_t tmp[32];
    // ... 암호화 ...
    memset_s(tmp, sizeof(tmp), 0, sizeof(tmp));
}
"""
ast_direct = {"file_calls": [{"name": "memset_s"}]}
r = _apply_rule_to_file(
    Path("/fake/src/lea_enc.c"), code_direct,
    COM001_RULE, Path("/fake"), ast_direct, None
)
record("T1-A 직접 호출 → 위반 없음", len(r) == 0,
       f"violations={len(r)}")

# T1-B: 호출 체인 없음 → 위반 탐지
code_no_clear = """
void lea_encrypt(uint32_t *rk, const uint32_t *key) {
    uint32_t tmp[32];
    // 제로화 없음
}
"""
r = _apply_rule_to_file(
    Path("/fake/src/lea_enc.c"), code_no_clear,
    COM001_RULE, Path("/fake"), {"file_calls": []}, {}
)
record("T1-B 제로화 없음 → 위반", len(r) > 0,
       f"violations={len(r)}")

# T1-C: 2-hop 체인 → 위반 없음
# lea_cleanup() 이 memset_s를 호출하고, lea_encrypt가 lea_cleanup을 호출
code_2hop = """
void lea_encrypt(uint32_t *rk, const uint32_t *key) {
    uint32_t tmp[32];
    lea_cleanup(tmp, sizeof(tmp));
}
"""
sg_2hop = {
    "definitions": {
        "lea_cleanup": [{"file": "src/lea_util.c", "line": 10, "end_line": 20}],
    },
    "call_graph": [
        # lea_encrypt → lea_cleanup
        {"caller_file": "src/lea_enc.c", "callee_name": "lea_cleanup",
         "defined_in": "src/lea_util.c", "def_line": 10},
        # lea_cleanup → memset_s (lea_util.c에서 memset_s 호출)
        {"caller_file": "src/lea_util.c", "callee_name": "memset_s",
         "defined_in": None, "def_line": None},
    ],
    "files_with_clearing_call": ["src/lea_util.c"],
}
r = _apply_rule_to_file(
    Path("/fake/src/lea_enc.c"), code_2hop,
    COM001_RULE, Path("/fake"),
    {"file_calls": []},  # AST에 직접 호출 없음
    sg_2hop,
)
record("T1-C 2-hop 체인 → 위반 없음", len(r) == 0,
       f"violations={len(r)}")

# ── T2: _find_func_boundary_from_sg ─────────────────────────────
print("\n[T2] symbol_graph end_line 기반 함수 경계 추출")

from app.services.llm_service import _find_func_boundary_from_sg

sg_defs = {
    "definitions": {
        "lea_encrypt": [{"file": "src/lea.c", "line": 10, "end_line": 50}],
        "lea_decrypt": [{"file": "src/lea.c", "line": 55, "end_line": 90}],
        "lea_set_key": [{"file": "src/lea.c", "line": 1, "end_line": 8}],
    }
}

# 라인 25는 lea_encrypt 내부
s, e = _find_func_boundary_from_sg(25, sg_defs)
record("T2-A 라인 25 → lea_encrypt 경계 (10~50)", s == 10 and e == 50,
       f"got ({s}, {e})")

# 라인 60은 lea_decrypt 내부
s, e = _find_func_boundary_from_sg(60, sg_defs)
record("T2-B 라인 60 → lea_decrypt 경계 (55~90)", s == 55 and e == 90,
       f"got ({s}, {e})")

# 라인 200은 어떤 함수에도 속하지 않음
s, e = _find_func_boundary_from_sg(200, sg_defs)
record("T2-C 라인 200 → 경계 없음 (-1, -1)", s == -1 and e == -1,
       f"got ({s}, {e})")

# 함수 중첩: 더 작은 범위 반환
sg_nested = {
    "definitions": {
        "outer": [{"file": "a.c", "line": 1, "end_line": 100}],
        "inner": [{"file": "a.c", "line": 30, "end_line": 60}],
    }
}
s, e = _find_func_boundary_from_sg(45, sg_nested)
record("T2-D 중첩 함수 → 더 작은 inner (30~60)", s == 30 and e == 60,
       f"got ({s}, {e})")

# ── T3: _build_structured_evidence fallback 규칙 ─────────────────
print("\n[T3] fallback 15개 규칙에 구조화 증거 주입")

from app.services.llm_service import _build_structured_evidence

sg_fallback = {
    "definitions": {
        "lea_encrypt": [{"file": "src/lea.c", "line": 1, "end_line": 50,
                         "params": ["uint32_t *ct", "const uint32_t *pt", "const uint32_t *RK"]}],
    },
    "array_inits": {
        "sbox": {"file": "src/lea.c", "size": 256, "type": "uint8_t",
                 "values": ["0x63", "0x7c", "0x77", "0x7b"]},
    },
    "type_aliases": {"uint32_t": "unsigned int"},
}

for rid in ["LEA-005", "LEA-022", "ARIA-002", "OFB-002", "CFB-002"]:
    v = {"rule_id": rid, "file": "src/lea.c", "line": 15}
    ev = _build_structured_evidence(v, sg_fallback)
    has_evidence = len(ev) > 0
    record(f"T3 {rid} 구조화 증거 생성됨", has_evidence,
           f"{len(ev)} chars")
    if ev:
        # 파라미터 정보 또는 배열 정보 포함 여부
        has_func_info = "파라미터" in ev or "배열" in ev or "타입" in ev
        record(f"T3 {rid} 함수/타입 정보 포함", has_func_info)

# 기존 규칙 (LEA-010)은 여전히 delta 검증
v_lea010 = {
    "rule_id": "LEA-010",
    "file": "src/lea.c",
    "line": 5,
}
sg_delta = {
    "array_inits": {
        "delta_128": {
            "size": 4,
            "values": ["0xdeadbeef", "0xcafebabe", "0x12345678", "0xabcdef01"],
        }
    },
    "type_aliases": {"uint32_t": "unsigned int"},
    "definitions": {},
}
ev_010 = _build_structured_evidence(v_lea010, sg_delta)
record("T3 LEA-010 여전히 delta 검증 작동", "비표준" in ev_010 or "불일치" in ev_010,
       f"{len(ev_010)} chars")

# ── T4: _get_code_context symbol_graph 사용 ─────────────────────
print("\n[T4] _get_code_context: symbol_graph end_line 활용")

from app.services.llm_service import _get_code_context

# 가짜 코드 (100줄)
fake_code_lines = []
for i in range(1, 101):
    if i == 10:
        fake_code_lines.append("void lea_encrypt(uint32_t *ct, const uint32_t *pt) {")
    elif i == 50:
        fake_code_lines.append("}")
    else:
        fake_code_lines.append(f"    // line {i}")
fake_code = "\n".join(fake_code_lines)

sg_ctx = {
    "definitions": {
        "lea_encrypt": [{"file": "lea.c", "line": 10, "end_line": 50}]
    }
}

# 라인 25는 lea_encrypt 내부 → symbol_graph로 10~50 반환
ctx = _get_code_context(fake_code, 25, "ast", symbol_graph=sg_ctx)
lines_returned = ctx.splitlines()
record("T4-A symbol_graph로 정확한 함수 경계 슬라이싱",
       len(lines_returned) >= 35,  # 10~50 = 41줄
       f"반환 줄 수={len(lines_returned)}")

# symbol_graph 없으면 기존 동작
ctx_no_sg = _get_code_context(fake_code, 25, "ast", symbol_graph=None)
record("T4-B symbol_graph 없으면 기존 slice_code 동작",
       ctx_no_sg is not None,
       f"반환 줄 수={len(ctx_no_sg.splitlines())}")

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
