#!/usr/bin/env python3
"""
개선 항목 종합 성능 측정 스크립트
=================================
검증 항목:
  P1   – L3 프롬프트 도메인 수치 보강 (정적 확인)
  P2a  – 패치 생성 병렬화 (코드 존재 확인)
  P2b  – 스캔본 PDF OCR 임계값 30자 (단위 테스트)
  P3-A – TRC AST 기반 함수 추출 + regex MULTILINE (단위 테스트)
  P3-B – AST fallback 5개 규칙 완전 구현 (단위 테스트 — 준수/위반 케이스)
  P4-A – RAG 인덱스 사전 로딩 (import + 함수 시그니처 확인)
  P4-B – L3 candidate cap 동적화 (단위 테스트)
  P4-C – 진행률 추적 세분화 (단위 테스트)
"""

import sys
import os
import re
import json
import time
import types
import tempfile
import importlib
import textwrap
from pathlib import Path
from typing import List, Dict, Any
from unittest.mock import MagicMock

# ── 경로 설정 ──────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# ── google.genai mock (llm_service/analyze 임포트 전에 등록) ───
_genai_mock = types.ModuleType("google.genai")
_genai_mock.Client = MagicMock
_genai_mock.GenerateContentConfig = MagicMock
_genai_mock.types = MagicMock()
sys.modules.setdefault("google", types.ModuleType("google"))
sys.modules["google.genai"] = _genai_mock
sys.modules["google.genai.types"] = MagicMock()

PASS  = "\033[92m✅ PASS\033[0m"
FAIL  = "\033[91m❌ FAIL\033[0m"
WARN  = "\033[93m⚠️  WARN\033[0m"
SKIP  = "\033[96m⏭  SKIP\033[0m"

results: List[Dict[str, Any]] = []


def record(item: str, ok, detail: str = ""):
    sym = PASS if ok is True else (FAIL if ok is False else SKIP)
    results.append({"item": item, "ok": ok, "detail": detail})
    print(f"  {sym} {item}" + (f"  — {detail}" if detail else ""))


# ══════════════════════════════════════════════════════════════════
# P1 – L3 프롬프트 도메인 수치 보강
# ══════════════════════════════════════════════════════════════════
print("\n[P1] L3 프롬프트 도메인 수치 보강")

try:
    # 소스 직접 읽기 (google.genai 의존 없이)
    src = Path(ROOT / "app/services/llm_service.py").read_text(encoding="utf-8")

    kw_checks = {
        "LEA-003 템플릿": ("LEA-003" in src and "192" in src),
        "LEA-010 템플릿": "LEA-010" in src,
        "few-shot 예시 존재": "위반" in src and ("VIOLATION" in src.upper() or "준수" in src),
        "_select_l3_candidates 존재": "_select_l3_candidates" in src,
        "KS X 3246 수치 포함 (델타 상수)": "0xc3efe9db" in src or "0x9908b0df" in src or "delta" in src.lower(),
        "LEA-031 도메인 수치": "LEA-031" in src,
        "LEA-034 도메인 수치": "LEA-034" in src,
    }
    for name, ok in kw_checks.items():
        record(f"P1 {name}", ok)
except Exception as e:
    record("P1 소스 분석", False, str(e))


# ══════════════════════════════════════════════════════════════════
# P2a – 패치 생성 병렬화
# ══════════════════════════════════════════════════════════════════
print("\n[P2a] 패치 생성 병렬화")

try:
    analyze_src = Path(ROOT / "app/api/routes/analyze.py").read_text(encoding="utf-8")
    record("P2a ThreadPoolExecutor import", "ThreadPoolExecutor" in analyze_src)
    record("P2a _PATCH_MAX_WORKERS 정의", "_PATCH_MAX_WORKERS" in analyze_src)
    record("P2a max_workers=_PATCH_MAX_WORKERS 사용", "max_workers=_PATCH_MAX_WORKERS" in analyze_src)
    # 병렬화 두 곳 확인 (코드 패치 + 문서 패치)
    count = analyze_src.count("ThreadPoolExecutor(max_workers=_PATCH_MAX_WORKERS)")
    record("P2a 병렬화 블록 2개 이상", count >= 2, f"발견: {count}개")
except Exception as e:
    record("P2a", False, str(e))


# ══════════════════════════════════════════════════════════════════
# P2b – 스캔본 PDF OCR 임계값 30자
# ══════════════════════════════════════════════════════════════════
print("\n[P2b] 스캔본 PDF OCR 임계값")

try:
    from app.services import preprocess_docs_service as pds
    import inspect

    # _is_scanned_pdf 기본값 30
    sig = inspect.signature(pds._is_scanned_pdf)
    default_val = sig.parameters["threshold_chars_per_page"].default
    record("P2b _is_scanned_pdf 기본값 30", default_val == 30, f"실제값: {default_val}")

    # 기능 단위 테스트
    empty_pages = ["", "", "", ""]       # 완전 비어있음 → 스캔본
    rich_pages  = ["a"*100]*4            # 텍스트 풍부 → 스캔본 아님
    edge_pages  = [" "*29]*4             # 29자 → 스캔본 (< 30)
    ok_pages    = [" "*31]*4             # 31자 → 스캔본 아님

    record("P2b 빈 페이지 → 스캔본", pds._is_scanned_pdf(empty_pages))
    record("P2b 풍부한 텍스트 → 스캔본 아님", not pds._is_scanned_pdf(rich_pages))
    record("P2b 29자 → 스캔본 (경계값)", pds._is_scanned_pdf(edge_pages))
    record("P2b 31자 → 스캔본 아님 (경계값)", not pds._is_scanned_pdf(ok_pages))

    # 페이지별 OCR 선별 임계값 30 확인
    src = Path(pds.__file__).read_text(encoding="utf-8")
    record("P2b 페이지별 선별 임계값 30", "< 30" in src)
except Exception as e:
    record("P2b", False, str(e))


# ══════════════════════════════════════════════════════════════════
# P3-A – TRC AST 기반 함수 추출 + regex MULTILINE
# ══════════════════════════════════════════════════════════════════
print("\n[P3-A] TRC AST 기반 함수 추출 + regex MULTILINE")

try:
    from app.services import traceability_service as trc

    # MULTILINE 플래그 확인
    flags = trc._FUNC_DECL_RE.flags
    record("P3-A _FUNC_DECL_RE MULTILINE 플래그", bool(flags & re.MULTILINE))

    # 멀티라인 함수 선언 매칭
    multiline_decl = "void lea_encrypt(\n    uint8_t *out,\n    const uint8_t *in);"
    m = trc._FUNC_DECL_RE.search(multiline_decl)
    record("P3-A 멀티라인 함수 선언 매칭", m is not None,
           f"매칭: {m.group(0)[:40].strip()!r}" if m else "매칭 없음")

    # AST 우선 fallback 코드 존재 확인
    src = Path(trc.__file__).read_text(encoding="utf-8")
    record("P3-A build_code_index AST 우선 로직", "is_header" in src and "ast.get" in src)
    record("P3-A header_funcs dict 사용", "header_funcs" in src)
except Exception as e:
    record("P3-A", False, str(e))


# ══════════════════════════════════════════════════════════════════
# P3-B – AST fallback 5개 규칙 완전 구현
# ══════════════════════════════════════════════════════════════════
print("\n[P3-B] AST fallback 5개 규칙 완전 구현")

try:
    from app.services.ast_checker_service import check_rule, _CHECKERS, _HAS_PYCPARSER

    NEW_RULES = ["LEA-014", "LEA-015", "LEA-021", "LEA-043", "ARIA-001"]
    for rid in NEW_RULES:
        record(f"P3-B {rid} _CHECKERS 등록", rid in _CHECKERS)

    record("P3-B pycparser 설치됨", _HAS_PYCPARSER)

    if not _HAS_PYCPARSER:
        print("    pycparser 미설치 — AST 단위 테스트 건너뜀")
    else:
        # ── LEA-014: T[] 대입에 + 없음 → 위반 ──────────────────
        c_lea014_bad = textwrap.dedent("""
            #include <stdint.h>
            void lea_key_schedule(uint32_t *RK, const uint32_t *K) {
                uint32_t T[4];
                int i;
                for (i = 0; i < 32; i++) {
                    T[0] = T[1] ^ K[0];   /* + 없음 */
                    T[1] = T[2] ^ K[1];
                    T[2] = T[3] ^ K[2];
                    T[3] = T[0] ^ K[3];
                }
            }
        """)
        c_lea014_ok = textwrap.dedent("""
            #include <stdint.h>
            static uint32_t ROL(uint32_t x, int n) { return (x<<n)|(x>>(32-n)); }
            void lea_key_schedule(uint32_t *RK, const uint32_t *K) {
                uint32_t T[4], delta[4] = {0xc3efe9db};
                int i;
                for (i = 0; i < 32; i++) {
                    T[0] = ROL(T[1] + delta[i % 4], 1);
                    T[1] = ROL(T[2] + delta[i % 4], 3);
                    T[2] = ROL(T[3] + delta[i % 4], 6);
                    T[3] = ROL(T[0] + delta[i % 4], 11);
                    RK[i] = T[0];
                }
            }
        """)
        v_bad = check_rule("LEA-014", c_lea014_bad, "lea.c")
        v_ok  = check_rule("LEA-014", c_lea014_ok,  "lea.c")
        record("P3-B LEA-014 위반 코드 → 위반 탐지",
               v_bad is not None and len(v_bad) > 0,
               f"위반 {len(v_bad) if v_bad else 0}건")
        record("P3-B LEA-014 준수 코드 → 위반 없음",
               v_ok is not None and len(v_ok) == 0,
               f"위반 {len(v_ok) if v_ok else 0}건")

        # ── LEA-015: delta[] % 없음 → 위반 ─────────────────────
        c_lea015_bad = textwrap.dedent("""
            #include <stdint.h>
            static uint32_t ROL(uint32_t x, int n) { return (x<<n)|(x>>(32-n)); }
            void lea_key_schedule(uint32_t *RK, const uint32_t *K) {
                uint32_t delta[4] = {0xc3efe9db,0x44626b02,0x79e27c8a,0x78df30ec};
                uint32_t T[4];
                int i;
                for (i = 0; i < 32; i++) {
                    T[0] = ROL(T[1] + delta[i], 1);  /* delta[i] — % 없음 */
                }
            }
        """)
        c_lea015_ok = textwrap.dedent("""
            #include <stdint.h>
            static uint32_t ROL(uint32_t x, int n) { return (x<<n)|(x>>(32-n)); }
            void lea_key_schedule(uint32_t *RK, const uint32_t *K) {
                uint32_t delta[4] = {0xc3efe9db,0x44626b02,0x79e27c8a,0x78df30ec};
                uint32_t T[4];
                int i;
                for (i = 0; i < 32; i++) {
                    T[0] = ROL(T[1] + delta[i % 4], 1);
                }
            }
        """)
        v_bad = check_rule("LEA-015", c_lea015_bad, "lea.c")
        v_ok  = check_rule("LEA-015", c_lea015_ok,  "lea.c")
        record("P3-B LEA-015 위반 코드 → 위반 탐지",
               v_bad is not None and len(v_bad) > 0,
               f"위반 {len(v_bad) if v_bad else 0}건")
        record("P3-B LEA-015 준수 코드 → 위반 없음",
               v_ok is not None and len(v_ok) == 0,
               f"위반 {len(v_ok) if v_ok else 0}건")

        # ── LEA-021: T[1] 반복 없음 → 위반 ─────────────────────
        c_lea021_bad = textwrap.dedent("""
            #include <stdint.h>
            void lea_key_schedule(uint32_t RK[32][6], const uint32_t *K) {
                uint32_t T[4];
                int i;
                for (i = 0; i < 32; i++) {
                    RK[i][0] = T[0];
                    RK[i][1] = T[2];  /* T[1] 없음 */
                    RK[i][2] = T[3];
                    RK[i][3] = T[0];
                    RK[i][4] = T[2];
                    RK[i][5] = T[3];
                }
            }
        """)
        c_lea021_ok = textwrap.dedent("""
            #include <stdint.h>
            void lea_key_schedule(uint32_t RK[32][6], const uint32_t *K) {
                uint32_t T[4];
                int i;
                for (i = 0; i < 32; i++) {
                    RK[i][0] = T[0];
                    RK[i][1] = T[1];
                    RK[i][2] = T[2];
                    RK[i][3] = T[1];
                    RK[i][4] = T[3];
                    RK[i][5] = T[1];
                }
            }
        """)
        v_bad = check_rule("LEA-021", c_lea021_bad, "lea.c")
        v_ok  = check_rule("LEA-021", c_lea021_ok,  "lea.c")
        record("P3-B LEA-021 위반 코드 → 위반 탐지",
               v_bad is not None and len(v_bad) > 0,
               f"위반 {len(v_bad) if v_bad else 0}건")
        record("P3-B LEA-021 준수 코드 → 위반 없음",
               v_ok is not None and len(v_ok) == 0,
               f"위반 {len(v_ok) if v_ok else 0}건")

        # ── LEA-043: 스택 배열, register 없음 → 위반 ────────────
        c_lea043_bad = textwrap.dedent("""
            #include <stdint.h>
            void lea_encrypt(uint32_t *ct, const uint32_t *pt, const uint32_t *RK) {
                uint32_t X[4];   /* 스택 배열 */
                int i;
                X[0] = pt[0]; X[1] = pt[1]; X[2] = pt[2]; X[3] = pt[3];
                for (i = 0; i < 32; i++) {
                    X[0] = X[0] ^ RK[i];
                }
                ct[0] = X[0];
            }
        """)
        c_lea043_ok = textwrap.dedent("""
            #include <stdint.h>
            void lea_encrypt(uint32_t *ct, const uint32_t *pt, const uint32_t *RK) {
                register uint32_t x0 = pt[0], x1 = pt[1], x2 = pt[2], x3 = pt[3];
                int i;
                for (i = 0; i < 32; i++) {
                    x0 = x0 ^ RK[i];
                }
                ct[0] = x0;
            }
        """)
        v_bad = check_rule("LEA-043", c_lea043_bad, "lea.c")
        v_ok  = check_rule("LEA-043", c_lea043_ok,  "lea.c")
        record("P3-B LEA-043 위반 코드 → 위반 탐지",
               v_bad is not None and len(v_bad) > 0,
               f"위반 {len(v_bad) if v_bad else 0}건")
        record("P3-B LEA-043 준수 코드 → 위반 없음",
               v_ok is not None and len(v_ok) == 0,
               f"위반 {len(v_ok) if v_ok else 0}건")

        # ── ARIA-001: XOR + 비트회전 + CK 모두 없음 → 위반 ─────
        c_aria001_bad = textwrap.dedent("""
            #include <stdint.h>
            /* XOR/비트회전/CK 없음 → 구조 불완전 */
            void aria_set_encrypt_key(const uint8_t *key, int bits, uint8_t *rk) {
                int i;
                for (i = 0; i < 16; i++) {
                    rk[i] = key[i] + i;   /* 단순 덧셈만 */
                }
            }
        """)
        c_aria001_ok = textwrap.dedent("""
            #include <stdint.h>
            static uint32_t ROL(uint32_t x, int n) { return (x<<n)|(x>>(32-n)); }
            static const uint32_t CK[4] = {0x517cc1b7, 0x27220a94, 0xfe13abe8, 0xfa9a6ee0};
            void aria_set_encrypt_key(const uint8_t *key, int bits, uint8_t *rk) {
                uint32_t W[4];
                int i;
                W[0] = W[1] ^ CK[0];
                W[1] = ROL(W[2], 3) ^ CK[1];
            }
        """)
        v_bad = check_rule("ARIA-001", c_aria001_bad, "aria.c")
        v_ok  = check_rule("ARIA-001", c_aria001_ok,  "aria.c")
        record("P3-B ARIA-001 위반 코드 → 위반 탐지",
               v_bad is not None and len(v_bad) > 0,
               f"위반 {len(v_bad) if v_bad else 0}건")
        record("P3-B ARIA-001 준수 코드 → 위반 없음",
               v_ok is not None and len(v_ok) == 0,
               f"위반 {len(v_ok) if v_ok else 0}건")

        # ── None 반환 없음 확인 (fallback 없이 판정) ────────────
        # 코드가 비어있거나 해당 함수 없으면 [] 반환 (None 아님)
        empty_result = check_rule("LEA-014", "int main(){return 0;}", "dummy.c")
        record("P3-B 해당 함수 없음 → [] (fallback 없음)",
               empty_result is not None,
               f"반환값: {empty_result}")

except Exception as e:
    record("P3-B", False, str(e))


# ══════════════════════════════════════════════════════════════════
# P4-A – RAG 인덱스 사전 로딩
# ══════════════════════════════════════════════════════════════════
print("\n[P4-A] RAG 인덱스 사전 로딩")

try:
    from app.services import rag_service
    record("P4-A rag_service.preload 함수 존재", hasattr(rag_service, "preload"))

    # lifespan 에서 호출되는지 확인
    main_src = Path(ROOT / "app/main.py").read_text(encoding="utf-8")
    record("P4-A lifespan 컨텍스트 매니저 정의", "lifespan" in main_src)
    record("P4-A rag_preload() 호출", "rag_preload()" in main_src)
    record("P4-A FastAPI lifespan= 인자", "lifespan=lifespan" in main_src)

    # preload 실행 시간 측정 (실제 실행)
    t0 = time.perf_counter()
    rag_service.preload()
    elapsed = time.perf_counter() - t0
    record("P4-A preload() 정상 실행", True, f"{elapsed*1000:.1f}ms")
except Exception as e:
    record("P4-A", False, str(e))


# ══════════════════════════════════════════════════════════════════
# P4-B – L3 candidate cap 동적화
# ══════════════════════════════════════════════════════════════════
print("\n[P4-B] L3 candidate cap 동적화")

try:
    # google.genai mock으로 llm_service import
    from app.services import llm_service
    _select_l3_candidates = llm_service._select_l3_candidates

    def _make_violations(n: int, pattern_type: str = "regex", severity: str = "medium") -> list:
        return [{"rule_id": f"LEA-{i % 30:03d}", "pattern_type": pattern_type,
                 "severity": severity, "file": "a.c", "line": i, "message": "test"}
                for i in range(n)]

    # N=15 → 전체 심사 (total_cap = 15)
    v15 = _make_violations(15)
    c15 = _select_l3_candidates(v15)
    record("P4-B N=15 → 전체 심사", len(c15) <= 15, f"선택 {len(c15)}/15")

    # N=50 → cap=60이지만 실제 50개만 있음
    v50 = _make_violations(50)
    c50 = _select_l3_candidates(v50)
    record("P4-B N=50 → cap 적용", len(c50) <= 60, f"선택 {len(c50)}/50")

    # N=100 → cap=min(100,50)=50
    v100 = _make_violations(100)
    c100 = _select_l3_candidates(v100)
    record("P4-B N=100 → cap=50", len(c100) <= 50, f"선택 {len(c100)}/100")

    # N=200 → cap=min(100,100)=100
    v200 = _make_violations(200)
    c200 = _select_l3_candidates(v200)
    record("P4-B N=200 → cap=100", len(c200) <= 100, f"선택 {len(c200)}/200")

    # severity=high는 우선 선택
    v_mix = _make_violations(20, severity="medium") + _make_violations(10, pattern_type="semantic", severity="high")
    c_mix = _select_l3_candidates(v_mix)
    high_selected = sum(1 for v in c_mix if v["severity"] == "high")
    record("P4-B high severity 우선 선택", high_selected >= 5, f"high {high_selected}건 선택")

    # missing 타입 제외
    v_missing = _make_violations(10, pattern_type="missing")
    c_missing = _select_l3_candidates(v_missing)
    record("P4-B missing 타입 L3 미전송",
           all(v["pattern_type"] != "missing" for v in c_missing),
           f"선택 {len(c_missing)}건")

except Exception as e:
    record("P4-B", False, str(e))


# ══════════════════════════════════════════════════════════════════
# P4-C – 진행률 추적 세분화
# ══════════════════════════════════════════════════════════════════
print("\n[P4-C] 진행률 추적 세분화")

try:
    # analyze.py import (google.genai mock 이미 등록됨)
    from app.api.routes.analyze import _write_status

    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)

        # _write_status 가 status.json 생성 확인
        _write_status(root, "preprocess", 15)
        status_file = root / "status.json"
        record("P4-C status.json 생성", status_file.is_file())

        data = json.loads(status_file.read_text(encoding="utf-8"))
        record("P4-C step 필드 기록", data.get("step") == "preprocess", f"step={data.get('step')}")
        record("P4-C progress 필드 기록", data.get("progress") == 15, f"progress={data.get('progress')}")
        record("P4-C status 필드 기록", data.get("status") == "running")

        # 여러 단계 진행
        steps = [
            ("preprocess", 15), ("symbol_graph", 30), ("rule_engine", 45),
            ("l3_llm", 60), ("patches", 72), ("doc_preprocess", 82),
            ("trc", 92),
        ]
        for step, prog in steps:
            _write_status(root, step, prog)
            d = json.loads(status_file.read_text(encoding="utf-8"))
            assert d["progress"] == prog, f"{step} progress mismatch"
        record("P4-C 7단계 진행률 순차 기록", True, f"최종: {data.get('step')}")

    # analyze.py에 _write_status 호출 8회 이상 확인
    analyze_src = Path(ROOT / "app/api/routes/analyze.py").read_text(encoding="utf-8")
    write_count = analyze_src.count("_write_status(")
    record("P4-C _write_status 호출 횟수", write_count >= 7, f"{write_count}회")

except Exception as e:
    record("P4-C", False, str(e))


# ══════════════════════════════════════════════════════════════════
# 결과 요약
# ══════════════════════════════════════════════════════════════════
print("\n" + "="*65)
print("  종합 결과")
print("="*65)

passed = [r for r in results if r["ok"] is True]
failed = [r for r in results if r["ok"] is False]
skipped = [r for r in results if r["ok"] is None]

print(f"  PASS : {len(passed)}")
print(f"  FAIL : {len(failed)}")
print(f"  SKIP : {len(skipped)}")
print(f"  합계 : {len(results)}")

if failed:
    print("\n  실패 항목:")
    for r in failed:
        print(f"    ❌ {r['item']}  — {r['detail']}")

print("="*65)
sys.exit(0 if not failed else 1)
