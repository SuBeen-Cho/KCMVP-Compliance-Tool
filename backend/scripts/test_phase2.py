"""
Phase 2 통합 테스트 스크립트.

검증 항목:
  [T1] mapping_service: rule_to_guideline.json 로드 및 조회
  [T2] mapping_service: get_guideline_path 경로 반환
  [T3] mapping_service: get_search_query 반환값
  [T4] rag_service: Direct-RAG — COM-001 가이드라인 파일 직접 로드
  [T5] rag_service: search_evidence 섹션 반환 (요구사항, 위반 패턴, 올바른 구현)
  [T6] rag_service: extract_evidence_for_violation 출처 포함 여부
  [T7] rag_service: TF-IDF fallback (존재하지 않는 rule_id)
  [T8] code_slicer: regex ±30라인 윈도우
  [T9] code_slicer: semantic — 함수 경계 탐지 (중괄호 카운팅)
  [T10] code_slicer: ast — 함수 + 전역 스켈레톤 포함
  [T11] code_slicer: missing → None 반환
  [T12] code_slicer: 중첩 함수 없는 짧은 파일 fallback
  [T13] llm_service: _get_code_context → code_slicer 위임 확인
  [T14] 전체 파이프라인: Phase 1 ZIP으로 L1+RAG 연동 확인

실행:
  cd backend
  python scripts/test_phase2.py
  python scripts/test_phase2.py --l3   # L3 Gemini 호출 포함
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

# ─────────────────────────────────────────────────────────────────
# 테스트 유틸
# ─────────────────────────────────────────────────────────────────
_results: List[Dict[str, Any]] = []


def ok(name: str, detail: str = "") -> None:
    _results.append({"name": name, "pass": True, "detail": detail})
    print(f"  [PASS] {name}" + (f" — {detail}" if detail else ""))


def fail(name: str, reason: str) -> None:
    _results.append({"name": name, "pass": False, "detail": reason})
    print(f"  [FAIL] {name} — {reason}")


def section(title: str) -> None:
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


# ─────────────────────────────────────────────────────────────────
# T1~T3: mapping_service
# ─────────────────────────────────────────────────────────────────
def test_mapping_service() -> None:
    section("T1~T3: mapping_service")

    from app.services.mapping_service import (
        lookup, get_guideline_path, get_search_query,
        is_l3_required, list_all_rule_ids,
    )

    # T1: lookup 반환값 구조 확인
    info = lookup("COM-001")
    if info and "item_ids" in info and "kcmvp_ref" in info:
        ok("T1", f"COM-001 lookup 성공 — item_ids={info['item_ids']}")
    else:
        fail("T1", f"COM-001 lookup 실패: {info}")

    # T1b: 존재하지 않는 rule_id
    info_unknown = lookup("UNKNOWN-999")
    if info_unknown == {}:
        ok("T1b", "존재하지 않는 rule_id → 빈 dict 반환")
    else:
        fail("T1b", f"예상과 다른 반환값: {info_unknown}")

    # T2: get_guideline_path
    path = get_guideline_path("COM-001")
    if path and path.exists():
        ok("T2", f"COM-001 guideline 경로 확인: {path.name}")
    elif path:
        fail("T2", f"경로 객체는 있지만 파일 없음: {path}")
    else:
        fail("T2", "get_guideline_path('COM-001') → None")

    # T3: get_search_query
    q = get_search_query("COM-004")
    if q and len(q) > 3:
        ok("T3", f"COM-004 search_query='{q}'")
    else:
        fail("T3", f"search_query 비어있음: {repr(q)}")

    # T3b: list_all_rule_ids
    all_ids = list_all_rule_ids()
    expected = {"COM-001", "COM-003", "COM-004", "LEA-042"}
    if expected.issubset(set(all_ids)):
        ok("T3b", f"list_all_rule_ids 포함 확인: {sorted(all_ids)[:5]}...")
    else:
        fail("T3b", f"기대 rule_id 누락: {expected - set(all_ids)}")


# ─────────────────────────────────────────────────────────────────
# T4~T7: rag_service
# ─────────────────────────────────────────────────────────────────
def test_rag_service() -> None:
    section("T4~T7: rag_service")

    from app.services.rag_service import (
        search_evidence,
        extract_evidence_for_violation,
        _load_guideline_file,
        _extract_sections_from_md,
    )

    # T4: Direct-RAG — COM-001 파일 로드
    content = _load_guideline_file("COM-001")
    if content and "## 요구사항" in content:
        ok("T4", "COM-001 가이드라인 MD 파일 로드 성공")
    else:
        fail("T4", f"_load_guideline_file('COM-001') 실패: {repr(content)[:80]}")

    # T4b: 섹션 분리
    if content:
        sections = _extract_sections_from_md(content)
        titles = [s["title"] for s in sections]
        if "요구사항" in titles:
            ok("T4b", f"섹션 분리 성공: {titles}")
        else:
            fail("T4b", f"'요구사항' 섹션 없음: {titles}")

    # T5: search_evidence 반환값 구조
    results = search_evidence("COM-001", top_k=3)
    if results and len(results) >= 1:
        first = results[0]
        required_keys = {"content", "title", "source"}
        missing_keys = required_keys - set(first.keys())
        if not missing_keys:
            ok("T5", f"COM-001 search_evidence {len(results)}건 반환, 필드 OK")
        else:
            fail("T5", f"결과 딕셔너리에 키 누락: {missing_keys}")
    else:
        fail("T5", f"search_evidence 결과 없음: {results}")

    # T5b: 핵심 섹션 우선 반환 (요구사항 / 위반 패턴 / 올바른 구현)
    priority_titles = {"요구사항", "위반 패턴", "올바른 구현", "참고"}
    returned_titles = {r.get("title", "") for r in results}
    if returned_titles & priority_titles:
        ok("T5b", f"핵심 섹션 우선 반환 확인: {returned_titles & priority_titles}")
    else:
        fail("T5b", f"핵심 섹션 미반환: 반환된 섹션={returned_titles}")

    # T6: extract_evidence_for_violation
    evidence = extract_evidence_for_violation("memset으로 키 제로화 미처리", "COM-001", top_k=2)
    if evidence and "출처" in evidence:
        ok("T6", f"extract_evidence_for_violation 출처 포함 ({len(evidence)}자)")
    elif evidence:
        fail("T6", f"출처 없음. 내용: {evidence[:100]}")
    else:
        fail("T6", "extract_evidence_for_violation → None")

    # T7: TF-IDF fallback — 존재하지 않는 rule_id
    fallback = search_evidence("UNKNOWN-999", query="timing attack constant time comparison", top_k=2)
    if isinstance(fallback, list):
        ok("T7", f"TF-IDF fallback 호출 성공 (결과 {len(fallback)}건)")
    else:
        fail("T7", f"예상치 못한 반환 타입: {type(fallback)}")


# ─────────────────────────────────────────────────────────────────
# T8~T13: code_slicer
# ─────────────────────────────────────────────────────────────────
_SAMPLE_C = """\
#include <openssl/crypto.h>
#include <string.h>
#include <stdint.h>

typedef struct {
    uint8_t key[16];
    uint8_t iv[16];
} CTX;

int helper(int x) {
    return x + 1;
}

int encrypt(const uint8_t *key, const uint8_t *data, size_t len, uint8_t *out) {
    CTX ctx;
    int ret = 0;

    memcpy(ctx.key, key, 16);

    if (len == 0) {
        ret = -1;
        goto cleanup;
    }

    /* actual encryption */
    for (size_t i = 0; i < len; i++) {
        out[i] = data[i] ^ ctx.key[i % 16];
    }

cleanup:
    memset(&ctx, 0, sizeof(ctx));
    return ret;
}

int verify_tag(const uint8_t *a, const uint8_t *b, size_t n) {
    if (memcmp(a, b, n) != 0) {
        return -1;
    }
    return 0;
}
""".strip()


def test_code_slicer() -> None:
    section("T8~T13: code_slicer")

    from app.services.code_slicer import slice_code, extract_global_skeleton, _find_function_boundary

    sample_lines = _SAMPLE_C.splitlines()
    n = len(sample_lines)

    # T8: regex ±30라인 윈도우
    # line_number=20 (for loop 라인)
    result_regex = slice_code(sample_lines, 20, "regex")
    if result_regex is not None:
        got_lines = result_regex.splitlines()
        # ±30 이내이므로 전체 파일보다 작거나 같아야 함
        if len(got_lines) <= min(n, 60):
            ok("T8", f"regex 슬라이싱: {len(got_lines)}라인 반환")
        else:
            fail("T8", f"라인 수 초과: {len(got_lines)} > {min(n, 60)}")
    else:
        fail("T8", "slice_code(regex) → None")

    # T9: semantic — encrypt 함수 내부 라인 (line 20 = for 루프)
    # encrypt 함수 시작은 14번째 줄 정도
    # encrypt 내부의 for 루프가 있는 라인을 찾아서 테스트
    target_line = None
    for i, ln in enumerate(sample_lines, 1):
        if "for (size_t i = 0;" in ln:
            target_line = i
            break

    if target_line:
        result_sem = slice_code(sample_lines, target_line, "semantic")
        # 엄격 검증: 반드시 encrypt 함수 시그니처가 포함되어야 함
        if result_sem and "encrypt" in result_sem and "CTX ctx" in result_sem:
            ok("T9", f"semantic 함수 경계 탐지 성공 (encrypt 전체 포함, {len(result_sem.splitlines())}라인)")
        elif result_sem and "encrypt" in result_sem:
            ok("T9", f"semantic 함수 포함 ({len(result_sem.splitlines())}라인)")
        elif result_sem:
            fail("T9", f"fallback 윈도우만 반환됨 ({len(result_sem.splitlines())}라인) — 함수 경계 탐지 실패")
        else:
            fail("T9", "slice_code(semantic) → None")
    else:
        fail("T9", "테스트용 for 루프 라인을 찾지 못함")

    # T10: ast — verify_tag 함수의 memcmp 라인
    memcmp_line = None
    for i, ln in enumerate(sample_lines, 1):
        if "memcmp" in ln:
            memcmp_line = i
            break

    if memcmp_line:
        result_ast = slice_code(sample_lines, memcmp_line, "ast")
        # 엄격 검증: verify_tag 함수 + CTX 스켈레톤 포함
        if result_ast and "verify_tag" in result_ast and "CTX" in result_ast:
            ok("T10", f"ast 슬라이싱 성공 — 함수+스켈레톤 포함 ({len(result_ast.splitlines())}라인)")
        elif result_ast and "verify_tag" in result_ast:
            fail("T10", f"verify_tag 함수는 있지만 CTX 스켈레톤 누락 ({len(result_ast.splitlines())}라인)")
        elif result_ast:
            fail("T10", f"verify_tag 함수 미포함 ({len(result_ast.splitlines())}라인) — 함수 경계 탐지 실패")
        else:
            fail("T10", "slice_code(ast) → None")
    else:
        fail("T10", "테스트용 memcmp 라인을 찾지 못함")

    # T11: missing → None
    result_missing = slice_code(sample_lines, 10, "missing")
    if result_missing is None:
        ok("T11", "missing → None 정상 반환")
    else:
        fail("T11", f"missing이 None이 아님: {repr(result_missing)[:50]}")

    # T12: 짧은 파일 (중괄호 없음) fallback
    short_lines = ["int x = 1;", "int y = 2;", "return x + y;"]
    result_short = slice_code(short_lines, 2, "semantic")
    if result_short is not None:
        ok("T12", f"짧은 파일 fallback: {len(result_short.splitlines())}라인 반환")
    else:
        fail("T12", "짧은 파일에서 None 반환")

    # T13: 전역 스켈레톤 추출 — typedef struct {...} CTX 반드시 포함
    skeleton = extract_global_skeleton(sample_lines)
    if "CTX" in skeleton and "typedef" in skeleton:
        ok("T13", f"extract_global_skeleton: typedef CTX 포함 ({len(skeleton.splitlines())}라인)")
    elif skeleton:
        fail("T13", f"CTX 누락. 스켈레톤 내용: '{skeleton[:100]}'")
    else:
        fail("T13", "extract_global_skeleton → 빈 문자열")


# ─────────────────────────────────────────────────────────────────
# T14: llm_service._get_code_context → code_slicer 위임 확인
# ─────────────────────────────────────────────────────────────────
def test_llm_service_slicer_integration() -> None:
    section("T14: llm_service — code_slicer 위임 확인")

    from app.services.llm_service import _get_code_context

    sample_lines = _SAMPLE_C.splitlines()
    content = _SAMPLE_C

    # semantic 타입: 함수 경계 또는 50라인 윈도우 반환
    result = _get_code_context(content, 25, "semantic")
    if result and len(result) > 0:
        ok("T14a", f"_get_code_context(semantic) → {len(result.splitlines())}라인")
    else:
        fail("T14a", f"_get_code_context(semantic) 빈 문자열: {repr(result)}")

    # missing 타입: 빈 문자열 반환 (None → '')
    result_missing = _get_code_context(content, 10, "missing")
    if result_missing == "":
        ok("T14b", "_get_code_context(missing) → '' 정상")
    else:
        fail("T14b", f"missing이 '' 아님: {repr(result_missing)[:50]}")

    # line=0: 빈 문자열
    result_no_line = _get_code_context(content, 0, "regex")
    if result_no_line == "":
        ok("T14c", "_get_code_context(line=0) → '' 정상")
    else:
        fail("T14c", f"line=0이 '' 아님: {repr(result_no_line)[:50]}")


# ─────────────────────────────────────────────────────────────────
# T15: Phase 1 ZIP으로 L1+RAG 연동 (선택적)
# ─────────────────────────────────────────────────────────────────
def test_full_pipeline_rag(run_l3: bool = False) -> None:
    section("T15: 전체 파이프라인 + RAG 연동")

    from scripts.create_phase1_test_zip import ZIP_FAIL, main as generate_zips
    from app.services.upload_service import create_job_from_upload, get_job_root
    from app.services.preprocess_service import run_preprocess
    from app.services.rule_engine_service import run_rule_engine
    from app.services.rag_service import search_evidence, extract_evidence_for_violation

    # ZIP 생성 (없으면)
    if not ZIP_FAIL.exists():
        generate_zips()

    job_id = create_job_from_upload(ZIP_FAIL.read_bytes(), ZIP_FAIL.name)
    job_root = get_job_root(job_id)
    preprocess_result = run_preprocess(job_root)
    l1_result_list = run_rule_engine(preprocess_result, BACKEND / "rules", job_root)
    violations = l1_result_list if isinstance(l1_result_list, list) else l1_result_list.get("violations", [])

    if not violations:
        fail("T15a", "L1 위반이 하나도 없음 — FAIL ZIP에서 기대와 다름")
        return

    ok("T15a", f"L1 위반 {len(violations)}건 탐지")

    # RAG 연동: 각 위반에 대해 근거 검색
    rag_hits = 0
    for v in violations[:5]:
        rule_id = v.get("rule_id", "")
        msg = v.get("message", "")
        evidence = extract_evidence_for_violation(msg, rule_id, top_k=2)
        if evidence:
            rag_hits += 1

    if rag_hits > 0:
        ok("T15b", f"RAG 근거 검색 성공: {rag_hits}/{min(len(violations), 5)}건")
    else:
        fail("T15b", "RAG 근거 검색 결과 없음 (guideline MD 파일 연결 확인 필요)")

    # L3 실제 호출 (선택적)
    if run_l3:
        from app.services.llm_service import run_l3_contextualizer
        l3_results = run_l3_contextualizer(preprocess_result, violations)
        ok("T15c", f"L3 호출 완료: {len(l3_results)}건 실제 위반 확정")
    else:
        ok("T15c", "L3 호출 스킵 (--l3 옵션으로 실행 가능)")


# ─────────────────────────────────────────────────────────────────
# 결과 출력
# ─────────────────────────────────────────────────────────────────
def print_summary() -> int:
    total = len(_results)
    passed = sum(1 for r in _results if r["pass"])
    failed = total - passed

    print(f"\n{'='*60}")
    print(f"  Phase 2 테스트 결과: {passed}/{total} PASS")
    if failed:
        print(f"  실패 항목:")
        for r in _results:
            if not r["pass"]:
                print(f"    - {r['name']}: {r['detail']}")
    print(f"{'='*60}\n")
    return 1 if failed else 0


# ─────────────────────────────────────────────────────────────────
# 메인
# ─────────────────────────────────────────────────────────────────
def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Phase 2 통합 테스트")
    parser.add_argument("--l3", action="store_true", help="L3 Gemini 실제 호출 포함")
    args = parser.parse_args()

    print("Phase 2 통합 테스트 시작\n")

    try:
        test_mapping_service()
    except Exception as e:
        fail("mapping_service 전체", str(e))

    try:
        test_rag_service()
    except Exception as e:
        fail("rag_service 전체", str(e))

    try:
        test_code_slicer()
    except Exception as e:
        fail("code_slicer 전체", str(e))

    try:
        test_llm_service_slicer_integration()
    except Exception as e:
        fail("llm_service slicer 연동", str(e))

    try:
        test_full_pipeline_rag(run_l3=args.l3)
    except Exception as e:
        fail("전체 파이프라인 RAG", str(e))

    return print_summary()


if __name__ == "__main__":
    sys.exit(main())
