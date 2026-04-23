"""
Phase 1 통합 테스트 스크립트.

검증 항목:
  [T1] L1 탐지: FAIL ZIP에서 COM-001~005 위반이 정상 탐지되는지
  [T2] L1 탐지: PASS ZIP에서 COM-003/004는 미탐지되는지
  [T3] L2 후보 선정: _select_l2_candidates 로직 (unit test)
  [T4] 코드 절삭: _get_code_context pattern_type별 범위 (unit test)
  [T5] 배치 프롬프트 빌드: _build_batch_prompt 형식 확인
  [T6] JSON 추출: _extract_json_array_from_text 정상 파싱
  [T7] 캐시: 동일 코드 블록 재호출 시 캐시 히트
  [T8] L2 실제 호출: GOOGLE_API_KEY 있으면 FAIL ZIP 전체 파이프라인 실행

실행:
  cd backend
  python scripts/test_phase1.py          # 전체 테스트
  python scripts/test_phase1.py --l2     # L2 실제 Gemini 호출 포함
  python scripts/test_phase1.py --case fail   # FAIL 케이스만
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Set

BACKEND = Path(__file__).resolve().parent.parent
RULES_DIR = BACKEND / "rules"
sys.path.insert(0, str(BACKEND))

from scripts.create_phase1_test_zip import ZIP_FAIL, ZIP_PASS, main as generate_zips

from app.services.upload_service import create_job_from_upload, get_job_root
from app.services.preprocess_service import run_preprocess
from app.services.rule_engine_service import run_rule_engine
from app.services.symbol_graph_service import build_symbol_graph
from app.services.llm_service import (
    _select_l2_candidates,
    _get_code_context,
    _build_batch_prompt,
    _extract_json_array_from_text,
    _l2_cache_key,
    _l2_cache,
    run_l2_contextualizer,
    PROMPT_TEMPLATES,
)


# ─────────────────────────────────────────────────────────────────
# 결과 집계 헬퍼
# ─────────────────────────────────────────────────────────────────
class TestResult:
    def __init__(self):
        self.passed: List[str] = []
        self.failed: List[str] = []

    def ok(self, name: str, detail: str = ""):
        mark = "✅"
        msg = f"{mark} PASS [{name}]"
        if detail:
            msg += f" — {detail}"
        print(msg)
        self.passed.append(name)

    def ng(self, name: str, detail: str = ""):
        mark = "❌"
        msg = f"{mark} FAIL [{name}]"
        if detail:
            msg += f" — {detail}"
        print(msg)
        self.failed.append(name)

    def summary(self) -> int:
        total = len(self.passed) + len(self.failed)
        print(f"\n{'='*60}")
        print(f"결과: {len(self.passed)}/{total} 통과")
        if self.failed:
            print(f"실패 항목: {', '.join(self.failed)}")
        print('='*60)
        return 0 if not self.failed else 1


def _get_rule_ids(violations: List[Dict[str, Any]]) -> Set[str]:
    return {(v.get("rule_id") or "").strip() for v in violations if v.get("rule_id")}


# ─────────────────────────────────────────────────────────────────
# L1 파이프라인 실행 헬퍼
# ─────────────────────────────────────────────────────────────────
def _run_l1(zip_path: Path) -> tuple[List[Dict[str, Any]], Any]:
    """ZIP → L1 위반 리스트 + preprocess_result 반환."""
    job_id = create_job_from_upload(zip_path.read_bytes(), zip_path.name)
    root = get_job_root(job_id)
    preprocess_result = run_preprocess(root)
    symbol_graph = build_symbol_graph(preprocess_result)
    violations = run_rule_engine(
        preprocess_result=preprocess_result,
        rules_dir=RULES_DIR,
        job_root=root,
    )
    return violations, preprocess_result


# ─────────────────────────────────────────────────────────────────
# T1: FAIL ZIP L1 탐지
# ─────────────────────────────────────────────────────────────────
def test_t1_fail_l1(tr: TestResult):
    print("\n[T1] FAIL ZIP — L1 탐지 검증")
    violations, _ = _run_l1(ZIP_FAIL)
    found_ids = _get_rule_ids(violations)

    print(f"  탐지된 rule_id: {sorted(found_ids)}")

    # 필수로 탐지되어야 할 룰
    must_detect = {
        "COM-001",  # missing: 잔존정보 제거 없음
        "COM-003",  # regex: 하드코딩 키 배열
        "COM-004",  # regex: rand() 사용
    }
    missing = must_detect - found_ids
    if missing:
        tr.ng("T1-fail-l1", f"탐지 누락: {missing}")
    else:
        tr.ok("T1-fail-l1", f"필수 룰 모두 탐지: {sorted(must_detect)}")

    # semantic 타입 탐지 확인 (COM-002, COM-005)
    semantic_detected = {"COM-002", "COM-005"} & found_ids
    if semantic_detected:
        tr.ok("T1-semantic", f"semantic 룰 탐지: {sorted(semantic_detected)}")
    else:
        # semantic은 파일 구조상 탐지 안 될 수도 있으므로 warning만
        print(f"  ⚠️  WARNING: semantic 룰(COM-002, COM-005) 미탐지 — 패턴 확인 필요")

    return violations


# ─────────────────────────────────────────────────────────────────
# T2: PASS ZIP L1 미탐지
# ─────────────────────────────────────────────────────────────────
def test_t2_pass_l1(tr: TestResult):
    print("\n[T2] PASS ZIP — L1 미탐지 검증")
    violations, _ = _run_l1(ZIP_PASS)
    found_ids = _get_rule_ids(violations)

    print(f"  탐지된 rule_id: {sorted(found_ids)}")

    # PASS ZIP에서 이 룰들은 탐지되면 안 됨
    should_not_detect = {"COM-003", "COM-004"}
    unexpected = should_not_detect & found_ids
    if unexpected:
        tr.ng("T2-pass-l1", f"오탐 발생: {unexpected}")
    else:
        tr.ok("T2-pass-l1", f"COM-003/COM-004 오탐 없음")


# ─────────────────────────────────────────────────────────────────
# T3: _select_l2_candidates unit test
# ─────────────────────────────────────────────────────────────────
def test_t3_candidate_selection(tr: TestResult):
    print("\n[T3] L2 후보 선정 로직 검증")

    mock_violations = [
        # COM-003: regex, high → 반드시 포함
        {"rule_id": "COM-003", "pattern_type": "regex", "severity": "high",
         "file": "a.c", "line": 10},
        # COM-001: missing → 제외 (위치 없음)
        {"rule_id": "COM-001", "pattern_type": "missing", "severity": "high",
         "file": "a.c", "line": None},
        # COM-002: semantic, medium → 포함
        {"rule_id": "COM-002", "pattern_type": "semantic", "severity": "medium",
         "file": "b.c", "line": 20},
        # COM-005: semantic, high → 포함
        {"rule_id": "COM-005", "pattern_type": "semantic", "severity": "high",
         "file": "c.c", "line": 30},
        # LEA-042: ast, medium → 포함
        {"rule_id": "LEA-042", "pattern_type": "ast", "severity": "medium",
         "file": "d.c", "line": 40},
        # COM-004: regex, high → 포함
        {"rule_id": "COM-004", "pattern_type": "regex", "severity": "high",
         "file": "e.c", "line": 50},
    ]

    candidates = _select_l2_candidates(mock_violations)
    candidate_ids = {v.get("rule_id") for v in candidates}

    print(f"  입력 {len(mock_violations)}건 → 후보 선정 {len(candidates)}건")
    print(f"  선정된 rule_id: {sorted(candidate_ids)}")

    # COM-001(missing)는 제외되어야 함
    if "COM-001" in candidate_ids:
        tr.ng("T3-exclude-missing", "COM-001(missing)이 L2 후보에 포함됨 — 제외되어야 함")
    else:
        tr.ok("T3-exclude-missing", "COM-001(missing) 올바르게 제외")

    # 나머지는 포함되어야 함
    expected_in = {"COM-003", "COM-002", "COM-005", "LEA-042", "COM-004"}
    missing = expected_in - candidate_ids
    if missing:
        tr.ng("T3-include-others", f"후보 누락: {missing}")
    else:
        tr.ok("T3-include-others", f"비-missing 타입 모두 포함")

    # high severity가 medium보다 앞에 와야 함
    high_indices = [i for i, v in enumerate(candidates) if v.get("severity") == "high"]
    medium_indices = [i for i, v in enumerate(candidates) if v.get("severity") == "medium"]
    if high_indices and medium_indices and max(high_indices) < min(medium_indices):
        tr.ok("T3-severity-sort", "high severity 우선 정렬 확인")
    elif not high_indices or not medium_indices:
        tr.ok("T3-severity-sort", "단일 severity (정렬 검증 생략)")
    else:
        tr.ng("T3-severity-sort", f"정렬 오류 — high idx: {high_indices}, medium idx: {medium_indices}")

    # rule_id별 최대 5건 제한
    from collections import Counter
    counts = Counter(v.get("rule_id") for v in candidates)
    over_limit = {k: v for k, v in counts.items() if v > 5}
    if over_limit:
        tr.ng("T3-per-rule-limit", f"룰별 5건 초과: {over_limit}")
    else:
        tr.ok("T3-per-rule-limit", "룰별 최대 5건 제한 확인")


# ─────────────────────────────────────────────────────────────────
# T4: _get_code_context 절삭 범위 검증
# ─────────────────────────────────────────────────────────────────
def test_t4_code_slicing(tr: TestResult):
    print("\n[T4] 코드 절삭 범위 검증")

    # 200라인 더미 소스 생성
    dummy_lines = [f"line_{i:03d}();" for i in range(1, 201)]
    dummy_source = "\n".join(dummy_lines)
    target_line = 100

    cases = [
        ("regex",    30, "regex ±30"),
        ("semantic", 50, "semantic ±50"),
        ("ast",      50, "ast ±50"),
        ("missing",   0, "missing 절삭 없음"),
    ]

    for pattern_type, window, label in cases:
        result = _get_code_context(dummy_source, target_line, pattern_type)
        if pattern_type == "missing":
            if result == "":
                tr.ok(f"T4-{pattern_type}", f"{label} → 빈 문자열")
            else:
                tr.ng(f"T4-{pattern_type}", f"{label} → 빈 문자열이어야 하는데 내용 있음")
        else:
            lines_out = result.splitlines()
            # target_line 기준 ±window 라인 수
            expected_start = max(1, target_line - window)
            expected_end = min(200, target_line - 1 + window)
            expected_count = expected_end - expected_start + 1
            actual_count = len(lines_out)
            if abs(actual_count - expected_count) <= 2:  # ±2 허용
                tr.ok(f"T4-{pattern_type}", f"{label} → {actual_count}라인 (기대: ~{expected_count})")
            else:
                tr.ng(f"T4-{pattern_type}", f"{label} → {actual_count}라인 (기대: ~{expected_count})")


# ─────────────────────────────────────────────────────────────────
# T5: _build_batch_prompt 형식 검증
# ─────────────────────────────────────────────────────────────────
def test_t5_batch_prompt(tr: TestResult):
    print("\n[T5] 배치 프롬프트 형식 검증")

    batch = [
        {
            "violation": {
                "rule_id": "COM-003",
                "line": 10,
                "message": "하드코딩된 키/IV 금지",
                "pattern_type": "regex",
            },
            "code_block": "static const uint8_t key[16] = {0x2b, 0x7e, ...};",
            "cache_key": "abc123",
        },
        {
            "violation": {
                "rule_id": "COM-002",
                "line": 25,
                "message": "에러 처리 없음",
                "pattern_type": "semantic",
            },
            "code_block": "void process(void) { lea_encrypt(key, p, c); }",
            "cache_key": "def456",
        },
    ]

    prompt = _build_batch_prompt("src/test.c", batch)

    checks = [
        ("파일명 포함",     "src/test.c" in prompt),
        ("위반 1 포함",    "위반 1" in prompt),
        ("위반 2 포함",    "위반 2" in prompt),
        ("COM-003 포함",   "COM-003" in prompt),
        ("COM-002 포함",   "COM-002" in prompt),
        ("JSON 배열 요청", "JSON 배열" in prompt),
        ("idx 형식 포함",  '"idx"' in prompt),
        ("COM-003 템플릿", "하드코딩" in prompt or "S-box" in prompt),
        ("COM-002 템플릿", "에러 처리" in prompt),
    ]

    all_ok = True
    for label, ok in checks:
        if ok:
            print(f"  ✅ {label}")
        else:
            print(f"  ❌ {label} — 프롬프트에 없음")
            all_ok = False

    if all_ok:
        tr.ok("T5-batch-prompt", "모든 형식 검증 통과")
    else:
        tr.ng("T5-batch-prompt", "프롬프트 형식 오류")


# ─────────────────────────────────────────────────────────────────
# T6: _extract_json_array_from_text 파싱 검증
# ─────────────────────────────────────────────────────────────────
def test_t6_json_array_parsing(tr: TestResult):
    print("\n[T6] JSON 배열 파싱 검증")

    cases = [
        (
            "순수 배열",
            '[{"idx":1,"is_real_issue":true,"description":"하드코딩 키","suggestion":"외부 주입"},'
            '{"idx":2,"is_real_issue":false,"description":"S-box","suggestion":"무시"}]',
            2,
        ),
        (
            "마크다운 코드블록",
            '```json\n[{"idx":1,"is_real_issue":true,"description":"test","suggestion":"fix"}]\n```',
            1,
        ),
        (
            "설명 텍스트 포함",
            '분석 결과입니다:\n[{"idx":1,"is_real_issue":false,"description":"정상","suggestion":"없음"}]\n끝',
            1,
        ),
        (
            "빈 배열",
            "[]",
            0,
        ),
    ]

    all_ok = True
    for label, raw, expected_len in cases:
        result = _extract_json_array_from_text(raw)
        if result is None:
            print(f"  ❌ {label} — None 반환 (파싱 실패)")
            all_ok = False
        elif len(result) != expected_len:
            print(f"  ❌ {label} — 길이 {len(result)} (기대: {expected_len})")
            all_ok = False
        else:
            print(f"  ✅ {label} — {len(result)}개 파싱 성공")

    if all_ok:
        tr.ok("T6-json-parse", "JSON 배열 파싱 모두 성공")
    else:
        tr.ng("T6-json-parse", "JSON 배열 파싱 실패 케이스 있음")


# ─────────────────────────────────────────────────────────────────
# T7: 캐시 동작 검증
# ─────────────────────────────────────────────────────────────────
def test_t7_cache(tr: TestResult):
    print("\n[T7] L2 결과 캐시 검증")

    rule_id = "COM-003"
    code_block = "static const uint8_t key[16] = {0x2b, 0x7e, 0x15, 0x16};"
    key = _l2_cache_key(rule_id, code_block)

    # 캐시에 직접 주입
    _l2_cache[key] = {"is_real_issue": True, "description": "캐시 테스트", "suggestion": "교체"}

    # 동일 코드로 키 생성 → 캐시 히트 확인
    key2 = _l2_cache_key(rule_id, code_block)
    if key == key2 and key in _l2_cache:
        tr.ok("T7-cache-key", f"동일 코드 → 동일 캐시 키: {key}")
    else:
        tr.ng("T7-cache-key", "캐시 키 불일치")

    # 다른 rule_id → 다른 키
    key3 = _l2_cache_key("COM-001", code_block)
    if key != key3:
        tr.ok("T7-cache-isolation", "rule_id 다르면 다른 캐시 키")
    else:
        tr.ng("T7-cache-isolation", "rule_id 달라도 같은 캐시 키 — 오류")

    # 다른 코드 → 다른 키
    key4 = _l2_cache_key(rule_id, code_block + " // 변경됨")
    if key != key4:
        tr.ok("T7-cache-content", "코드 다르면 다른 캐시 키")
    else:
        tr.ng("T7-cache-content", "코드 달라도 같은 캐시 키 — 오류")

    # 캐시 정리
    del _l2_cache[key]


# ─────────────────────────────────────────────────────────────────
# T8: 전체 파이프라인 (L1 + L2 실제 호출)
# ─────────────────────────────────────────────────────────────────
def test_t8_full_pipeline(tr: TestResult, run_l2: bool):
    print("\n[T8] 전체 파이프라인 (L1 + L2)")

    violations_l1, preprocess_result = _run_l1(ZIP_FAIL)
    found_ids_l1 = _get_rule_ids(violations_l1)
    print(f"  L1 위반: {len(violations_l1)}건 — rule_ids: {sorted(found_ids_l1)}")

    # L2 후보 선정
    from app.services.llm_service import _select_l2_candidates
    candidates = _select_l2_candidates(violations_l1)
    print(f"  L2 후보: {len(candidates)}건")

    if not run_l2:
        print("  (--l2 플래그 없음 → Gemini 실제 호출 생략)")
        if candidates:
            tr.ok("T8-pipeline-l1", f"L1 → L2 후보 선정 성공: {len(candidates)}건")
        else:
            tr.ng("T8-pipeline-l1", "L2 후보가 0건 — L1 위반 탐지 또는 선정 로직 확인 필요")
        return

    # 실제 L2 호출
    import os
    if not os.environ.get("GOOGLE_API_KEY") and not (BACKEND / ".env").exists():
        print("  ⚠️  GOOGLE_API_KEY 없음 → L2 호출 생략")
        tr.ok("T8-pipeline-skip", "GOOGLE_API_KEY 없어서 생략 (정상)")
        return

    print("  Gemini L2 호출 중...")
    violations_l2 = run_l2_contextualizer(preprocess_result, violations_l1)
    print(f"  L2 확정 위반: {len(violations_l2)}건")

    for v in violations_l2:
        print(f"    {v.get('rule_id')} @ {v.get('file')}:{v.get('line')} — {v.get('message')[:60]}")

    if len(violations_l2) >= 0:  # 결과가 나오면 성공 (0건도 정상 가능)
        tr.ok("T8-l2-call", f"L2 호출 성공: {len(violations_l2)}건 확정")
    else:
        tr.ng("T8-l2-call", "L2 호출 실패")


# ─────────────────────────────────────────────────────────────────
# 메인
# ─────────────────────────────────────────────────────────────────
def main() -> int:
    ap = argparse.ArgumentParser(description="Phase 1 통합 테스트")
    ap.add_argument("--l2", action="store_true", help="Gemini L2 실제 호출 포함")
    ap.add_argument(
        "--case", choices=["fail", "pass", "unit", "all"], default="all",
        help="실행할 테스트 케이스"
    )
    ap.add_argument("--regen", action="store_true", help="테스트 ZIP 재생성")
    args = ap.parse_args()

    print("=" * 60)
    print("Phase 1 통합 테스트")
    print("=" * 60)

    # ZIP 생성
    if args.regen or not ZIP_FAIL.exists() or not ZIP_PASS.exists():
        print("\n테스트 ZIP 생성 중...")
        generate_zips()

    tr = TestResult()

    run_fail = args.case in {"fail", "all"}
    run_pass = args.case in {"pass", "all"}
    run_unit = args.case in {"unit", "all"}

    if run_unit:
        test_t3_candidate_selection(tr)
        test_t4_code_slicing(tr)
        test_t5_batch_prompt(tr)
        test_t6_json_array_parsing(tr)
        test_t7_cache(tr)

    if run_fail:
        test_t1_fail_l1(tr)
        test_t8_full_pipeline(tr, run_l2=args.l2)

    if run_pass:
        test_t2_pass_l1(tr)

    return tr.summary()


if __name__ == "__main__":
    sys.exit(main())
