"""
Phase 3 통합 테스트.

검증 항목:
  [T1] post_process_violations: L1+L2 dedup (file+line+rule_id 기준)
  [T2] post_process_violations: L2 병합 (source=L1+L2, suggestion 반영)
  [T3] post_process_violations: 매칭 안 된 L2 독립 유지
  [T4] post_process_violations: L1만 있을 때 정상 반환
  [T5] attach_evidence: 위반 리스트에 evidence 필드 추가
  [T6] attach_evidence: 이미 evidence 있으면 스킵
  [T7] generate_patch_for_violation: API키 없으면 stub 반환
  [T8] generate_patch_for_violation: 프롬프트 빌드 형식
  [T9] 전체 파이프라인: FAIL ZIP → post_process → evidence → patch 생성
  [T10] analyze.py 파이프라인: violations.json에 evidence 필드 포함 여부
  [T11] analyze.py 파이프라인: patches/ 디렉터리 생성 확인

실행:
  cd backend
  venv/bin/python3 scripts/test_phase3.py
  venv/bin/python3 scripts/test_phase3.py --l2   # L2 Gemini 포함
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

_results: List[Dict[str, Any]] = []


def ok(name: str, detail: str = "") -> None:
    _results.append({"name": name, "pass": True})
    print(f"  [PASS] {name}" + (f" — {detail}" if detail else ""))


def fail(name: str, reason: str) -> None:
    _results.append({"name": name, "pass": False, "detail": reason})
    print(f"  [FAIL] {name} — {reason}")


def section(title: str) -> None:
    print(f"\n{'='*60}\n  {title}\n{'='*60}")


# ─────────────────────────────────────────────────────────────────
# T1~T4: post_process_violations
# ─────────────────────────────────────────────────────────────────
def test_post_process() -> None:
    section("T1~T4: post_process_violations")

    from app.services.report_service import post_process_violations

    # 기본 L1 위반 세트
    l1 = [
        {"file": "src/a.c", "line": 10, "rule_id": "COM-003", "message": "하드코딩 키", "severity": "high", "pattern_type": "regex"},
        {"file": "src/a.c", "line": 10, "rule_id": "COM-003", "message": "하드코딩 키 (중복)", "severity": "high", "pattern_type": "regex"},  # 중복
        {"file": "src/b.c", "line": 20, "rule_id": "COM-001", "message": "제로화 미처리", "severity": "high", "pattern_type": "missing"},
    ]
    l2_empty: List[Dict] = []
    l2_match = [
        {
            "source": "L2",
            "file": "src/a.c",
            "line": 10,
            "rule_id": "L2-COM-003",
            "message": "실제 암호 키로 확인됨",
            "severity": "high",
            "suggestion": "외부 KMS에서 키 로드",
            "confidence": 0.95,
            "pattern_type": "regex",
        }
    ]

    # T1: dedup (동일 file+line+rule_id 중복 제거)
    result = post_process_violations(l1, l2_empty)
    if len(result) == 2:
        ok("T1", f"dedup 성공: {len(l1)}건 → {len(result)}건")
    else:
        fail("T1", f"dedup 실패: 기대 2건, 실제 {len(result)}건")

    # T2: L2 병합 (source=L1+L2, suggestion 반영)
    result_merged = post_process_violations(l1, l2_match)
    merged = [v for v in result_merged if v.get("source") == "L1+L2"]
    if merged and merged[0].get("suggestion") == "외부 KMS에서 키 로드":
        ok("T2", f"L2 병합 성공 — suggestion='{merged[0]['suggestion']}'")
    else:
        fail("T2", f"L2 병합 실패: merged={merged}")

    # T3: 매칭 안 된 L2는 독립 유지
    l2_unmatched = [
        {
            "source": "L2",
            "file": "src/c.c",  # L1에 없는 파일
            "line": 99,
            "rule_id": "L2-COM-004",
            "message": "PRNG 사용 확인",
            "severity": "medium",
            "suggestion": "getrandom() 사용",
            "confidence": 0.8,
            "pattern_type": "regex",
        }
    ]
    result_unmatched = post_process_violations(l1, l2_unmatched)
    l2_items = [v for v in result_unmatched if v.get("source") == "L2"]
    if l2_items:
        ok("T3", f"매칭 안 된 L2 독립 유지: {len(l2_items)}건")
    else:
        fail("T3", "매칭 안 된 L2가 제거됨")

    # T4: L1만 있을 때 정상 반환
    result_l1_only = post_process_violations(l1, [])
    if len(result_l1_only) == 2:
        ok("T4", "L1만 있을 때 dedup 후 정상 반환")
    else:
        fail("T4", f"기대 2건, 실제 {len(result_l1_only)}건")


# ─────────────────────────────────────────────────────────────────
# T5~T6: attach_evidence
# ─────────────────────────────────────────────────────────────────
def test_attach_evidence() -> None:
    section("T5~T6: attach_evidence")

    from app.services.rag_service import attach_evidence

    violations = [
        {"file": "src/a.c", "line": 10, "rule_id": "COM-001", "message": "제로화 미처리", "severity": "high"},
        {"file": "src/b.c", "line": 20, "rule_id": "COM-003", "message": "하드코딩 키", "severity": "high", "evidence": "이미 있는 근거"},
    ]

    # T5: evidence 없는 항목에 필드 추가
    result = attach_evidence(violations, top_k=1)
    if len(result) == 2:
        com001 = next((v for v in result if v.get("rule_id") == "COM-001"), None)
        if com001 and com001.get("evidence"):
            ok("T5", f"COM-001 evidence 첨부 성공 ({len(com001['evidence'])}자)")
        elif com001:
            fail("T5", "COM-001 evidence 필드 없음 — 가이드라인 MD 파일 연결 확인 필요")
        else:
            fail("T5", "COM-001 항목을 찾지 못함")
    else:
        fail("T5", f"결과 개수 불일치: {len(result)}")

    # T6: 이미 evidence 있으면 덮어쓰지 않음
    com003 = next((v for v in result if v.get("rule_id") == "COM-003"), None)
    if com003 and com003.get("evidence") == "이미 있는 근거":
        ok("T6", "기존 evidence 보존 확인")
    else:
        fail("T6", f"기존 evidence 덮어씀: {com003}")


# ─────────────────────────────────────────────────────────────────
# T7~T8: generate_patch_for_violation
# ─────────────────────────────────────────────────────────────────
def test_generate_patch() -> None:
    section("T7~T8: generate_patch_for_violation")

    from app.services.llm_service import generate_patch_for_violation, _build_patch_prompt

    # T7: API 키 없을 때 stub 반환
    import app.services.llm_service as llm_mod
    original_key = llm_mod.GOOGLE_API_KEY
    llm_mod.GOOGLE_API_KEY = ""

    stub = generate_patch_for_violation(
        file_path="src/a.c", line=10,
        snippet="static const uint8_t key[16] = {0x00,...};",
        violation_message="하드코딩된 키",
        evidence="키는 런타임에 로드해야 함",
    )
    llm_mod.GOOGLE_API_KEY = original_key

    if "src/a.c" in stub and "하드코딩된 키" in stub:
        ok("T7", "API 키 없을 때 stub 마크다운 반환")
    else:
        fail("T7", f"stub 내용 예상과 다름: {stub[:80]}")

    # T8: 프롬프트 빌드 형식 확인
    prompt = _build_patch_prompt(
        file_path="src/a.c", line=10,
        snippet="static const uint8_t key[16] = {0x00,...};",
        violation_message="하드코딩된 키",
        evidence="키는 런타임에 로드해야 함",
    )
    required = ["Before", "After", "수정 이유", "src/a.c", "하드코딩된 키"]
    missing = [r for r in required if r not in prompt]
    if not missing:
        ok("T8", "패치 프롬프트 형식 OK")
    else:
        fail("T8", f"프롬프트에 누락 항목: {missing}")


# ─────────────────────────────────────────────────────────────────
# T9: 전체 파이프라인 통합
# ─────────────────────────────────────────────────────────────────
def test_full_pipeline(run_l2: bool = False) -> None:
    section("T9~T11: 전체 파이프라인 (post_process + evidence + patch)")

    from scripts.create_phase1_test_zip import ZIP_FAIL, main as generate_zips
    from app.services.upload_service import create_job_from_upload, get_job_root
    from app.services.preprocess_service import run_preprocess
    from app.services.rule_engine_service import run_rule_engine
    from app.services.llm_service import run_l2_contextualizer, generate_patch_for_violation
    from app.services.rag_service import attach_evidence
    from app.services.report_service import post_process_violations, save_patch
    from app.services.code_slicer import slice_code

    if not ZIP_FAIL.exists():
        generate_zips()

    job_id = create_job_from_upload(ZIP_FAIL.read_bytes(), ZIP_FAIL.name)
    job_root = get_job_root(job_id)
    preprocess_result = run_preprocess(job_root)
    l1_violations = run_rule_engine(preprocess_result, BACKEND / "rules", job_root)

    l2_violations = []
    if run_l2:
        l2_violations = run_l2_contextualizer(preprocess_result, l1_violations)

    # T9: post_process
    merged = post_process_violations(l1_violations, l2_violations)
    if len(merged) <= len(l1_violations):
        ok("T9", f"post_process 완료: {len(l1_violations)}건 → {len(merged)}건 (dedup)")
    else:
        fail("T9", f"post_process 후 건수 증가: {len(l1_violations)} → {len(merged)}")

    # T10: attach_evidence
    evidenced = attach_evidence(merged, top_k=1)
    with_evidence = [v for v in evidenced if v.get("evidence")]
    if with_evidence:
        ok("T10", f"evidence 첨부 성공: {len(with_evidence)}/{len(evidenced)}건")
    else:
        fail("T10", "evidence 첨부 건수 0 — 가이드라인 MD 파일 확인 필요")

    # T11: patch 생성 + patches/ 디렉터리
    _patch_count = 0
    for v in evidenced:
        if _patch_count >= 3:
            break
        if (v.get("severity") or "").lower() != "high":
            continue
        _file = v.get("file") or ""
        _line = v.get("line") or 0
        _rule_id = v.get("rule_id") or "UNKNOWN"

        _snippet = ""
        for fi in preprocess_result.get("files", []):
            fp = fi.get("path") or ""
            if fp == _file or fp.endswith(_file) or _file.endswith(fp):
                lines = fi.get("lines")
                if lines and _line:
                    _snippet = slice_code(lines, _line, v.get("pattern_type") or "regex") or ""
                break

        patch_md = generate_patch_for_violation(
            file_path=_file, line=_line,
            snippet=_snippet,
            violation_message=v.get("message") or "",
            evidence=v.get("evidence") or "",
        )
        save_patch(job_root, _rule_id, _file, _line, patch_md)
        _patch_count += 1

    patches_dir = job_root / "patches"
    if patches_dir.is_dir() and list(patches_dir.glob("*.md")):
        patch_files = list(patches_dir.glob("*.md"))
        ok("T11", f"patches/ 생성 완료: {len(patch_files)}개 파일")
    elif _patch_count == 0:
        ok("T11", "high severity 위반 없음 — patches/ 생성 스킵 (정상)")
    else:
        fail("T11", "patches/ 디렉터리 미생성 또는 .md 파일 없음")


# ─────────────────────────────────────────────────────────────────
# 결과 요약
# ─────────────────────────────────────────────────────────────────
def print_summary() -> int:
    total = len(_results)
    passed = sum(1 for r in _results if r["pass"])
    failed = total - passed
    print(f"\n{'='*60}")
    print(f"  Phase 3 테스트 결과: {passed}/{total} PASS")
    if failed:
        for r in _results:
            if not r["pass"]:
                print(f"    - {r['name']}: {r.get('detail', '')}")
    print(f"{'='*60}\n")
    return 1 if failed else 0


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--l2", action="store_true")
    args = parser.parse_args()

    print("Phase 3 통합 테스트 시작\n")

    for fn in [test_post_process, test_attach_evidence, test_generate_patch]:
        try:
            fn()
        except Exception as e:
            fail(fn.__name__, str(e))

    try:
        test_full_pipeline(run_l2=args.l2)
    except Exception as e:
        fail("전체 파이프라인", str(e))

    return print_summary()


if __name__ == "__main__":
    sys.exit(main())
