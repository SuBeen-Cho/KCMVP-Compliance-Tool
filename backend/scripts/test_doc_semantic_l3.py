#!/usr/bin/env python3
"""
DOC semantic 규칙 → L3 항상 전달 수정 검증 스크립트
=====================================================
fake_design_doc.pdf 기준으로:
  1. doc_rule_service: semantic 규칙 항상 발동 여부
  2. keyword_found 필드 존재 여부
  3. L3 contextualizer: needs_ai_review 위반 수신 여부
  4. (API 키 있을 시) 실제 L3 AI 판정 결과

알려진 의도적 위반 5개: DOC-003, DOC-012, DOC-022, DOC-040, DOC-048
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
print("  DOC semantic → L3 수정 검증 (fake_design_doc.pdf)")
print("=" * 65)

# ── 1. 전처리 결과 로드 ───────────────────────────────────────────
print("\n[1] 기존 전처리 결과 로드")

import json, glob as _glob

JOBS_DIR = ROOT / "storage" / "jobs"
doc_preprocess = None
job_id_used = None

for jpath in sorted(JOBS_DIR.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
    design_dir = jpath / "docs" / "design"
    if design_dir.exists() and any("fake_design" in f.name for f in design_dir.iterdir()):
        dp_file = jpath / "doc_preprocess_result.json"
        if dp_file.exists():
            doc_preprocess = json.loads(dp_file.read_text())
            job_id_used = jpath.name
            break

record("기존 전처리 결과 로드", doc_preprocess is not None, f"job={job_id_used}")
if doc_preprocess is None:
    print("  전처리 결과 없음 — 직접 전처리 시도")
    try:
        from app.services.preprocess_docs_service import run_preprocess_docs
        PDF_PATH = ROOT / "testdata" / "fake_design_doc.pdf"
        doc_preprocess = run_preprocess_docs({"design": [str(PDF_PATH)]})
        record("직접 전처리 성공", True)
    except Exception as e:
        record("직접 전처리 실패", False, str(e)[:80])
        sys.exit(1)

sections = doc_preprocess.get("sections", [])
print(f"  섹션 수: {len(sections)}")

# ── 2. DOC 규칙 로드 ─────────────────────────────────────────────
print("\n[2] DOC 규칙 로드")
from app.services.doc_rule_service import load_doc_rules, run_doc_rule_engine

RULES_DIR = ROOT / "rules"
rules = load_doc_rules(RULES_DIR)
semantic_rules = [r for r in rules if r.get("pattern_type") == "semantic"]
missing_rules  = [r for r in rules if r.get("pattern_type") == "missing"]

record("DOC 규칙 로드", len(rules) > 0, f"전체={len(rules)}, semantic={len(semantic_rules)}, missing={len(missing_rules)}")

TARGET_RULES = {"DOC-003", "DOC-012", "DOC-022", "DOC-040", "DOC-048"}
target_in_rules = {r["id"] for r in rules if r.get("id") in TARGET_RULES}
record("5개 타깃 규칙 모두 로드됨", target_in_rules == TARGET_RULES, str(target_in_rules))

# ── 3. L1 규칙 엔진 실행 ─────────────────────────────────────────
print("\n[3] L1 규칙 엔진 실행")
violations_l1 = run_doc_rule_engine(doc_preprocess, rules)
doc_viols = [v for v in violations_l1 if str(v.get("rule_id","")).startswith("DOC")]

record("L1 실행 완료", True, f"DOC 위반={len(doc_viols)}건")

# 타깃 5개 탐지 여부
print("\n  [타깃 5개 탐지 현황]")
for rid in sorted(TARGET_RULES):
    matches = [v for v in doc_viols if v.get("rule_id") == rid]
    found = len(matches) > 0
    kw = matches[0].get("keyword_found") if matches else None
    ai = matches[0].get("needs_ai_review") if matches else None
    pt = matches[0].get("pattern_type") if matches else None
    detail = f"keyword_found={kw}, needs_ai_review={ai}, pattern_type={pt}" if found else "미탐"
    record(f"L1 탐지: {rid}", found, detail)

# keyword_found 필드 검증
semantic_viols = [v for v in doc_viols if v.get("needs_ai_review") is True]
has_keyword_field = all("keyword_found" in v for v in semantic_viols) if semantic_viols else False
record("semantic 위반에 keyword_found 필드 존재", has_keyword_field,
       f"{len(semantic_viols)}개 semantic 위반 확인")

kw_true  = [v for v in semantic_viols if v.get("keyword_found") is True]
kw_false = [v for v in semantic_viols if v.get("keyword_found") is False]
print(f"  keyword_found=True (키워드 있지만 맥락 부적절): {len(kw_true)}건")
print(f"  keyword_found=False (키워드 아예 없음):         {len(kw_false)}건")

# ── 4. L3 필터 검증 (API 호출 없이) ─────────────────────────────
print("\n[4] L3 필터 로직 검증 (API 호출 없음)")
ai_candidates = [v for v in violations_l1 if v.get("needs_ai_review") is True]
record("needs_ai_review=True 위반이 L3 후보로 선정됨", len(ai_candidates) > 0,
       f"{len(ai_candidates)}건")

# DOC-003/012/022가 AI 후보에 포함되는지
for rid in ["DOC-003", "DOC-012", "DOC-022"]:
    in_candidates = any(v.get("rule_id") == rid for v in ai_candidates)
    record(f"L3 후보에 {rid} 포함", in_candidates)

# ── 5. 실제 L3 AI 판정 ───────────────────────────────────────────
print("\n[5] 실제 L3 AI 판정 (Gemini API)")
api_key = os.environ.get("GOOGLE_API_KEY", "")
if not api_key or api_key in ("your_key_here", ""):
    print(f"  {INFO} GOOGLE_API_KEY 없음 → L3 실행 생략")
    record("L3 실행 (API 키 없어 스킵)", True, "스킵됨")
else:
    try:
        from app.services.llm_service import run_doc_l3_contextualizer
        print(f"  L3 전송 전 위반 수: {len(violations_l1)}건")
        violations_l3 = run_doc_l3_contextualizer(violations_l1, doc_preprocess)
        print(f"  L3 처리 후 위반 수: {len(violations_l3)}건")

        removed = len(violations_l1) - len(violations_l3)
        record("L3 실행 완료", True, f"제거된 FP={removed}건")

        print("\n  [타깃 5개 L3 최종 결과]")
        for rid in sorted(TARGET_RULES):
            remaining = [v for v in violations_l3 if v.get("rule_id") == rid]
            conf = remaining[0].get("confidence", "미판정") if remaining else "-"
            record(f"L3 최종: {rid}", len(remaining) > 0, f"confidence={conf}")

    except Exception as e:
        record("L3 실행 실패", False, str(e)[:100])

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
