"""
DOC L1 파이프라인 통합 테스트.

목표
- run_doc_preprocess → load_doc_rules → run_doc_rule_engine 까지 한 번에 실행하고
- 섹션 수, 로드된 DOC 룰 수, 위반 건수 및 샘플 위반(rule_id, message)을 출력한다.
- DOC-KEYBIZ-SELFTEST 등 keybiz 룰이 설계서 풀텍스트에서 매칭되는지 확인용.

사용법
  cd backend
  python -m scripts.test_doc_l1_pipeline
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List

BACKEND = Path(__file__).resolve().parent.parent
RULES_DIR = BACKEND / "rules"
TESTDATA = BACKEND / "testdata"
JOB_ROOT = BACKEND / "storage" / "jobs" / "doc_preprocess_local"

sys.path.insert(0, str(BACKEND))

from app.services.preprocess_docs_service import run_doc_preprocess
from app.services.doc_rule_service import load_doc_rules, run_doc_rule_engine


def _prepare_job_root() -> Path:
    """backend/testdata/*.pdf 를 JOB_ROOT/docs/design/ 로 복사한다."""
    JOB_ROOT.mkdir(parents=True, exist_ok=True)
    docs_design = JOB_ROOT / "docs" / "design"
    docs_design.mkdir(parents=True, exist_ok=True)

    pdfs: List[Path] = [p for p in TESTDATA.iterdir() if p.is_file() and p.suffix.lower() == ".pdf"]
    for src in pdfs:
        dst = docs_design / src.name
        if not dst.exists():
            dst.write_bytes(src.read_bytes())

    print(f"JOB_ROOT: {JOB_ROOT}")
    print("design PDFs:", [p.name for p in sorted(pdfs)])
    return JOB_ROOT


def main() -> None:
    root = _prepare_job_root()

    print("\n[1/3] run_doc_preprocess...")
    doc_preprocess = run_doc_preprocess(root)
    sections: List[Dict[str, Any]] = doc_preprocess.get("sections") or []
    errors: List[Dict[str, Any]] = doc_preprocess.get("errors") or []
    print(f"  sections: {len(sections)}, errors: {len(errors)}")

    print("\n[2/3] load_doc_rules...")
    doc_rules = load_doc_rules(RULES_DIR)
    print(f"  doc_rules_loaded: {len(doc_rules)}")
    keybiz_rules = [r for r in doc_rules if (r.get("id") or "").startswith("DOC-KEYBIZ")]
    if keybiz_rules:
        print("  keybiz 룰 포함:", [r.get("id") for r in keybiz_rules])

    print("\n[3/3] run_doc_rule_engine...")
    violations_doc = run_doc_rule_engine(doc_preprocess, doc_rules)
    print(f"  violations_count: {len(violations_doc)}")

    print("\n=== DOC L1 파이프라인 요약 ===")
    print("sections:", len(sections))
    print("doc_rules_loaded:", len(doc_rules))
    print("violations_doc:", len(violations_doc))

    if violations_doc:
        print("\n위반 샘플 (최대 10건):")
        for v in violations_doc[:10]:
            print(f"  - rule_id={v.get('rule_id')} doc_type={v.get('doc_type')} message={v.get('message')} path={v.get('path')}")

    keybiz_vios = [v for v in violations_doc if v.get("rule_id") == "DOC-KEYBIZ-SELFTEST"]
    if keybiz_vios:
        print("\n[OK] DOC-KEYBIZ-SELFTEST 매칭됨 (keybiz 설계서에 '9. 자가시험' 존재):", len(keybiz_vios), "건")
    else:
        print("\n[INFO] DOC-KEYBIZ-SELFTEST 위반 없음 (패턴이 없거나 룰이 design 풀텍스트에 적용되지 않음)")


if __name__ == "__main__":
    main()
