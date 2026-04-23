"""
CFB-LEA-001 단독 테스트 러너.

동작
- create_cfb_rule_test_zip.py 로 fail/pass ZIP 생성
- 각 ZIP을 job 으로 업로드 → run_preprocess → run_rule_engine 실행
- 알고리즘: LEA, 모드: CFB 로 한정
- 기대:
  - fail ZIP  : CFB-LEA-001 이 L1 위반으로 반드시 포함
  - pass ZIP  : CFB-LEA-001 이 위반으로 나오지 않음
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Dict, Any, List, Set


BACKEND = Path(__file__).resolve().parent.parent
RULES_DIR = BACKEND / "rules"
sys.path.insert(0, str(BACKEND))

from app.services.preprocess_service import run_preprocess
from app.services.rule_engine_service import run_rule_engine
from app.services.symbol_graph_service import build_symbol_graph
from app.services.upload_service import create_job_from_upload, get_job_root

from scripts.create_cfb_rule_test_zip import ZIP_FAIL, ZIP_PASS, main as generate_main


EXPECTED_ID = "CFB-LEA-001"


def _extract_rule_ids(violations: List[Dict[str, Any]]) -> Set[str]:
    return { (v.get("rule_id") or "").strip() for v in violations if v.get("rule_id") }


def _run_case(zip_path: Path) -> Dict[str, Any]:
    print(f"\n=== CFB case: {zip_path.name} ===")
    job_id = create_job_from_upload(zip_path.read_bytes(), zip_path.name)
    root = get_job_root(job_id)

    print("[CFB] preprocess...")
    pre = run_preprocess(root)
    print("  files:", len(pre.get("files", [])), "errors:", len(pre.get("errors", [])))

    print("[CFB] symbol_graph...")
    sym = build_symbol_graph(pre)

    print("[CFB] run_rule_engine (algorithm=LEA, mode=CFB)...")
    vios = run_rule_engine(
        preprocess_result=pre,
        rules_dir=RULES_DIR,
        job_root=root,
        algorithms=["lea"],
        modes=["cfb"],
        symbol_graph=sym,
    )

    rids = _extract_rule_ids(vios)
    print("  rule_ids:", sorted(rids))

    report = {
        "job_id": job_id,
        "zip": zip_path.name,
        "l1": {
            "violations_count": len(vios),
            "rule_ids": sorted(rids),
            "violations": vios,
        },
    }
    (root / "cfb_rule_test_report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return report


def main() -> int:
    # ZIP이 없으면 생성
    if not ZIP_FAIL.exists() or not ZIP_PASS.exists():
        generate_main()

    fail_report = _run_case(ZIP_FAIL)
    pass_report = _run_case(ZIP_PASS)

    fail_ids = set(fail_report["l1"]["rule_ids"])
    pass_ids = set(pass_report["l1"]["rule_ids"])

    ok = True

    if EXPECTED_ID not in fail_ids:
        print(f"[FAIL] 기대 위반 {EXPECTED_ID} 가 fail ZIP 결과에 없음")
        ok = False
    if EXPECTED_ID in pass_ids:
        print(f"[FAIL] {EXPECTED_ID} 가 pass ZIP 결과에 나오면 안 됨")
        ok = False

    print("\n=== CFB-LEA-001 result ===")
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

