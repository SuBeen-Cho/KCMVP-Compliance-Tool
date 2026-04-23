"""
LEA 모드 룰셋 테스트 러너.

동작
- create_lea_mode_rules_test_zip.py 로 fail/pass 테스트 ZIP을 준비
- 각 ZIP을 job으로 업로드한 뒤, run_rule_engine(L1) + doc_preprocess(DOC)까지 실행
- fail 케이스에서는 기대되는 "새로 추가된 모드 룰" rule_id 가 위반으로 나오는지 확인
- pass 케이스에서는 기대되는 모드 룰이 위반으로 나오지 않는지 확인(부분/부드러운 검증)

주의(중요)
- 현재 L1 룰 엔진은 YAML의 pattern_type 이 "missing" 또는 "regex" 인 룰만 적용합니다.
  "semantic" 룰은 L1에서 제외됩니다. 따라서 CCM-001/CCM-004/GCM-001/GCM-003 등 semantic 기반 룰은
  이 스크립트에서 "L1" 기준으로는 검증되지 않습니다.

실행 예시
  cd backend
  python scripts/test_lea_mode_rules_v2.py

특정 PDF 사용
  python scripts/test_lea_mode_rules_v2.py --design-pdf "testdata/설계서.pdf"
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, Any, List, Set


BACKEND = Path(__file__).resolve().parent.parent
RULES_DIR = BACKEND / "rules"

sys.path.insert(0, str(BACKEND))

from app.services.preprocess_service import run_preprocess
from app.services.preprocess_docs_service import run_doc_preprocess
from app.services.rule_engine_service import run_rule_engine
from app.services.doc_rule_service import load_doc_rules, run_doc_rule_engine
from app.services.symbol_graph_service import build_symbol_graph
from app.services.upload_service import create_job_from_upload, get_job_root, save_single_doc_to_job

from scripts.create_lea_mode_rules_test_zip import ZIP_FAIL, ZIP_PASS, main as generate_main


DEFAULT_DESIGN_PDF = BACKEND / "testdata" / "설계서.pdf"


EXPECTED_FAIL_RULE_IDS: Set[str] = {
    # CCM (regex/missing)
    "CCM-002",
    "CCM-003",
    "CCM-LEA-001",
    # GCM (regex/missing)
    "GCM-002",
    "GCM-LEA-001",
    "GCM-LEA-002",
    # CFB (missing)
    "CFB-LEA-001",
    # OFB (regex/missing)
    "OFB-001",
    "OFB-LEA-001",
    # CMAC (missing)
    "CMAC-LEA-001",
    # Common: 온라인 API 함수명 규격(missing)
    "COM-006",
}


def _extract_rule_ids(violations: List[Dict[str, Any]]) -> Set[str]:
    rids: Set[str] = set()
    for v in violations:
        rid = (v.get("rule_id") or "").strip()
        if rid:
            rids.add(rid)
    return rids


def _load_all_relevant_rules() -> Dict[str, Any]:
    """
    현재 테스트에서 사용하는 룰셋 메타 정보 수집.
    - algorithm/lea.yaml
    - mode/{ccm,gcm,cfb,ofb,cmac}.yaml
    - common/security.yaml
    """
    import yaml

    out: Dict[str, Any] = {"all": [], "by_pattern_type": {}}

    def _load_yaml(path: Path) -> List[Dict[str, Any]]:
        if not path.is_file():
            return []
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return data.get("rules", []) or []

    algo_rules = _load_yaml(RULES_DIR / "algorithm" / "lea.yaml")
    mode_files = ["ccm.yaml", "gcm.yaml", "cfb.yaml", "ofb.yaml", "cmac.yaml"]
    mode_rules: List[Dict[str, Any]] = []
    for name in mode_files:
        mode_rules.extend(_load_yaml(RULES_DIR / "mode" / name))
    common_rules = _load_yaml(RULES_DIR / "common" / "security.yaml")

    all_rules: List[Dict[str, Any]] = []
    all_rules.extend(algo_rules)
    all_rules.extend(mode_rules)
    all_rules.extend(common_rules)

    by_pattern: Dict[str, List[str]] = {}
    for r in all_rules:
        rid = r.get("id") or ""
        pt = (r.get("pattern_type") or "").lower()
        by_pattern.setdefault(pt, []).append(rid)

    out["all"] = all_rules
    out["by_pattern_type"] = by_pattern
    return out


def _run_one_case(*, zip_path: Path, design_pdf: Path, modes: List[str]) -> Dict[str, Any]:
    print(f"\n=== Running case: {zip_path.name} ===")
    job_id = create_job_from_upload(zip_path.read_bytes(), zip_path.name)
    root = get_job_root(job_id)

    save_single_doc_to_job(
        job_id=job_id,
        file_content=design_pdf.read_bytes(),
        filename=design_pdf.name,
        doc_type="design",
    )

    print("[L1] preprocess...")
    preprocess_result = run_preprocess(root)

    print("[L1] symbol_graph...")
    symbol_graph = build_symbol_graph(preprocess_result)

    print("[L1] run_rule_engine...")
    violations_l1 = run_rule_engine(
        preprocess_result=preprocess_result,
        rules_dir=RULES_DIR,
        job_root=root,
        algorithms=["lea"],
        modes=modes,
        symbol_graph=symbol_graph,
    )

    print("[DOC] doc_preprocess...")
    doc_pre = run_doc_preprocess(root)
    print("[DOC] load_doc_rules + run_doc_rule_engine...")
    doc_rules = load_doc_rules(RULES_DIR)
    violations_doc = run_doc_rule_engine(doc_pre, doc_rules)

    # 룰 메타데이터도 함께 포함 (ast/semantic vs missing/regex 구분용)
    rules_meta = _load_all_relevant_rules()

    # Save report for later debugging
    report = {
        "job_id": job_id,
        "zip": zip_path.name,
        "design_pdf": design_pdf.name,
        "preprocess": {
            "file_count": len(preprocess_result.get("files", [])),
            "errors_count": len(preprocess_result.get("errors", [])),
        },
        "l1": {
            "violations_count": len(violations_l1),
            "rule_ids": sorted(_extract_rule_ids(violations_l1)),
            "violations": violations_l1,
        },
        "doc": {
            "doc_rules_loaded": len(doc_rules),
            "violations_count": len(violations_doc),
            "rule_ids": sorted(_extract_rule_ids(violations_doc)),
            "violations": violations_doc,
        },
        "rules_meta": {
            "by_pattern_type": rules_meta["by_pattern_type"],
        },
    }

    (root / "mode_rules_test_report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return report


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--design-pdf",
        type=str,
        default=str(DEFAULT_DESIGN_PDF),
        help="job/docs/design에 업로드할 PDF 경로",
    )
    ap.add_argument(
        "--regen",
        action="store_true",
        help="테스트 ZIP을 재생성",
    )
    ap.add_argument(
        "--case",
        choices=["fail", "pass", "both"],
        default="both",
    )
    ap.add_argument(
        "--modes",
        type=str,
        default="CCM,GCM,CFB,OFB,CMAC",
        help="run_rule_engine에서 로드할 모드 룰셋 목록",
    )
    args = ap.parse_args()

    design_pdf = Path(args.design_pdf)
    if not design_pdf.is_file():
        print(f"[ERR] design-pdf not found: {design_pdf}")
        return 2

    if args.regen:
        generate_main()
    else:
        # 없으면 자동 생성
        if not ZIP_FAIL.exists() or not ZIP_PASS.exists():
            generate_main()

    modes = [m.strip().upper() for m in args.modes.split(",") if m.strip()]
    # run_rule_engine은 내부에서 lower()로 파일을 찾음
    modes_lower = [m.lower() for m in modes]

    selected: List[Path] = []
    if args.case in {"fail", "both"}:
        selected.append(ZIP_FAIL)
    if args.case in {"pass", "both"}:
        selected.append(ZIP_PASS)

    pass_all = True

    # 룰 메타 정보(semantic/ast vs missing/regex) 한 번만 로드
    rules_meta = _load_all_relevant_rules()
    by_pattern = rules_meta["by_pattern_type"]
    non_l1_ids = sorted(set(by_pattern.get("semantic", [])) | set(by_pattern.get("ast", [])))
    l1_candidate_ids = sorted(set(by_pattern.get("missing", [])) | set(by_pattern.get("regex", [])))

    print("\n=== Rule pattern_type 요약 ===")
    print("  missing :", l1_candidate_ids[:20], ("..." if len(l1_candidate_ids) > 20 else ""))
    print("  semantic:", by_pattern.get("semantic", [])[:20], ("..." if len(by_pattern.get("semantic", [])) > 20 else ""))
    print("  ast     :", by_pattern.get("ast", [])[:20], ("..." if len(by_pattern.get("ast", [])) > 20 else ""))

    for zip_path in selected:
        report = _run_one_case(zip_path=zip_path, design_pdf=design_pdf, modes=modes_lower)
        l1_rule_ids = set(report["l1"]["rule_ids"])
        # L1에서 실제로 검사되지 않는 semantic/ast 룰 중, 이 ZIP에서 트리거되지 않은 목록
        non_tested_non_l1 = sorted(set(non_l1_ids) - l1_rule_ids)

        if zip_path.name == ZIP_FAIL.name:
            missing = sorted(EXPECTED_FAIL_RULE_IDS - l1_rule_ids)
            unexpected_extra = sorted(l1_rule_ids - EXPECTED_FAIL_RULE_IDS)

            print(f"\n[FAIL CASE] L1 rule_id count={len(l1_rule_ids)}")
            print("[FAIL CASE] expected missing:", missing if missing else "None")
            print("[FAIL CASE] unexpected extra (may be OK):", unexpected_extra[:30])
            print("[FAIL CASE] non-L1(ast/semantic) rules not tested in this run:", non_tested_non_l1[:30])

            if missing:
                pass_all = False

        if zip_path.name == ZIP_PASS.name:
            # fail case에서 기대했던 rule_id는 pass에서 나오면 안 됨(부드러운 검증)
            unexpected = sorted(EXPECTED_FAIL_RULE_IDS & l1_rule_ids)
            print(f"\n[PASS CASE] L1 rule_id count={len(l1_rule_ids)}")
            print("[PASS CASE] unexpected (should not appear):", unexpected if unexpected else "None")
            if unexpected:
                pass_all = False

    print("\n=== Result ===")
    print("PASS" if pass_all else "FAIL")
    return 0 if pass_all else 1


if __name__ == "__main__":
    sys.exit(main())

