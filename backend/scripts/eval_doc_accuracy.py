"""
DOC 규칙별 정확도 평가 스크립트 (Phase 0 기준선 측정용)

ground_truth_design.json 기반으로 rule-level Precision / Recall / F1 계산.

Usage:
    cd backend
    source venv/bin/activate
    python scripts/eval_doc_accuracy.py                          # L1+L2
    python scripts/eval_doc_accuracy.py --no-l2                 # L1만
    python scripts/eval_doc_accuracy.py --gt custom_gt.json     # 다른 GT 파일

Output:
    - 문서별 탐지/미탐지 규칙 목록
    - Rule-level TP/FP/FN 집계
    - Precision / Recall / F1
    - FP 규칙 목록 (오탐 분석용)
    - FN 규칙 목록 (미탐 분석용)
"""

import sys
import json
import shutil
import tempfile
import argparse
from pathlib import Path
from datetime import datetime

BACKEND_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(BACKEND_ROOT))

from app.services.preprocess_docs_service import run_doc_preprocess
from app.services.doc_rule_service import load_doc_rules, run_doc_rule_engine
from app.services.llm.doc_judge import run_doc_l2_contextualizer


TESTDATA_DIR = BACKEND_ROOT / "testdata"
DEFAULT_GT = TESTDATA_DIR / "ground_truth_design.json"


def load_ground_truth(gt_path: Path) -> dict:
    with open(gt_path, encoding="utf-8") as f:
        return json.load(f)


def run_pdf(pdf_path: Path, doc_type: str, rules: list, use_l2: bool):
    """단일 PDF 평가 → (l1_violation_ids, final_violation_ids)"""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        dest = tmp / "docs" / doc_type
        dest.mkdir(parents=True)
        shutil.copy(pdf_path, dest / pdf_path.name)

        preprocess = run_doc_preprocess(tmp)
        l1_viols = run_doc_rule_engine(preprocess, rules)
        if use_l2 and l1_viols:
            final = run_doc_l2_contextualizer(l1_viols, preprocess)
        else:
            final = l1_viols

    l1_ids = {v.get("rule_id") for v in l1_viols}
    final_ids = {v.get("rule_id") for v in final}
    return l1_ids, final_ids


def evaluate(gt_path: Path = DEFAULT_GT, use_l2: bool = True):
    gt = load_ground_truth(gt_path)
    rules = load_doc_rules(BACKEND_ROOT / "rules")
    print(f"\n{'='*70}")
    print(f"DOC Rule-Level Accuracy Evaluation")
    print(f"GT: {gt_path.name}  |  L2: {'on' if use_l2 else 'off'}")
    print(f"규칙: {len(rules)}개  |  평가 문서: {len(gt['documents'])}개")
    print(f"{'='*70}")

    # rule-level accumulators
    rule_tp: dict[str, int] = {}
    rule_fp: dict[str, int] = {}
    rule_fn: dict[str, int] = {}

    doc_results = []

    for doc in gt["documents"]:
        filename = doc["filename"]
        doc_type = doc.get("doc_type", "design")
        pdf_path = TESTDATA_DIR / filename

        if not pdf_path.exists():
            print(f"\n[SKIP] {filename} — 파일 없음")
            continue

        print(f"\n[{doc['confidence'].upper()}] {filename}")
        print(f"  {doc['description']}")

        l1_ids, final_ids = run_pdf(pdf_path, doc_type, rules, use_l2)

        expected_viol_ids = set(doc.get("expected_violations", {}).keys())
        expected_pass_ids = set(doc.get("expected_passes", {}).keys())

        # Rule-level evaluation (only for annotated rules)
        all_annotated = expected_viol_ids | expected_pass_ids

        doc_tp, doc_fp, doc_fn, doc_tn = [], [], [], []

        for rid in sorted(all_annotated):
            detected = rid in final_ids
            expected_viol = rid in expected_viol_ids

            if expected_viol and detected:
                doc_tp.append(rid)
                rule_tp[rid] = rule_tp.get(rid, 0) + 1
            elif not expected_viol and detected:
                doc_fp.append(rid)
                rule_fp[rid] = rule_fp.get(rid, 0) + 1
            elif expected_viol and not detected:
                doc_fn.append(rid)
                rule_fn[rid] = rule_fn.get(rid, 0) + 1
            else:
                doc_tn.append(rid)

        # Print per-rule details
        if doc_tp:
            print(f"  TP (올바르게 탐지):  {doc_tp}")
        if doc_fp:
            print(f"  FP (오탐):           {doc_fp}")
        if doc_fn:
            print(f"  FN (미탐):           {doc_fn}")
        if doc_tn:
            print(f"  TN (올바르게 통과):  {doc_tn}")

        # Additional uncharted detections (not in GT)
        extra = final_ids - all_annotated
        if extra:
            print(f"  [미주석 탐지]:       {sorted(extra)} (GT에 없음 — 수동 검토 필요)")

        l2_filtered = l1_ids - final_ids
        if l2_filtered:
            print(f"  [L2 필터 제거]:      {sorted(l2_filtered)}")

        doc_results.append({
            "filename": filename,
            "l1_ids": sorted(l1_ids),
            "final_ids": sorted(final_ids),
            "expected_violations": sorted(expected_viol_ids),
            "expected_passes": sorted(expected_pass_ids),
            "TP": doc_tp, "FP": doc_fp, "FN": doc_fn, "TN": doc_tn,
            "extra_detections": sorted(extra),
        })

    # ── 전체 집계 ──────────────────────────────────────────────────────────
    total_tp = sum(rule_tp.values())
    total_fp = sum(rule_fp.values())
    total_fn = sum(rule_fn.values())

    precision = total_tp / (total_tp + total_fp) * 100 if (total_tp + total_fp) > 0 else 100.0
    recall    = total_tp / (total_tp + total_fn) * 100 if (total_tp + total_fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) > 0 else 0.0)

    print(f"\n{'='*70}")
    print(f"RULE-LEVEL RESULTS  (주석된 규칙만 집계)")
    print(f"  TP={total_tp}  FP={total_fp}  FN={total_fn}")
    print(f"  Precision = {precision:.1f}%")
    print(f"  Recall    = {recall:.1f}%")
    print(f"  F1        = {f1:.1f}%")
    print(f"{'─'*70}")

    if rule_fp:
        print(f"\n[FP 규칙 — 오탐 분석]")
        for rid in sorted(rule_fp):
            print(f"  {rid}  (발생 횟수: {rule_fp[rid]})")

    if rule_fn:
        print(f"\n[FN 규칙 — 미탐 분석]")
        for rid in sorted(rule_fn):
            print(f"  {rid}  (발생 횟수: {rule_fn[rid]})")

    if rule_tp:
        print(f"\n[TP 규칙 — 올바르게 탐지]")
        for rid in sorted(rule_tp):
            print(f"  {rid}  (발생 횟수: {rule_tp[rid]})")

    print(f"\n[참고] 미주석 탐지 항목은 FP/FN에 포함되지 않음 — 수동 검토 후 GT 업데이트 권장")
    print(f"{'='*70}\n")

    return {
        "timestamp": datetime.now().isoformat(),
        "l2_enabled": use_l2,
        "rule_tp": rule_tp, "rule_fp": rule_fp, "rule_fn": rule_fn,
        "precision": round(precision, 1),
        "recall": round(recall, 1),
        "f1": round(f1, 1),
        "doc_results": doc_results,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DOC rule-level accuracy evaluation")
    parser.add_argument("--gt", type=Path, default=DEFAULT_GT,
                        help="Ground truth JSON path")
    parser.add_argument("--no-l2", action="store_true",
                        help="Skip L2 Gemini re-judgment")
    args = parser.parse_args()

    result = evaluate(gt_path=args.gt, use_l2=not args.no_l2)

    # Save result JSON next to this script
    out_path = BACKEND_ROOT / "scripts" / f"eval_result_{datetime.now().strftime('%Y%m%d_%H%M')}.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"결과 저장: {out_path}")
