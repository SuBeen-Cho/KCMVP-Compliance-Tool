"""
DOC 정확도 평가 스크립트 (L1 doc_rule_engine + L3 doc_l3_contextualizer)

각 PDF를 독립적으로 평가 (실제 제출 시나리오: 문서 타입별 1개 제출).

Usage:
    python scripts/run_doc_accuracy.py [zip_path]
    python scripts/run_doc_accuracy.py testdata/doc_accuracy_test_v1.zip --no-l3

Ground Truth 형식 (GROUND_TRUTH.md):
  파일명 | P/N | 위반규칙(comma) | 설명

평가 기준 (파일 레벨):
  - P-case: 해당 파일만 단독으로 룰 엔진 실행 → 위반 있으면 TP, 없으면 FN
  - N-case: 해당 파일만 단독으로 룰 엔진 실행 → 위반 없으면 TN, 있으면 FP
"""

import sys
import zipfile
import tempfile
import shutil
from pathlib import Path
from collections import defaultdict

BACKEND_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(BACKEND_ROOT))

from app.services.preprocess_docs_service import run_doc_preprocess
from app.services.doc_rule_service import load_doc_rules, run_doc_rule_engine
from app.services.llm_service import run_doc_l3_contextualizer


def parse_ground_truth(text: str):
    p_cases, n_cases = [], []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "|" not in line:
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 3:
            continue
        filename = parts[0]
        label = parts[1].upper()
        rule_ids_str = parts[2] if len(parts) > 2 else "-"
        desc = parts[3] if len(parts) > 3 else ""
        rule_ids = [r.strip() for r in rule_ids_str.split(",")
                    if r.strip() and r.strip() != "-"]
        if label == "P":
            p_cases.append((filename, rule_ids, desc))
        elif label == "N":
            n_cases.append((filename, [], desc))
    return p_cases, n_cases


def _eval_single_pdf(pdf_path: Path, doc_type: str,
                     rules, use_l3: bool) -> tuple[list, list]:
    """단일 PDF를 독립적으로 평가 → (l1_violations, final_violations)"""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        # docs/{doc_type}/ 구조로 배치
        dest_dir = tmp / "docs" / doc_type
        dest_dir.mkdir(parents=True)
        shutil.copy(pdf_path, dest_dir / pdf_path.name)

        preprocess = run_doc_preprocess(tmp)
        l1_viols = run_doc_rule_engine(preprocess, rules)
        if use_l3 and l1_viols:
            final = run_doc_l3_contextualizer(l1_viols, preprocess)
        else:
            final = l1_viols
    return l1_viols, final


def run_doc_eval(zip_path: str, use_l3: bool = True):
    print(f"\n{'='*65}")
    print(f"DOC 정확도 평가: {zip_path}")
    print(f"L3 사용: {'예 (Gemini)' if use_l3 else '아니오 (L1만)'}")
    print(f"{'='*65}")

    rules_dir = BACKEND_ROOT / "rules"
    doc_rules = load_doc_rules(rules_dir)
    print(f"규칙 수: {len(doc_rules)}개\n")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(tmp)
            gt_text = zf.read("GROUND_TRUTH.md").decode("utf-8")

        p_cases, n_cases = parse_ground_truth(gt_text)
        print(f"Ground Truth: P={len(p_cases)}, N={len(n_cases)}")

        # ── 파일별 개별 평가 ─────────────────────────────────────────
        results: dict = {}  # filename → {l1_viol_ids, final_viol_ids}
        all_cases = [(f, rids, desc, "P") for f, rids, desc in p_cases] + \
                    [(f, [], desc, "N") for f, _, desc in n_cases]

        for filename, expected_rids, desc, label in all_cases:
            pdf_path = tmp / "docs" / filename
            if not pdf_path.exists():
                print(f"  [WARN] 파일 없음: {pdf_path}")
                results[filename] = {"l1": set(), "final": set(), "error": "not found"}
                continue

            # doc_type 추출: docs/design/xxx.pdf → "design"
            parts = Path(filename).parts
            doc_type = parts[0] if len(parts) >= 2 else "design"

            l1_viols, final_viols = _eval_single_pdf(pdf_path, doc_type, doc_rules, use_l3)
            l1_ids = {v.get("rule_id") for v in l1_viols}
            final_ids = {v.get("rule_id") for v in final_viols}

            results[filename] = {"l1": l1_ids, "final": final_ids}
            status_icon = "✓" if (final_ids and label == "P") or (not final_ids and label == "N") else "✗"
            print(f"  {status_icon} [{label}] {filename}")
            if l1_ids != final_ids:
                print(f"       L1: {sorted(l1_ids)}")
                print(f"       L3후: {sorted(final_ids)}")
            else:
                print(f"       탐지: {sorted(final_ids) if final_ids else '없음'}")

        # ── 정확도 계산 ───────────────────────────────────────────────
        print(f"\n{'─'*65}")
        TP = FP = FN = TN = 0
        fn_details, fp_details = [], []

        for filename, expected_rids, desc in p_cases:
            final_ids = results.get(filename, {}).get("final", set())
            if final_ids:
                TP += 1
            else:
                FN += 1
                fn_details.append((filename, expected_rids, desc,
                                   results.get(filename, {}).get("l1", set())))

        for filename, _, desc in n_cases:
            final_ids = results.get(filename, {}).get("final", set())
            if not final_ids:
                TN += 1
            else:
                FP += 1
                fp_details.append((filename, desc, final_ids))

        precision = TP / (TP + FP) * 100 if (TP + FP) > 0 else 100.0
        recall    = TP / (TP + FN) * 100 if (TP + FN) > 0 else 100.0
        f1 = (2 * precision * recall / (precision + recall)
              if (precision + recall) > 0 else 0.0)

        print(f"  TP={TP}  FP={FP}  FN={FN}  TN={TN}")
        print(f"  Precision={precision:.1f}%  Recall={recall:.1f}%  F1={f1:.1f}%")
        print(f"{'─'*65}")

        if fn_details:
            print(f"\n[FN — 미탐지]")
            for fname, expected, desc, l1_ids in fn_details:
                print(f"  FN | {fname}")
                print(f"       기대 위반: {expected}")
                print(f"       L1 탐지:  {sorted(l1_ids)}")
                print(f"       설명: {desc}")

        if fp_details:
            print(f"\n[FP — 오탐]")
            for fname, desc, detected in fp_details:
                print(f"  FP | {fname}: {sorted(detected)}")

        # ── P-case 규칙별 세부 분석 ──────────────────────────────────
        print(f"\n[P-case 규칙별 탐지 현황]")
        for filename, expected_rids, desc in p_cases:
            final_ids = results.get(filename, {}).get("final", set())
            l1_ids = results.get(filename, {}).get("l1", set())
            print(f"\n  {filename} ({desc})")
            print(f"  {'규칙ID':<12} {'기대':<6} {'L1탐지':<8} {'L3최종':<8}")
            print(f"  {'-'*40}")
            all_rids = sorted(set(expected_rids) | l1_ids | final_ids)
            for rid in all_rids:
                exp = "P" if rid in expected_rids else " "
                l1_det = "Y" if rid in l1_ids else "N"
                fin_det = "Y" if rid in final_ids else "N"
                ok = "✓" if (rid in expected_rids) == (rid in final_ids) else "✗"
                print(f"  {rid:<12} {exp:<6} {l1_det:<8} {fin_det:<8} {ok}")

        return {"TP": TP, "FP": FP, "FN": FN, "TN": TN,
                "precision": precision, "recall": recall, "f1": f1,
                "results": results}


if __name__ == "__main__":
    zip_path = sys.argv[1] if len(sys.argv) > 1 else "testdata/doc_accuracy_test_v1.zip"
    use_l3 = "--no-l3" not in sys.argv
    run_doc_eval(zip_path, use_l3=use_l3)
