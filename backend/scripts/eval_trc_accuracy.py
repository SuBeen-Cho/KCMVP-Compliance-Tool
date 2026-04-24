"""
TRC (Traceability) 정확도 평가 스크립트

사전 분석된 job의 TRC 위반 결과를 Ground Truth와 비교하여
rule-level Precision / Recall / F1을 계산.

Usage:
    cd backend
    source venv/bin/activate
    python scripts/eval_trc_accuracy.py
    python scripts/eval_trc_accuracy.py --job-id <job_id>  # 특정 job 지정

Output:
    - TRC 규칙별 TP/FP/FN
    - Precision / Recall / F1
    - TRC 유형별(trc_type) 분류 통계
"""

import sys
import json
import os
import argparse
from pathlib import Path
from datetime import datetime

BACKEND_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(BACKEND_ROOT))

from app.config import settings
from app.services.traceability_service import run_traceability_checks, build_code_index
import yaml


JOBS_ROOT = BACKEND_ROOT / settings.STORAGE_ROOT / settings.JOB_DATA_DIR


# ─────────────────────────────────────────────────────────────────
# 내장 Ground Truth (TRC)
# design doc에서 선언된 에러 코드가 코드에 없는 경우 등 알려진 위반
# ─────────────────────────────────────────────────────────────────
_BUILTIN_GT = {
    # job c404e272 — fake_design_doc.pdf + LEA 벤치마크 코드
    "c404e272-f6a3-449d-a32d-bed6477fee18": {
        "expected_violations": [
            "TRC-002",  # LEA_ERR_INVALID_KEY 코드 미정의
            "TRC-002",  # LEA_ERR_MODULE_NOT_READY 코드 미정의
            "TRC-002",  # MODULE_STATE_ERROR 코드 미정의
            "TRC-002",  # LEA_ERR_SELFTEST_FAIL 코드 미정의
            "TRC-002",  # LEA_ERR_INTEGRITY_FAIL 코드 미정의
            "TRC-002",  # LEA_ERR_NULL_PTR 코드 미정의
        ],
        "expected_passes": [
            "TRC-003",  # 시험서 없으므로 TRC-003 미발동
        ],
    }
}


def load_trc_rules():
    trc_path = BACKEND_ROOT / "rules" / "traceability" / "traceability.yaml"
    with open(trc_path, encoding="utf-8") as f:
        return yaml.safe_load(f).get("rules", [])


def evaluate_job(job_id: str, verbose: bool = True) -> dict:
    """단일 job에 대해 TRC 평가 실행."""
    job_path = JOBS_ROOT / job_id

    # 전처리 결과 로드
    pp_path = job_path / "preprocess_result.json"
    doc_path = job_path / "doc_preprocess_result.json"

    if not pp_path.exists():
        print(f"  [SKIP] {job_id[:8]}: preprocess_result.json 없음")
        return {}

    pp = json.loads(pp_path.read_text(encoding="utf-8"))
    doc = json.loads(doc_path.read_text(encoding="utf-8")) if doc_path.exists() else {"sections": []}

    design_secs = [s for s in doc.get("sections", []) if (s.get("doc_type") or "").lower() == "design"]
    test_secs   = [s for s in doc.get("sections", []) if (s.get("doc_type") or "").lower() == "test"]

    if not design_secs and not test_secs:
        print(f"  [SKIP] {job_id[:8]}: 설계서/시험서 섹션 없음")
        return {}

    # symbol graph 로드 (TRC-004)
    sg_path = job_path / "symbol_graph.json"
    symbol_graph = json.loads(sg_path.read_text(encoding="utf-8")) if sg_path.exists() else None

    code_index = build_code_index(pp)
    rules = load_trc_rules()

    violations = run_traceability_checks(
        design_doc={"sections": design_secs},
        code_index=code_index,
        test_doc={"sections": test_secs},
        rules=rules,
        symbol_graph=symbol_graph,
    )

    # 통계
    by_rule = {}
    by_type = {}
    for v in violations:
        rid = v.get("rule_id", "unknown")
        ttype = v.get("trc_type", "unknown")
        by_rule[rid] = by_rule.get(rid, 0) + 1
        by_type[ttype] = by_type.get(ttype, 0) + 1

    hf_count = len(code_index.get("header_funcs", {}))
    sf_count = len(code_index.get("source_funcs", {}))
    ec_count = len(code_index.get("error_codes",  {}))

    result = {
        "job_id": job_id,
        "design_sections": len(design_secs),
        "test_sections": len(test_secs),
        "header_funcs": hf_count,
        "source_funcs": sf_count,
        "error_codes": ec_count,
        "total_violations": len(violations),
        "by_rule": by_rule,
        "by_type": by_type,
        "violations": violations,
    }

    if verbose:
        print(f"\nJob {job_id[:8]}...")
        print(f"  Code index: header_funcs={hf_count}, source_funcs={sf_count}, error_codes={ec_count}")
        print(f"  Doc: design_secs={len(design_secs)}, test_secs={len(test_secs)}")
        print(f"  TRC violations: {len(violations)}건")
        for rid, cnt in sorted(by_rule.items()):
            print(f"    {rid}: {cnt}건")

    return result


def run_builtin_gt_eval(results: dict) -> None:
    """내장 GT 기반 TRC-002 정확도 평가."""
    print("\n" + "=" * 60)
    print("  내장 GT 기반 TRC-002 정확도 평가")
    print("=" * 60)

    for job_id, gt in _BUILTIN_GT.items():
        if job_id not in results:
            continue
        job_res = results[job_id]
        viols = job_res.get("violations", [])

        expected_rules = set(gt.get("expected_violations", []))
        detected_rules = {v.get("rule_id") for v in viols}

        # Rule-level TP/FP/FN
        tp = len(expected_rules & detected_rules)
        fp = len(detected_rules - expected_rules)
        fn = len(expected_rules - detected_rules)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall    = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        print(f"\nJob {job_id[:8]}:")
        print(f"  TP={tp} FP={fp} FN={fn}")
        print(f"  Precision={precision:.1%}  Recall={recall:.1%}  F1={f1:.1%}")

        # TRC-002 instance-level
        trc002_viols = [v for v in viols if v.get("rule_id") == "TRC-002"]
        gt_trc002_count = sum(1 for r in gt.get("expected_violations", []) if r == "TRC-002")
        print(f"  TRC-002 인스턴스: 탐지 {len(trc002_viols)}건 / GT {gt_trc002_count}건")


def main():
    parser = argparse.ArgumentParser(description="TRC 정확도 평가")
    parser.add_argument("--job-id", default=None, help="특정 job ID (미지정 시 모든 job)")
    parser.add_argument("--save", action="store_true", help="결과 JSON 저장")
    args = parser.parse_args()

    print("TRC 정확도 평가 시작\n")

    all_results = {}
    if args.job_id:
        res = evaluate_job(args.job_id)
        if res:
            all_results[args.job_id] = res
    else:
        if not JOBS_ROOT.exists():
            print(f"Jobs 디렉토리 없음: {JOBS_ROOT}")
            return

        for job_id in sorted(os.listdir(JOBS_ROOT)):
            job_path = JOBS_ROOT / job_id
            if not job_path.is_dir():
                continue
            res = evaluate_job(job_id, verbose=True)
            if res:
                all_results[job_id] = res

    # 통계 요약
    print("\n" + "=" * 60)
    print("  전체 요약")
    print("=" * 60)
    jobs_with_viols = {jid: r for jid, r in all_results.items() if r.get("total_violations", 0) > 0}
    print(f"TRC 위반 발생 job: {len(jobs_with_viols)}/{len(all_results)}개")

    # 규칙별 집계
    rule_totals = {}
    type_totals = {}
    for r in all_results.values():
        for rule, cnt in r.get("by_rule", {}).items():
            rule_totals[rule] = rule_totals.get(rule, 0) + cnt
        for t, cnt in r.get("by_type", {}).items():
            type_totals[t] = type_totals.get(t, 0) + cnt

    if rule_totals:
        print("\n규칙별 위반 총계:")
        for rule, cnt in sorted(rule_totals.items()):
            print(f"  {rule}: {cnt}건")
        print("\n유형별 위반 총계:")
        for ttype, cnt in sorted(type_totals.items()):
            print(f"  {ttype}: {cnt}건")

    run_builtin_gt_eval(all_results)

    if args.save:
        ts = datetime.now().strftime("%Y%m%d_%H%M")
        out_path = BACKEND_ROOT / "scripts" / f"eval_trc_{ts}.json"
        out = {jid: {k: v for k, v in r.items() if k != "violations"} for jid, r in all_results.items()}
        out_path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\n결과 저장: {out_path}")


if __name__ == "__main__":
    main()
