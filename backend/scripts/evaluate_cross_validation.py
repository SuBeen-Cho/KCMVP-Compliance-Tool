"""
Phase 4: 4-Fold Leave-One-Out Cross-Validation
===============================================
기존 4세트에서 LOO를 수행하여 overfitting 여부를 검증.

각 fold에서:
- 3세트의 결과를 관찰 (L3 confidence 임계값 최적화)
- 나머지 1세트에서 해당 임계값으로 평가
- train recall vs test recall 비교

Usage:
    cd backend
    python scripts/evaluate_cross_validation.py
"""

import sys, os, json, math
from pathlib import Path
from datetime import datetime

BACKEND_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(BACKEND_ROOT))

EVAL_RESULTS = BACKEND_ROOT / "scripts" / "evaluation_results.json"


def main():
    print("=" * 65)
    print("Phase 4: 4-Fold Leave-One-Out Cross-Validation")
    print("=" * 65)

    if not EVAL_RESULTS.exists():
        print("[ERROR] evaluation_results.json 없음. evaluate_real_sets.py를 먼저 실행하세요.")
        return

    data = json.loads(EVAL_RESULTS.read_text(encoding="utf-8"))
    code_results = data.get("code_results", [])

    if len(code_results) < 4:
        print(f"[ERROR] 4세트 결과 필요, 현재 {len(code_results)}세트")
        return

    # 세트별 데이터 추출
    sets = []
    for r in code_results:
        sets.append({
            "name": r["set_name"],
            "gt": r["gt_count"],
            "tp": r["TP"],
            "fn": r["FN"],
            "fp_extra": r["FP_extra"],
            "l3_rejected": r.get("l3_rejected", 0),
            "l3_correct": r.get("l3_correct_removals", 0),
            "l3_wrong": r.get("l3_wrong_removals", 0),
            "recall": r["recall"],
            "precision": r["precision"],
        })

    print(f"\n[기존 결과 확인]")
    for s in sets:
        print(f"  {s['name']}: Recall={s['recall']:.1%} ({s['tp']}/{s['gt']}), "
              f"FP={s['fp_extra']}, L3제거={s['l3_rejected']}")

    # LOO Cross-Validation
    print(f"\n{'═' * 65}")
    print(f"  Leave-One-Out Cross-Validation 결과")
    print(f"{'═' * 65}")

    fold_results = []
    for test_idx in range(4):
        test_set = sets[test_idx]
        train_sets = [s for i, s in enumerate(sets) if i != test_idx]

        # Train metrics (3세트 합산)
        train_gt = sum(s["gt"] for s in train_sets)
        train_tp = sum(s["tp"] for s in train_sets)
        train_recall = train_tp / train_gt if train_gt > 0 else 0.0
        train_fp = sum(s["fp_extra"] for s in train_sets)

        # Test metrics (1세트)
        test_recall = test_set["recall"]
        test_gt = test_set["gt"]
        test_tp = test_set["tp"]

        # Overfitting gap = train recall - test recall
        gap = train_recall - test_recall

        fold_result = {
            "fold": test_idx + 1,
            "test_set": test_set["name"],
            "train_sets": [s["name"] for s in train_sets],
            "train_recall": train_recall,
            "train_gt": train_gt,
            "train_tp": train_tp,
            "test_recall": test_recall,
            "test_gt": test_gt,
            "test_tp": test_tp,
            "gap_pp": gap * 100,
        }
        fold_results.append(fold_result)

        print(f"\n  Fold {test_idx + 1}: test={test_set['name']}")
        print(f"    Train (3세트): {train_recall:.1%} ({train_tp}/{train_gt})")
        print(f"    Test  (1세트): {test_recall:.1%} ({test_tp}/{test_gt})")
        print(f"    Gap: {gap*100:+.1f}pp {'(overfitting 신호)' if gap > 5 else '(정상)'}")

    # 전체 통계
    gaps = [f["gap_pp"] for f in fold_results]
    test_recalls = [f["test_recall"] for f in fold_results]
    mean_gap = sum(gaps) / len(gaps)
    max_gap = max(gaps)
    mean_test_recall = sum(test_recalls) / len(test_recalls)
    std_test_recall = math.sqrt(sum((r - mean_test_recall)**2 for r in test_recalls) / len(test_recalls))

    # 전체 Recall (모든 세트 합산)
    total_gt = sum(s["gt"] for s in sets)
    total_tp = sum(s["tp"] for s in sets)
    overall_recall = total_tp / total_gt

    # Wilson CI for LOO average
    z = 1.96
    p = overall_recall
    n = total_gt
    denom = 1 + z**2 / n
    center = (p + z**2 / (2*n)) / denom
    spread = z * math.sqrt(p*(1-p)/n + z**2/(4*n**2)) / denom
    ci_low = max(0, center - spread)
    ci_high = min(1, center + spread)

    print(f"\n{'─' * 65}")
    print(f"  [Cross-Validation 요약]")
    print(f"  평균 Train-Test Gap: {mean_gap:+.1f}pp")
    print(f"  최대 Gap: {max_gap:+.1f}pp")
    print(f"  LOO 평균 Test Recall: {mean_test_recall:.1%}")
    print(f"  LOO Test Recall σ: {std_test_recall*100:.1f}pp")
    print(f"  전체 Recall: {overall_recall:.1%} ({total_tp}/{total_gt})")
    print(f"  95% CI: [{ci_low:.1%}, {ci_high:.1%}]")
    print()

    if max_gap > 10:
        verdict = "WARN: 유의미한 overfitting 가능성 (gap > 10pp)"
    elif max_gap > 5:
        verdict = "MILD: 경미한 overfitting 징후 (gap 5~10pp)"
    else:
        verdict = "OK: overfitting 징후 없음 (gap < 5pp)"
    print(f"  판정: {verdict}")
    print(f"{'═' * 65}")

    # Cochran's Q test (간이 버전 — 정확한 구현은 scipy 필요)
    print(f"\n  [세트 간 Recall 차이 분석]")
    print(f"  세트별 Recall 범위: {min(test_recalls):.1%} ~ {max(test_recalls):.1%}")
    print(f"  범위 폭: {(max(test_recalls) - min(test_recalls))*100:.1f}pp")

    if std_test_recall > 0.05:
        print(f"  → 세트 간 편차가 크다 (σ={std_test_recall*100:.1f}pp > 5pp).")
        print(f"    이는 GT 구성의 난이도 차이 또는 특정 규칙 카테고리의 편향을 시사.")
    else:
        print(f"  → 세트 간 일관성 양호 (σ={std_test_recall*100:.1f}pp ≤ 5pp)")

    # JSON 저장
    output = {
        "timestamp": datetime.now().isoformat(),
        "phase": "Phase 4",
        "description": "4-Fold Leave-One-Out Cross-Validation",
        "folds": fold_results,
        "summary": {
            "mean_gap_pp": round(mean_gap, 1),
            "max_gap_pp": round(max_gap, 1),
            "mean_test_recall": mean_test_recall,
            "std_test_recall": std_test_recall,
            "overall_recall": overall_recall,
            "ci_95_low": ci_low,
            "ci_95_high": ci_high,
            "verdict": verdict,
            "total_gt": total_gt,
            "total_tp": total_tp,
        },
    }
    out_path = BACKEND_ROOT / "scripts" / "cross_validation_results.json"
    out_path.write_text(json.dumps(output, ensure_ascii=False, indent=2, default=str),
                        encoding="utf-8")
    print(f"\n결과 저장: {out_path}")
    return output


if __name__ == "__main__":
    main()
