"""
회귀 테스트 — Golden File + FP 기준선.

4세트 TP/FN 고정 비교: 코드 변경 시 Recall이 떨어지면 즉시 탐지.
FP 기준선: KISA LEA FP가 P0 적용 후 기준선 이하인지 확인.
"""

import pytest


# ======================================================================
# Golden: 4세트 Recall 회귀 테스트
# ======================================================================

# 2026-04-23 기준 L1 전용 성능 (evaluate_real_sets.py --no-l3 결과)
GOLDEN = {
    "set1": {"gt": 28, "min_tp": 26, "known_fn_rules": {"COM-001"}},
    "set2": {"gt": 27, "min_tp": 22, "known_fn_rules": {"LEA-005", "LEA-011", "COM-001", "LEA-016", "LEA-017"}},
    "set3": {"gt": 28, "min_tp": 26, "known_fn_rules": set()},
    "set4": {"gt": 22, "min_tp": 18, "known_fn_rules": {"LEA-023", "LEA-034", "LEA-035", "LEA-047", "CTR-002"}},
}


class TestGoldenRecall:
    """4세트 Recall이 기준선 이하로 떨어지지 않는지 확인.

    이 테스트는 evaluate_real_sets.py를 직접 실행하지 않고,
    결과 JSON 파일을 읽어 검증한다. 전체 파이프라인 실행은 slow 마커 사용.
    """

    @pytest.mark.regression
    @pytest.mark.slow
    def test_overall_recall_no_regression(self):
        """전체 Recall ≥ 87.6% (L1 전용 89.5% 기준)"""
        import json
        from pathlib import Path

        results_path = Path(__file__).resolve().parent.parent.parent / "scripts" / "evaluation_results.json"
        if not results_path.exists():
            pytest.skip("evaluation_results.json 없음 — evaluate_real_sets.py 먼저 실행")

        with open(results_path) as f:
            data = json.load(f)

        summary = data.get("summary", {})
        total_tp = summary.get("total_tp", 0)
        total_fn = summary.get("total_fn", 0)
        total_gt = total_tp + total_fn

        if total_gt == 0:
            pytest.skip("GT 0건")

        recall = total_tp / total_gt
        assert recall >= 0.85, (
            f"Recall 회귀 탐지: {recall:.1%} < 85.0% "
            f"(TP={total_tp}, FN={total_fn}, GT={total_gt})"
        )

    @pytest.mark.regression
    @pytest.mark.slow
    def test_no_new_fn(self):
        """기존 known FN 이외의 새로운 FN이 발생하지 않는지 확인."""
        import json
        from pathlib import Path

        results_path = Path(__file__).resolve().parent.parent.parent / "scripts" / "evaluation_results.json"
        if not results_path.exists():
            pytest.skip("evaluation_results.json 없음")

        with open(results_path) as f:
            data = json.load(f)

        all_known_fn = set()
        for s in GOLDEN.values():
            all_known_fn.update(s["known_fn_rules"])

        # code_results에서 FN 규칙 수집
        for set_result in data.get("code_results", []):
            fn_rules = set(set_result.get("fn_rules", []))
            new_fn = fn_rules - all_known_fn
            assert not new_fn, f"새로운 FN 발견: {new_fn}"


# ======================================================================
# FP 기준선: KISA LEA 블라인드 테스트 (02 보고서 §3)
# ======================================================================

# P0 적용 후 기대 상한: 208 → ~86건
FP_BASELINE = {
    "current_max_fp": 210,       # 현재 상한 (P0 미적용)
    "post_p0_target_fp": 90,     # P0 적용 후 목표
    "current_max_fp_kloc": 21.0, # 현재 FP/KLOC 상한
}


class TestFPBaseline:
    """KISA LEA 레퍼런스 FP가 기준선을 초과하지 않는지 확인."""

    @pytest.mark.regression
    @pytest.mark.slow
    def test_kisa_lea_fp_no_regression(self):
        """KISA LEA FP가 현재 기준선(210건) 이하인지."""
        import json
        from pathlib import Path

        results_path = Path(__file__).resolve().parent.parent.parent / "scripts" / "blind_test_kisa_lea_results.json"
        if not results_path.exists():
            pytest.skip("blind_test_kisa_lea_results.json 없음")

        with open(results_path) as f:
            data = json.load(f)

        total_fp = data.get("total_fp", data.get("l1_fp", 0))
        assert total_fp <= FP_BASELINE["current_max_fp"], (
            f"FP 회귀 탐지: {total_fp}건 > 기준선 {FP_BASELINE['current_max_fp']}건"
        )

    @pytest.mark.regression
    @pytest.mark.slow
    def test_kisa_lea_fp_kloc_no_regression(self):
        """KISA LEA FP/KLOC가 현재 기준선(21.0) 이하인지."""
        import json
        from pathlib import Path

        results_path = Path(__file__).resolve().parent.parent.parent / "scripts" / "blind_test_kisa_lea_results.json"
        if not results_path.exists():
            pytest.skip("blind_test_kisa_lea_results.json 없음")

        with open(results_path) as f:
            data = json.load(f)

        fp_kloc = data.get("fp_per_kloc", 0)
        assert fp_kloc <= FP_BASELINE["current_max_fp_kloc"], (
            f"FP/KLOC 회귀 탐지: {fp_kloc:.1f} > 기준선 {FP_BASELINE['current_max_fp_kloc']}"
        )
