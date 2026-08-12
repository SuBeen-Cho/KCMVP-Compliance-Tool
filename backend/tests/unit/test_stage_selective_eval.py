import pytest

from experiments.stage_selective_eval import SelectiveEvalInputError, summarize


def test_selective_metrics_separate_coverage_and_abstention() -> None:
    rows = [
        {"stage": "deterministic", "label": "violation"},
        {"stage": "deterministic", "label": "non_violation"},
        {"stage": "ai_ready", "label": "violation"},
        {"stage": "hold", "label": "insufficient_context"},
        {"stage": "hold", "label": "not_applicable"},
    ]
    result = summarize(rows, snapshot_id="s", gt_id="g", input_sha256={"x": "a" * 64})
    perf = result["deterministic_selective_performance"]
    assert perf["accuracy_abstention_excluded"] is None
    assert perf["selective_risk_abstention_excluded"] is None
    assert perf["binary_population_coverage"] == pytest.approx(2 / 3)
    assert result["routing_all"]["hold"]["coverage"] == 0.4
    assert result["hold_analysis"]["proxy_violation_count"] == 0


def test_rejects_open_or_unknown_rows() -> None:
    with pytest.raises(SelectiveEvalInputError):
        summarize([{"stage": "hold", "label": "violation", "extra": "x"}],
                  snapshot_id="s", gt_id="g", input_sha256={})
    with pytest.raises(SelectiveEvalInputError):
        summarize([{"stage": "other", "label": "violation"}],
                  snapshot_id="s", gt_id="g", input_sha256={})
