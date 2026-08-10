from experiments.calibration import brier_score, expected_calibration_error, rejudge_window_sweep
from experiments.generalization import coverage_report
from experiments.labeling import cohens_kappa, disagreements
from experiments.telemetry import Telemetry
import pytest


def test_cost_and_phase_accounting():
    telemetry = Telemetry(calls=2, input_tokens=1_000_000, output_tokens=500_000)
    with telemetry.phase("l1"):
        pass
    data = telemetry.as_dict({"input_usd_per_million": 0.1, "output_usd_per_million": 0.4, "source": "frozen-test"})
    assert data["estimated_cost_usd"] == 0.3
    assert data["phases_s"]["l1"] >= 0


def test_calibration_metrics_and_window_sweep():
    rows = [{"confidence": 90, "correct": True}, {"confidence": 70, "correct": False}]
    assert round(brier_score(rows), 3) == 0.25
    assert expected_calibration_error(rows, bins=10) >= 0
    assert rejudge_window_sweep(rows, [(65, 74)])[0]["selected"] == 1


def test_calibration_rejects_invalid_values():
    with pytest.raises(ValueError):
        expected_calibration_error([{"confidence": 101, "correct": True}])
    with pytest.raises(TypeError):
        brier_score([{"confidence": 50, "correct": 1}])
    with pytest.raises(ValueError):
        rejudge_window_sweep([{"confidence": 50, "correct": True}], [(75, 65)])


def test_generalization_requires_ground_truth_for_every_algorithm():
    report = coverage_report([
        {"algorithm": "LEA", "has_ground_truth": True},
        {"algorithm": "AES", "has_ground_truth": False},
    ])
    assert report["generalization_claim_supported"] is False
    assert report["missing_ground_truth"] == ["AES", "SEED"]


def test_label_agreement_and_disagreement_queue():
    assert cohens_kappa(["TP", "FP", "TP", "FP"], ["TP", "FP", "TP", "FP"]) == 1.0
    rows = [{"id": 1, "annotator_a": "TP", "annotator_b": "FP"}]
    assert disagreements(rows) == rows
