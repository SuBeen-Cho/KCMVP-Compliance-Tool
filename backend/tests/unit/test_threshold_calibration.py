import json
from pathlib import Path
import subprocess
import sys

import pytest

from experiments.calibration import (
    CalibrationDataError, calibrate, grouped_dev_heldout_split,
    probability_calibration_metrics, validate_calibration_dataset,
)


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "calibrate_threshold.py"


def _dataset():
    rows = []
    specifications = [
        ("family-a", True, 90, 95), ("family-a", False, 55, 20),
        ("family-b", True, 75, 85), ("family-b", False, 65, 25),
        ("family-c", True, 85, 90), ("family-c", False, 45, 15),
        ("family-d", True, 70, 80), ("family-d", False, 60, 30),
        ("family-e", True, 95, 98), ("family-e", False, 35, 10),
    ]
    for index, (group, truth, initial, second) in enumerate(specifications):
        rows.append({
            "observation_id": f"obs-{index}", "candidate_id": f"candidate-{index}",
            "group_id": group, "condition": "rag", "repeat": 0,
            "ground_truth_violation": truth,
            "initial": {
                "verdict": "violation" if initial >= 50 else "not_violation",
                "violation_probability": initial,
            },
            "rejudge": {
                "verdict": "violation" if second >= 50 else "not_violation",
                "violation_probability": second,
            },
        })
    return {"schema_version": "1.0", "score_semantics": "violation_probability", "rows": rows}


def test_closed_schema_rejects_generic_or_conflicting_confidence():
    data = _dataset()
    data["rows"][0]["initial"] = {"verdict": "violation", "confidence": 90}
    with pytest.raises(CalibrationDataError, match="closed"):
        validate_calibration_dataset(data)

    data = _dataset()
    data["rows"][0]["initial"] = {"verdict": "not_violation", "violation_probability": 90}
    with pytest.raises(CalibrationDataError, match="conflicts"):
        validate_calibration_dataset(data)


def test_candidate_identity_cannot_cross_groups_change_truth_or_duplicate_occurrence():
    data = _dataset()
    duplicate = dict(data["rows"][0])
    duplicate.update({"observation_id": "cross-group", "condition": "no_rag", "group_id": "other"})
    data["rows"].append(duplicate)
    with pytest.raises(CalibrationDataError, match="exactly one group_id"):
        validate_calibration_dataset(data)

    data = _dataset()
    duplicate = dict(data["rows"][0])
    duplicate.update({"observation_id": "changed-truth", "condition": "no_rag", "ground_truth_violation": False})
    data["rows"].append(duplicate)
    with pytest.raises(CalibrationDataError, match="consistent"):
        validate_calibration_dataset(data)

    data = _dataset()
    duplicate = dict(data["rows"][0])
    duplicate["observation_id"] = "duplicate-occurrence"
    data["rows"].append(duplicate)
    with pytest.raises(CalibrationDataError, match="occurrences must be unique"):
        validate_calibration_dataset(data)


def test_group_split_is_stable_disjoint_and_salt_sensitive():
    rows = validate_calibration_dataset(_dataset())
    dev, heldout = grouped_dev_heldout_split(rows, heldout_fraction=0.4)
    dev_again, heldout_again = grouped_dev_heldout_split(rows, heldout_fraction=0.4)
    assert [row["observation_id"] for row in dev] == [row["observation_id"] for row in dev_again]
    assert [row["observation_id"] for row in heldout] == [row["observation_id"] for row in heldout_again]
    assert {row["group_id"] for row in dev}.isdisjoint({row["group_id"] for row in heldout})


def test_calibration_selects_on_dev_and_reports_fixed_heldout_with_stability():
    report = calibrate(
        _dataset(), thresholds=[50, 70, 80], windows=[None, (50, 69)],
        minimum_recall=0.5, heldout_fraction=0.4, bootstrap_iterations=20, seed=7,
    )
    assert report["selection_protocol"] == "grouped_dev_selection_then_single_heldout_evaluation"
    assert report["dev_groups"] == 3
    assert report["heldout_groups"] == 2
    assert report["heldout_metrics"]["n"] == report["heldout_n"]
    assert sum(report["dev_bootstrap_selection_frequency"].values()) == 20
    assert set(report["heldout_group_bootstrap_95_ci"]) == {"precision", "recall", "f1"}
    assert 0 <= report["heldout_probability_calibration"]["brier_score"] <= 1


def test_probability_metrics_use_violation_truth_not_verdict_correctness():
    rows = validate_calibration_dataset(_dataset())
    metrics = probability_calibration_metrics(rows)
    expected = sum(
        (row["initial"]["violation_probability"] / 100 - int(row["ground_truth_violation"])) ** 2
        for row in rows
    ) / len(rows)
    assert metrics["brier_score"] == pytest.approx(expected)


def test_selected_window_requires_complete_second_judgments():
    data = _dataset()
    data["rows"][1]["rejudge"] = None
    with pytest.raises(CalibrationDataError, match="without rejudge"):
        calibrate(
            data, thresholds=[50], windows=[(50, 69)], minimum_recall=0,
            bootstrap_iterations=2,
        )


def test_offline_cli_writes_report_and_rejects_wrong_semantics(tmp_path):
    source, output = tmp_path / "data.json", tmp_path / "report.json"
    source.write_text(json.dumps(_dataset()), encoding="utf-8")
    completed = subprocess.run([
        sys.executable, str(SCRIPT), str(source), "--output", str(output),
        "--threshold", "50", "--threshold", "70", "--window", "none",
        "--window", "50:69", "--minimum-recall", "0.5",
        "--bootstrap-iterations", "10",
    ], text=True, capture_output=True, check=False)
    assert completed.returncode == 0, completed.stderr
    assert json.loads(output.read_text())["score_semantics"] == "violation_probability"

    bad = _dataset()
    bad["score_semantics"] = "verdict_confidence"
    source.write_text(json.dumps(bad), encoding="utf-8")
    failed = subprocess.run([
        sys.executable, str(SCRIPT), str(source), "--output", str(output),
        "--threshold", "50", "--window", "none",
    ], text=True, capture_output=True, check=False)
    assert failed.returncode == 2
    assert "violation_probability" in failed.stderr
