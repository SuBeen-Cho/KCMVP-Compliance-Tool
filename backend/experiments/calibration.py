"""Leakage-resistant confidence calibration without provider calls.

The strict API uses ``violation_probability``: 0 means certainly compliant and
100 means certainly a violation.  It must not be populated with a generic
"confidence in whichever verdict was emitted" score.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import math
import random
from typing import Any, Iterable, Sequence


SCHEMA_VERSION = "1.0"
SCORE_SEMANTICS = "violation_probability"
_TOP_KEYS = {"schema_version", "score_semantics", "rows"}
_PROXY_TOP_KEYS = _TOP_KEYS | {"ground_truth_basis", "claim_limit", "eligibility"}
_ROW_KEYS = {
    "observation_id", "candidate_id", "group_id", "condition", "repeat",
    "ground_truth_violation", "initial", "rejudge",
}
_JUDGMENT_KEYS = {"verdict", "violation_probability"}


class CalibrationDataError(ValueError):
    """The input cannot support a valid calibration analysis."""


def _probability(value: Any) -> int:
    if type(value) is not int or not 0 <= value <= 100:
        raise CalibrationDataError("violation_probability must be an integer from 0 to 100")
    return value


def _judgment(value: Any, *, optional: bool = False) -> dict[str, Any] | None:
    if value is None and optional:
        return None
    if not isinstance(value, dict) or set(value) != _JUDGMENT_KEYS:
        raise CalibrationDataError("each judgment must use the closed verdict/probability schema")
    verdict = value["verdict"]
    if verdict not in {"violation", "not_violation"}:
        raise CalibrationDataError("verdict must be violation or not_violation")
    probability = _probability(value["violation_probability"])
    # This catches the common, invalid interpretation "confidence in verdict".
    if (verdict == "violation" and probability < 50) or (
        verdict == "not_violation" and probability > 50
    ):
        raise CalibrationDataError("verdict conflicts with violation_probability semantics")
    return {"verdict": verdict, "violation_probability": probability}


def validate_calibration_dataset(dataset: Any) -> list[dict[str, Any]]:
    """Validate and copy a closed, occurrence-level calibration dataset."""
    if not isinstance(dataset, dict) or set(dataset) not in (_TOP_KEYS, _PROXY_TOP_KEYS):
        raise CalibrationDataError("dataset must use the closed calibration schema")
    if dataset["schema_version"] not in {SCHEMA_VERSION, "1.1"}:
        raise CalibrationDataError("unsupported calibration schema version")
    if dataset["schema_version"] == "1.1":
        if set(dataset) != _PROXY_TOP_KEYS:
            raise CalibrationDataError("proxy calibration dataset must disclose its claim basis")
        if dataset["ground_truth_basis"] != "same_model_temperature0_test_retest_proxy_not_external_expert_gt":
            raise CalibrationDataError("proxy ground truth must not claim external expertise")
        claim = dataset["claim_limit"].lower() if isinstance(dataset["claim_limit"], str) else ""
        if not all(term in claim for term in ("proxy", "test-retest", "not independent")):
            raise CalibrationDataError("proxy calibration must disclose same-model test-retest non-independence")
        eligibility = dataset["eligibility"]
        if (not isinstance(eligibility, dict)
                or set(eligibility) != {"sealed_total", "binary_eligible", "common_scored",
                                        "common_scored_binary", "excluded_by_label",
                                        "excluded_by_disposition"}
                or set(eligibility.get("excluded_by_label", {})) != {
                    "insufficient_context", "not_applicable",
                }
                or eligibility.get("common_scored_binary", {}).get("count") != len({
                    row.get("candidate_id") for row in dataset.get("rows", [])
                })
                or eligibility["sealed_total"] != eligibility["binary_eligible"]
                + sum(eligibility["excluded_by_label"].values())):
            raise CalibrationDataError("proxy eligibility accounting is inconsistent")
        for summary in (eligibility.get("common_scored"),
                        eligibility.get("common_scored_binary")):
            if (not isinstance(summary, dict) or set(summary) != {"count", "ids_sha256"}
                    or type(summary["count"]) is not int
                    or not isinstance(summary["ids_sha256"], str)
                    or len(summary["ids_sha256"]) != 64):
                raise CalibrationDataError("proxy eligibility ID summary is invalid")
        dispositions = eligibility.get("excluded_by_disposition")
        if not isinstance(dispositions, dict) or not dispositions:
            raise CalibrationDataError("proxy disposition exclusions are required")
        for condition, categories in dispositions.items():
            if (not isinstance(condition, str) or not condition
                    or not isinstance(categories, dict)
                    or set(categories) != {"unselected", "score_unresolved",
                                           "condition_only_scored"}):
                raise CalibrationDataError("proxy disposition exclusion schema is invalid")
            for summary in categories.values():
                if (not isinstance(summary, dict) or set(summary) != {"count", "ids_sha256"}
                        or type(summary["count"]) is not int
                        or not isinstance(summary["ids_sha256"], str)
                        or len(summary["ids_sha256"]) != 64):
                    raise CalibrationDataError("proxy disposition ID summary is invalid")
    elif set(dataset) != _TOP_KEYS:
        raise CalibrationDataError("legacy calibration dataset cannot carry undeclared metadata")
    if dataset["score_semantics"] != SCORE_SEMANTICS:
        raise CalibrationDataError("score_semantics must be violation_probability")
    if not isinstance(dataset["rows"], list) or not dataset["rows"]:
        raise CalibrationDataError("rows must be a non-empty list")
    checked: list[dict[str, Any]] = []
    identities: set[str] = set()
    occurrences: set[tuple[str, str, int]] = set()
    candidate_metadata: dict[str, tuple[str, bool]] = {}
    for raw in dataset["rows"]:
        if not isinstance(raw, dict) or set(raw) != _ROW_KEYS:
            raise CalibrationDataError("each row must use the closed occurrence schema")
        strings = {key: raw[key] for key in ("observation_id", "candidate_id", "group_id", "condition")}
        if any(not isinstance(value, str) or not value.strip() for value in strings.values()):
            raise CalibrationDataError("row identifiers and condition must be non-empty strings")
        if strings["observation_id"] in identities:
            raise CalibrationDataError("observation_id values must be unique")
        identities.add(strings["observation_id"])
        if type(raw["repeat"]) is not int or raw["repeat"] < 0:
            raise CalibrationDataError("repeat must be a non-negative integer")
        if type(raw["ground_truth_violation"]) is not bool:
            raise CalibrationDataError("ground_truth_violation must be boolean")
        occurrence = (strings["candidate_id"], strings["condition"], raw["repeat"])
        if occurrence in occurrences:
            raise CalibrationDataError(
                "candidate_id/condition/repeat occurrences must be unique"
            )
        occurrences.add(occurrence)
        metadata = (strings["group_id"], raw["ground_truth_violation"])
        previous = candidate_metadata.setdefault(strings["candidate_id"], metadata)
        if previous[0] != metadata[0]:
            raise CalibrationDataError("each candidate_id must belong to exactly one group_id")
        if previous[1] != metadata[1]:
            raise CalibrationDataError(
                "ground_truth_violation must be consistent for each candidate_id"
            )
        checked.append({
            **strings,
            "repeat": raw["repeat"],
            "ground_truth_violation": raw["ground_truth_violation"],
            "initial": _judgment(raw["initial"]),
            "rejudge": _judgment(raw["rejudge"], optional=True),
        })
    return checked


def grouped_dev_heldout_split(
    rows: Sequence[dict[str, Any]], *, heldout_fraction: float = 0.3,
    salt: str = "kcmvp-calibration-v1",
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Deterministically split whole groups, preventing candidate-family leakage."""
    if not 0 < heldout_fraction < 1:
        raise ValueError("heldout_fraction must be between zero and one")
    groups = sorted({row["group_id"] for row in rows})
    if len(groups) < 2:
        raise CalibrationDataError("at least two groups are required for dev/held-out calibration")
    ranked = sorted(groups, key=lambda group: hashlib.sha256(f"{salt}\0{group}".encode()).digest())
    heldout_count = min(len(groups) - 1, max(1, round(len(groups) * heldout_fraction)))
    heldout_groups = set(ranked[:heldout_count])
    dev = [row for row in rows if row["group_id"] not in heldout_groups]
    heldout = [row for row in rows if row["group_id"] in heldout_groups]
    return dev, heldout


def _final_probability(row: dict[str, Any], window: tuple[int, int] | None) -> tuple[int, bool]:
    probability = row["initial"]["violation_probability"]
    selected = window is not None and window[0] <= probability <= window[1]
    if selected:
        if row["rejudge"] is None:
            raise CalibrationDataError("a selected rejudge window contains a row without rejudge output")
        return row["rejudge"]["violation_probability"], True
    return probability, False


def evaluate_policy(
    rows: Sequence[dict[str, Any]], *, threshold: int,
    rejudge_window: tuple[int, int] | None = None,
) -> dict[str, Any]:
    """Evaluate one fixed threshold/window policy at occurrence level."""
    threshold = _probability(threshold)
    if rejudge_window is not None and not (
        len(rejudge_window) == 2 and 0 <= rejudge_window[0] <= rejudge_window[1] <= 100
    ):
        raise ValueError("rejudge_window must satisfy 0 <= low <= high <= 100")
    counts = Counter(tp=0, fp=0, fn=0, tn=0)
    calls = 0
    for row in rows:
        probability, rejudged = _final_probability(row, rejudge_window)
        calls += int(rejudged)
        predicted = probability >= threshold
        truth = row["ground_truth_violation"]
        counts[("t" if predicted == truth else "f") + ("p" if predicted else "n")] += 1
    tp, fp, fn, tn = (counts[key] for key in ("tp", "fp", "fn", "tn"))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "threshold": threshold,
        "rejudge_window": list(rejudge_window) if rejudge_window is not None else None,
        "n": len(rows), "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": precision, "recall": recall,
        "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
        "estimated_rejudge_calls": calls,
    }


def probability_calibration_metrics(
    rows: Sequence[dict[str, Any]], *, rejudge_window: tuple[int, int] | None = None,
    bins: int = 10,
) -> dict[str, float]:
    """Calculate Brier score and ECE for violation probabilities, not verdict confidence."""
    if bins < 1:
        raise ValueError("bins must be positive")
    pairs = [(_final_probability(row, rejudge_window)[0] / 100, int(row["ground_truth_violation"])) for row in rows]
    if not pairs:
        raise CalibrationDataError("calibration rows must not be empty")
    brier = sum((probability - truth) ** 2 for probability, truth in pairs) / len(pairs)
    ece = 0.0
    for index in range(bins):
        low, high = index / bins, (index + 1) / bins
        bucket = [pair for pair in pairs if low <= pair[0] <= high and (index == bins - 1 or pair[0] < high)]
        if bucket:
            mean_probability = sum(pair[0] for pair in bucket) / len(bucket)
            prevalence = sum(pair[1] for pair in bucket) / len(bucket)
            ece += len(bucket) / len(pairs) * abs(mean_probability - prevalence)
    return {"brier_score": brier, "expected_calibration_error": ece}


def select_policy(
    dev_rows: Sequence[dict[str, Any]], *, thresholds: Iterable[int],
    windows: Iterable[tuple[int, int] | None], minimum_recall: float,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Select on dev only: recall constraint, then precision/F1/call economy."""
    if not 0 <= minimum_recall <= 1:
        raise ValueError("minimum_recall must be between zero and one")
    grid = [evaluate_policy(dev_rows, threshold=t, rejudge_window=w) for w in windows for t in thresholds]
    eligible = [item for item in grid if item["recall"] >= minimum_recall]
    if not eligible:
        raise CalibrationDataError("no dev policy satisfies the recall constraint")
    best = max(eligible, key=lambda item: (
        item["precision"], item["f1"], -item["estimated_rejudge_calls"], item["threshold"],
        tuple(item["rejudge_window"] or [-1, -1]),
    ))
    return best, grid


def _percentile(values: Sequence[float], probability: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    low, high = math.floor(position), math.ceil(position)
    return ordered[low] if low == high else ordered[low] + (ordered[high] - ordered[low]) * (position - low)


def _resample_groups(rows: Sequence[dict[str, Any]], rng: random.Random) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(row["group_id"], []).append(row)
    names = sorted(grouped)
    return [row for _ in names for row in grouped[rng.choice(names)]]


def calibrate(
    dataset: Any, *, thresholds: Iterable[int], windows: Iterable[tuple[int, int] | None],
    minimum_recall: float = 1.0, heldout_fraction: float = 0.3,
    bootstrap_iterations: int = 500, seed: int = 42,
) -> dict[str, Any]:
    """Select on development data and report one untouched held-out estimate."""
    rows = validate_calibration_dataset(dataset)
    thresholds, windows = tuple(thresholds), tuple(windows)
    if not thresholds or not windows:
        raise ValueError("threshold and window grids must not be empty")
    if bootstrap_iterations < 1:
        raise ValueError("bootstrap_iterations must be positive")
    dev, heldout = grouped_dev_heldout_split(rows, heldout_fraction=heldout_fraction)
    for name, partition in (("development", dev), ("held-out", heldout)):
        if {row["ground_truth_violation"] for row in partition} != {False, True}:
            raise CalibrationDataError(f"{name} partition must contain both ground-truth classes")
    selected, grid = select_policy(dev, thresholds=thresholds, windows=windows, minimum_recall=minimum_recall)
    fixed = evaluate_policy(
        heldout, threshold=selected["threshold"],
        rejudge_window=tuple(selected["rejudge_window"]) if selected["rejudge_window"] else None,
    )
    rng = random.Random(seed)
    metrics = {name: [] for name in ("precision", "recall", "f1")}
    choices: Counter[str] = Counter()
    for _ in range(bootstrap_iterations):
        heldout_sample = _resample_groups(heldout, rng)
        sample_result = evaluate_policy(
            heldout_sample, threshold=selected["threshold"],
            rejudge_window=tuple(selected["rejudge_window"]) if selected["rejudge_window"] else None,
        )
        for name in metrics:
            metrics[name].append(sample_result[name])
        dev_sample = _resample_groups(dev, rng)
        try:
            choice, _ = select_policy(
                dev_sample, thresholds=thresholds, windows=windows, minimum_recall=minimum_recall,
            )
            choices[f"{choice['threshold']}|{choice['rejudge_window']}"] += 1
        except CalibrationDataError:
            choices["no_eligible_policy"] += 1
    return {
        "schema_version": dataset["schema_version"],
        "score_semantics": SCORE_SEMANTICS,
        **({"ground_truth_basis": dataset["ground_truth_basis"],
            "claim_limit": dataset["claim_limit"], "eligibility": dataset["eligibility"]}
           if dataset["schema_version"] == "1.1" else {}),
        "selection_protocol": "grouped_dev_selection_then_single_heldout_evaluation",
        "minimum_recall": minimum_recall,
        "dev_n": len(dev), "heldout_n": len(heldout),
        "dev_groups": len({row["group_id"] for row in dev}),
        "heldout_groups": len({row["group_id"] for row in heldout}),
        "selected_policy_dev_metrics": selected,
        "heldout_metrics": fixed,
        "heldout_probability_calibration": probability_calibration_metrics(
            heldout,
            rejudge_window=tuple(selected["rejudge_window"]) if selected["rejudge_window"] else None,
        ),
        "heldout_group_bootstrap_95_ci": {
            name: [_percentile(values, 0.025), _percentile(values, 0.975)]
            for name, values in metrics.items()
        },
        "dev_bootstrap_selection_frequency": dict(sorted(choices.items())),
        "bootstrap_iterations": bootstrap_iterations,
        "grid_size": len(grid),
    }


# Legacy helpers retained for existing research notebooks. ``correct`` is a
# confidence-in-correctness schema and must not be mixed with the strict API.
def _validated_rows(rows: Iterable[dict]) -> list[dict]:
    checked = list(rows)
    if not checked:
        raise ValueError("rows must not be empty")
    for row in checked:
        confidence = float(row["confidence"])
        if not 0 <= confidence <= 100:
            raise ValueError("confidence must be between 0 and 100")
        if type(row["correct"]) is not bool:
            raise TypeError("correct must be a boolean")
    return checked


def brier_score(rows: Iterable[dict]) -> float:
    rows = _validated_rows(rows)
    return sum((float(r["confidence"]) / 100 - int(r["correct"])) ** 2 for r in rows) / len(rows)


def expected_calibration_error(rows: Iterable[dict], bins: int = 10) -> float:
    rows = _validated_rows(rows)
    if bins <= 0:
        raise ValueError("positive bins are required")
    total, error = len(rows), 0.0
    for index in range(bins):
        low, high = index / bins, (index + 1) / bins
        bucket = [r for r in rows if low <= float(r["confidence"]) / 100 <= high and (index == bins - 1 or float(r["confidence"]) / 100 < high)]
        if bucket:
            conf = sum(float(r["confidence"]) / 100 for r in bucket) / len(bucket)
            acc = sum(r["correct"] for r in bucket) / len(bucket)
            error += len(bucket) / total * abs(acc - conf)
    return error


def rejudge_window_sweep(rows: Iterable[dict], windows: Iterable[tuple[int, int]]) -> list[dict]:
    rows = _validated_rows(rows)
    output = []
    for low, high in windows:
        if not 0 <= low <= high <= 100:
            raise ValueError("each window must satisfy 0 <= low <= high <= 100")
        selected = [r for r in rows if low <= int(r["confidence"]) <= high]
        output.append({"low": low, "high": high, "selected": len(selected), "errors_in_window": sum(not r["correct"] for r in selected), "estimated_extra_calls": len(selected)})
    return output
