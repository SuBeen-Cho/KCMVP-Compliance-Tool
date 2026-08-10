"""Confidence calibration and threshold analysis without model calls."""
from __future__ import annotations

from typing import Iterable


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
    return sum((float(r["confidence"]) / 100 - int(bool(r["correct"]))) ** 2 for r in rows) / len(rows)


def expected_calibration_error(rows: Iterable[dict], bins: int = 10) -> float:
    rows = _validated_rows(rows)
    if bins <= 0:
        raise ValueError("positive bins are required")
    total = len(rows)
    error = 0.0
    for index in range(bins):
        low, high = index / bins, (index + 1) / bins
        bucket = [r for r in rows if low <= float(r["confidence"]) / 100 <= high and (index == bins - 1 or float(r["confidence"]) / 100 < high)]
        if bucket:
            conf = sum(float(r["confidence"]) / 100 for r in bucket) / len(bucket)
            acc = sum(bool(r["correct"]) for r in bucket) / len(bucket)
            error += len(bucket) / total * abs(acc - conf)
    return error


def rejudge_window_sweep(rows: Iterable[dict], windows: Iterable[tuple[int, int]]) -> list[dict]:
    rows = _validated_rows(rows)
    output = []
    for low, high in windows:
        if not (0 <= low <= high <= 100):
            raise ValueError("each window must satisfy 0 <= low <= high <= 100")
        selected = [r for r in rows if low <= int(r["confidence"]) <= high]
        output.append({
            "low": low,
            "high": high,
            "selected": len(selected),
            "errors_in_window": sum(not bool(r["correct"]) for r in selected),
            "estimated_extra_calls": len(selected),
        })
    return output
