"""Audit whether an evaluation corpus can support algorithm-generalization claims."""
from __future__ import annotations

from collections import Counter
from typing import Iterable


REQUIRED_ALGORITHMS = ("LEA", "AES", "SEED")


def coverage_report(items: Iterable[dict]) -> dict:
    items = list(items)
    counts = Counter(str(item["algorithm"]).upper() for item in items)
    gt_counts = Counter(str(item["algorithm"]).upper() for item in items if item.get("has_ground_truth"))
    missing_gt = [name for name in REQUIRED_ALGORITHMS if gt_counts[name] == 0]
    return {
        "datasets_by_algorithm": dict(sorted(counts.items())),
        "ground_truth_datasets_by_algorithm": dict(sorted(gt_counts.items())),
        "required_algorithms": list(REQUIRED_ALGORITHMS),
        "missing_ground_truth": missing_gt,
        "generalization_claim_supported": not missing_gt,
    }
