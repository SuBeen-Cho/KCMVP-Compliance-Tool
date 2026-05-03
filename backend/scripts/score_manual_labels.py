"""
Manual-label metric calculator for 0_KCMVP-style evaluations.

The input label file must not contain source snippets. It should contain only
finding metadata and one of these manual labels:
TP, FP, REVIEW, ARTIFACT, UNREVIEWED.

Default metric policy:
- code precision = TP / (TP + FP)
- REVIEW, UNREVIEWED, and ARTIFACT are excluded from code precision.
- ARTIFACT is counted separately as submission-package completeness work.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List


VALID_LABELS = {"TP", "FP", "REVIEW", "ARTIFACT", "UNREVIEWED"}


def _load_items(path: Path) -> List[Dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    items = data.get("items")
    if not isinstance(items, list):
        raise ValueError(f"{path} does not contain an items list")
    return items


def _label(item: Dict[str, Any]) -> str:
    label = str(item.get("manual_label") or "UNREVIEWED").upper()
    if label not in VALID_LABELS:
        raise ValueError(f"invalid manual_label={label!r} for {item.get('id')}")
    return label


def _percent(numerator: int, denominator: int) -> str:
    if denominator == 0:
        return "N/A"
    return f"{(numerator / denominator) * 100:.1f}%"


def _counter(items: Iterable[Dict[str, Any]]) -> Counter:
    return Counter(_label(item) for item in items)


def calculate(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    counts = _counter(items)
    tp = counts["TP"]
    fp = counts["FP"]
    denominator = tp + fp
    return {
        "total_findings": len(items),
        "label_counts": {label: counts[label] for label in sorted(VALID_LABELS)},
        "code_precision": None if denominator == 0 else tp / denominator,
        "code_precision_display": _percent(tp, denominator),
        "code_precision_denominator": denominator,
        "artifact_items": counts["ARTIFACT"],
        "pending_items": counts["REVIEW"] + counts["UNREVIEWED"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "labels",
        nargs="?",
        default=str(Path(__file__).parent.parent / "evaluation" / "0_kcmvp_labels_20260503.json"),
        help="manual label JSON path",
    )
    args = parser.parse_args()

    labels_path = Path(args.labels)
    items = _load_items(labels_path)
    result = calculate(items)

    print(f"Label file: {labels_path}")
    print(f"Total findings: {result['total_findings']}")
    print("Label counts:")
    for label, count in result["label_counts"].items():
        print(f"  {label}: {count}")
    print(f"Code precision: {result['code_precision_display']}")
    print(f"Code precision denominator: {result['code_precision_denominator']}")
    print(f"Artifact items: {result['artifact_items']}")
    print(f"Pending review/unreviewed: {result['pending_items']}")

    if result["code_precision"] is None:
        print("Note: code precision is unavailable until at least one TP or FP label is assigned.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
