"""
Manual-label metric calculator for 0_KCMVP-style evaluations.

The input label file must not contain source snippets. It should contain only
finding metadata and one of these manual labels: TP, FP, UNREVIEWED.

Metric policy (CLAUDE.md 성능 측정 원칙 준수):
- Precision = TP / (TP + FP) — 모든 탐지 결과가 분모에 포함
- UNREVIEWED 항목은 검토 완료 시 TP 또는 FP로 확정해야 함
- ARTIFACT, REVIEW 등 분모를 줄이는 별도 카테고리 사용 금지
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List


VALID_LABELS = {"TP", "FP", "UNREVIEWED"}


def _load_items(path: Path) -> List[Dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    items = data.get("items")
    if not isinstance(items, list):
        raise ValueError(f"{path} does not contain an items list")
    return items


def _label(item: Dict[str, Any]) -> str:
    label = str(item.get("manual_label") or "UNREVIEWED").upper()
    if label not in VALID_LABELS:
        raise ValueError(
            f"invalid manual_label={label!r} for {item.get('id')}. "
            f"Allowed: {VALID_LABELS}. ARTIFACT/REVIEW are not allowed — "
            f"all findings must be TP, FP, or UNREVIEWED."
        )
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
    unreviewed = counts["UNREVIEWED"]
    return {
        "total_findings": len(items),
        "label_counts": {label: counts[label] for label in sorted(VALID_LABELS)},
        "precision": None if denominator == 0 else tp / denominator,
        "precision_display": _percent(tp, denominator),
        "precision_denominator": denominator,
        "unreviewed_items": unreviewed,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "labels",
        nargs="?",
        default=str(Path(__file__).parent.parent / "evaluation" / "0_kcmvp_labels.json"),
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
    print(f"Precision: {result['precision_display']} ({result['precision_denominator']}건 기준)")
    if result["unreviewed_items"] > 0:
        print(f"Unreviewed: {result['unreviewed_items']}건 (검토 완료 시 TP/FP로 확정 필요)")

    if result["precision"] is None:
        print("Note: precision is unavailable until at least one TP or FP label is assigned.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
