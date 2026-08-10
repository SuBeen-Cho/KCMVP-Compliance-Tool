"""Blind-label agreement and adjudication helpers."""
from __future__ import annotations

from collections import Counter
from typing import Iterable


def cohens_kappa(labels_a: Iterable[str], labels_b: Iterable[str]) -> float:
    a, b = list(labels_a), list(labels_b)
    if not a or len(a) != len(b):
        raise ValueError("two equally sized non-empty label lists are required")
    categories = sorted(set(a) | set(b))
    observed = sum(x == y for x, y in zip(a, b)) / len(a)
    ca, cb = Counter(a), Counter(b)
    expected = sum(ca[c] / len(a) * cb[c] / len(b) for c in categories)
    return 1.0 if expected == 1.0 and observed == 1.0 else (observed - expected) / (1 - expected)


def disagreements(rows: Iterable[dict]) -> list[dict]:
    return [row for row in rows if row.get("annotator_a") != row.get("annotator_b")]
