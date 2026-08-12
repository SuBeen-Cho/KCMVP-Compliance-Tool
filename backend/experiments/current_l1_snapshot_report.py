"""Disclosure-minimized report for a newly generated L1 snapshot."""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
from typing import Any

from experiments.l1_snapshot import validate_snapshot


def build(current: dict[str, Any], *, current_file_sha256: str, latency_ms: float,
          historical: dict[str, Any] | None = None) -> dict[str, Any]:
    validation = validate_snapshot(current)
    counts = Counter(row["payload"]["rule_id"] for row in current["candidates"])
    delta = None
    if historical is not None:
        validate_snapshot(historical)
        old = Counter(row["payload"]["rule_id"] for row in historical["candidates"])
        delta = {rule: counts[rule] - old[rule] for rule in sorted(counts | old)
                 if counts[rule] != old[rule]}
    return {
        "schema_version": "1.0", "scope": "current_head_real_sets_1_7_l1_only",
        "content_policy": "aggregate_only_no_candidate_source_or_snippet",
        "api_calls": 0, "strict_validation": validation,
        "snapshot": {"snapshot_id": current["snapshot_id"], "file_sha256": current_file_sha256,
                     "private_mode": "0600", "set_id": current["set_id"]},
        "clean_binding": {**current["provenance"], "worktree_clean": True},
        "latency_ms": round(latency_ms, 3),
        "rule_frequency": dict(sorted(counts.items())),
        "historical_aggregate_comparison": None if historical is None else {
            "comparison_only_not_merged": True,
            "candidate_count_delta": len(current["candidates"]) - len(historical["candidates"]),
            "rule_frequency_delta": delta,
            "historical_snapshot_id": historical["snapshot_id"],
        },
    }


def evaluate(current_path: Path, latency_ms: float, historical_path: Path | None = None) -> dict[str, Any]:
    current = json.loads(current_path.read_text(encoding="utf-8"))
    historical = json.loads(historical_path.read_text(encoding="utf-8")) if historical_path else None
    return build(current, current_file_sha256=hashlib.sha256(current_path.read_bytes()).hexdigest(),
                 latency_ms=latency_ms, historical=historical)
