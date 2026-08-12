"""API-free current-router evaluation of a newly generated L1 snapshot."""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
from typing import Any

from experiments.full_stage_boundary_benchmark import benchmark
from experiments.grounded_ai_ready_eval import _sha, select_exact_ai_ready
from experiments.l1_snapshot import validate_snapshot


def build(snapshot: dict[str, Any], *, snapshot_file_sha256: str,
          historical: dict[str, Any] | None = None, warm_runs: int = 5) -> dict[str, Any]:
    validate_snapshot(snapshot)
    routed = benchmark(snapshot, warm_runs=warm_runs)
    selected = select_exact_ai_ready(snapshot)
    payload_hashes = [_sha({k: v for k, v in row.items() if k not in
                            {"rag_evidence_bundle", "rag_guideline_text", "rag_route"}})
                      for _, row in selected]
    envelope_hashes = [_sha({"candidate_id": cid, "payload": row}) for cid, row in selected]
    comparison = None
    if historical:
        comparison = {stage: routed["stage_distribution"][stage]["count"] -
                       int(historical["stage_distribution"][stage]["count"])
                      for stage in ("deterministic", "ai_ready", "hold")}
    return {
        "schema_version": "1.0", "scope": "current_head_snapshot_current_router_api_free",
        "claim_limit": "Routing coverage and latency only; no LLM decisions or accuracy claim.",
        "api_calls": 0,
        "snapshot": {"snapshot_id": snapshot["snapshot_id"], "file_sha256": snapshot_file_sha256,
                     "candidate_count": len(snapshot["candidates"])},
        "stage_distribution": routed["stage_distribution"],
        "ai_ready_universe": {
            "count": len(selected),
            "ordered_candidate_hashes_sha256": _sha(payload_hashes),
            "ordered_envelope_binding_hashes_sha256": _sha(envelope_hashes),
            "atomic_v3_alignment_contract": "same select_exact_ai_ready function and ordered envelope binding",
        },
        "latency_ms": routed["latency_ms"],
        "manifest": routed["reproducibility_manifest"],
        "historical_aggregate_comparison": None if historical is None else {
            "comparison_only_not_merged": True, "stage_count_delta": comparison,
            "historical_snapshot_identity": historical.get("dataset", {}).get("snapshot_sha256"),
        },
    }


def evaluate(snapshot_path: Path, historical_path: Path | None = None, *, warm_runs: int = 5) -> dict[str, Any]:
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    historical = json.loads(historical_path.read_text(encoding="utf-8")) if historical_path else None
    return build(snapshot, snapshot_file_sha256=hashlib.sha256(snapshot_path.read_bytes()).hexdigest(),
                 historical=historical, warm_runs=warm_runs)
