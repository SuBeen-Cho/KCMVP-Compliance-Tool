"""Aggregate-only benchmark of a frozen L1 snapshot at the production L2 boundary."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import statistics
import subprocess
import time
from collections import Counter
from pathlib import Path
from typing import Any

from app.services.analysis_stage_contract import ai_is_authorized, close_for_l3
from app.services.llm.candidate_selector import _select_l3_candidates
from app.services.rag_grounding import is_deterministic_verified_bypass, route_rag
from app.services.rag_service import run_l2_rag_context


class SnapshotError(ValueError):
    pass


def _sha(value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode()).hexdigest()


def load_candidates(snapshot: Any) -> list[dict[str, Any]]:
    """Validate the closed snapshot while returning payloads only in memory."""
    if not isinstance(snapshot, dict) or snapshot.get("schema_version") != "1.0":
        raise SnapshotError("unsupported snapshot")
    rows = snapshot.get("candidates")
    if not isinstance(rows, list) or not rows:
        raise SnapshotError("non-empty candidates required")
    result = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"candidate_id", "payload", "payload_sha256"}:
            raise SnapshotError("closed candidate envelope required")
        if not isinstance(row["payload"], dict) or _sha(row["payload"]) != row["payload_sha256"]:
            raise SnapshotError("candidate payload integrity failure")
        result.append(dict(row["payload"]))
    return result


def _classify(closed: dict[str, Any], selected: bool) -> tuple[str, bool]:
    if closed.get("disposition") == "deterministic" and closed.get("ai_need") == "not_required":
        return "deterministic", bool(closed.get("rag_evidence_bundle"))
    if closed.get("disposition") == "hold" or closed.get("ai_need") == "prohibited":
        return "hold", bool(closed.get("rag_evidence_bundle"))
    if not selected:
        return "hold", bool(closed.get("rag_evidence_bundle"))
    claimed = closed.get("rag_route") or {}
    recomputed = route_rag({key: value for key, value in closed.items() if key != "rag_route"})
    authorized = (
        ai_is_authorized(closed)
        and claimed.get("decision") == recomputed.get("decision") == "retrieve"
        and not is_deterministic_verified_bypass(closed)
    )
    return ("ai_ready" if authorized else "hold"), bool(closed.get("rag_evidence_bundle"))


def _percentile(values: list[float], quantile: float) -> float:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * quantile) - 1)]


def _file_hash(path: Path) -> str | None:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def _tree_hash(root: Path, pattern: str) -> str:
    rows = [(str(path.relative_to(root)), _file_hash(path)) for path in sorted(root.rglob(pattern))]
    return _sha(rows)


def _manifest(snapshot: dict[str, Any]) -> dict[str, Any]:
    backend = Path(__file__).resolve().parents[1]
    repo = backend.parent
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, check=True,
                          capture_output=True, text=True).stdout.strip()
    dirty = bool(subprocess.run(["git", "status", "--porcelain"], cwd=repo, check=True,
                                capture_output=True, text=True).stdout.strip())
    return {
        "git_head": head,
        "git_dirty": dirty,
        "rules_tree_sha256": _tree_hash(backend / "rules", "*.yaml"),
        "mapping_tree_sha256": _tree_hash(backend / "mapping", "*.json"),
        "official_index_sha256": _file_hash(backend / "data/evidence/official_units.local.json"),
        "snapshot_source_tree_sha256": snapshot.get("source_tree_sha256"),
    }


def benchmark(snapshot: Any, *, warm_runs: int = 5) -> dict[str, Any]:
    if isinstance(warm_runs, bool) or not isinstance(warm_runs, int) or warm_runs < 1:
        raise ValueError("warm_runs must be a positive integer")
    candidates = load_candidates(snapshot)

    started = time.perf_counter()
    cold_rows = run_l2_rag_context(candidates)
    cold_closed = [close_for_l3(row) for row in cold_rows]
    cold_selected = {id(row) for row in _select_l3_candidates(cold_closed)}
    states = [_classify(row, id(row) in cold_selected) for row in cold_closed]
    cold_ms = (time.perf_counter() - started) * 1000

    warm_ms = []
    for _ in range(warm_runs):
        started = time.perf_counter()
        warm_rows = run_l2_rag_context(candidates)
        warm_closed = [close_for_l3(row) for row in warm_rows]
        warm_selected = {id(row) for row in _select_l3_candidates(warm_closed)}
        if [_classify(row, id(row) in warm_selected) for row in warm_closed] != states:
            raise RuntimeError("non-reproducible boundary distribution")
        warm_ms.append((time.perf_counter() - started) * 1000)

    distribution = Counter(state for state, _ in states)
    retrieve_needed = distribution["ai_ready"] + distribution["hold"]
    bundle_available = sum(has_evidence for state, has_evidence in states if state != "deterministic")
    baseline = len(candidates)  # naive policy: one LLM call for every L1 occurrence
    projected = distribution["ai_ready"]
    core = {
        "schema_version": "1.0",
        "dataset": {
            "candidate_count": len(candidates),
            "snapshot_sha256": _sha(snapshot),
            "content_policy": "aggregate_only_no_candidate_ids_or_source_text",
            "interpretation_scope": "historical_policy_replay_not_current_end_to_end",
        },
        "execution": {
            "production_function": "run_l2_rag_context",
            "external_api_calls": 0,
            "warm_run_count": warm_runs,
        },
        "reproducibility_manifest": _manifest(snapshot),
        "stage_distribution": {
            key: {"count": distribution[key], "ratio": distribution[key] / len(candidates)}
            for key in ("deterministic", "ai_ready", "hold")
        },
        "verified_evidence": {
            "required_count": retrieve_needed,
            "bundle_available_count": bundle_available,
            "verifier_full_pass_count": None,
            "verifier_full_pass_coverage": None,
            "measurement_status": "not_measured_without_llm_decision_entailment",
        },
        "projected_llm_calls": {
            "naive_all_candidates_upper_bound": baseline,
            "need_gated": projected,
            "need_gated_ratio": projected / baseline,
            "upper_bound_reduction_ratio": (baseline - projected) / baseline,
            "measured_calls_avoided": None,
            "measurement_kind": "routing_projection_no_eligible_all_call_comparator",
        },
        "latency_ms": {
            "cold_batch": cold_ms,
            "cold_per_candidate": cold_ms / len(candidates),
            "warm_batch_mean": statistics.mean(warm_ms),
            "warm_batch_median": statistics.median(warm_ms),
            "warm_batch_p95_nearest_rank": _percentile(warm_ms, .95),
            "warm_per_candidate_mean": statistics.mean(warm_ms) / len(candidates),
        },
    }
    core["result_sha256"] = _sha(core)
    return core


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("-o", "--output", type=Path, required=True)
    parser.add_argument("--warm-runs", type=int, default=5)
    args = parser.parse_args()
    result = benchmark(json.loads(args.snapshot.read_text(encoding="utf-8")), warm_runs=args.warm_runs)
    args.output.write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
