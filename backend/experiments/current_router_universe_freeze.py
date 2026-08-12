"""Freeze the current AI-ready router universe and compare sealed membership.

The prior universe is supplied as candidate-id digests from its private ledger.
Only aggregate cohort counts and rule-family counts are emitted.  No source,
snippet, candidate id, or per-occurrence digest is written to the public result.
"""
from __future__ import annotations

from collections import Counter
import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from app.services.atomic_claim_contract import build_atomic_contract
from app.services.rag_service import _load_verified_official_units
from experiments.full_stage_boundary_benchmark import benchmark
from experiments.grounded_ai_ready_eval import _sha, select_exact_ai_ready
from experiments.l1_snapshot import validate_snapshot


def _rule_counts(ids: set[str], by_digest: dict[str, dict[str, Any]]) -> dict[str, int]:
    return dict(sorted(Counter(str(by_digest[item]["rule_id"]) for item in ids).items()))


def _readiness(rows: list[dict[str, Any]]) -> dict[str, int]:
    bundle_ready = 0
    atomic_ready = 0
    for row in rows:
        bundle = list(row.get("rag_evidence_bundle") or [])
        if bundle and all(
            isinstance(unit, dict)
            and all(isinstance(unit.get(key), str) and unit[key].strip()
                    for key in ("unit_id", "source_id"))
            and isinstance(unit.get("locator"), (str, dict))
            and bool(unit.get("locator"))
            and isinstance(unit.get("span") or unit.get("text"), str)
            and bool((unit.get("span") or unit.get("text") or "").strip())
            and unit.get("span_sha256") == hashlib.sha256(
                (unit.get("span") or unit.get("text") or "").encode("utf-8")
            ).hexdigest()
            for unit in bundle
        ):
            bundle_ready += 1
        try:
            units = _load_verified_official_units(str(row.get("rule_id") or ""))
            contract = build_atomic_contract(str(row.get("rule_id") or ""), units)
            if contract.get("claims"):
                atomic_ready += 1
        except (KeyError, TypeError, ValueError):
            pass
    return {
        "count": len(rows),
        "verified_official_bundle_ready": bundle_ready,
        "audited_atomic_contract_ready": atomic_ready,
    }


def build(snapshot: dict[str, Any], *, snapshot_file_sha256: str,
          prior_rows: list[dict[str, Any]], prior_ledger_sha256: str,
          expected_prior_ledger_sha256: str, warm_runs: int = 3) -> dict[str, Any]:
    validate_snapshot(snapshot)
    if prior_ledger_sha256 != expected_prior_ledger_sha256:
        raise ValueError("prior private ledger hash does not match its public seal")
    if len(prior_rows) != 41 or [row.get("index") for row in prior_rows] != list(range(41)):
        raise ValueError("prior universe must contain exactly 41 ordered rows")
    prior_ordered = [str(row.get("candidate_id_sha256") or "") for row in prior_rows]
    if any(len(value) != 64 for value in prior_ordered) or len(set(prior_ordered)) != 41:
        raise ValueError("prior candidate membership seal is malformed or duplicated")

    selected = select_exact_ai_ready(snapshot)
    current_ordered = [_sha(cid.encode()) for cid, _ in selected]
    if len(current_ordered) != len(set(current_ordered)):
        raise ValueError("current AI-ready membership contains duplicate candidates")
    all_by_digest = {
        _sha(str(envelope["candidate_id"]).encode()): envelope["payload"]
        for envelope in snapshot["candidates"]
    }
    if set(prior_ordered) - set(all_by_digest):
        raise ValueError("prior membership cannot be joined to the current frozen L1 universe")

    current_by_digest = {
        digest: row for digest, (_, row) in zip(current_ordered, selected, strict=True)
    }
    prior = set(prior_ordered)
    current = set(current_ordered)
    retained, added, removed = current & prior, current - prior, prior - current
    routed = benchmark(snapshot, warm_runs=warm_runs)
    payload_hashes = [_sha({key: value for key, value in row.items() if key not in
                            {"rag_evidence_bundle", "rag_guideline_text", "rag_route"}})
                      for _, row in selected]
    envelope_hashes = [_sha({"candidate_id": cid, "payload": row}) for cid, row in selected]

    cohort_rows = {
        "retained": [current_by_digest[item] for item in current_ordered if item in retained],
        "added": [current_by_digest[item] for item in current_ordered if item in added],
    }
    return {
        "schema_version": "1.0",
        "scope": ("dirty_worktree_current_router_universe_freeze_api_free"
                  if routed["reproducibility_manifest"].get("git_dirty")
                  else "clean_current_head_router_universe_freeze_api_free"),
        "claim_limit": (
            "Membership and evidence-readiness coverage only; no LLM decision, "
            "semantic authorization, or accuracy claim."
        ),
        "privacy": "aggregate_only_no_candidate_id_source_or_snippet",
        "api_calls": 0,
        "snapshot": {
            "snapshot_id": snapshot["snapshot_id"],
            "file_sha256": snapshot_file_sha256,
            "candidate_count": len(snapshot["candidates"]),
            "source_count": len(snapshot["sources"]),
            "git_commit": snapshot["provenance"]["git_commit"],
        },
        "current_router": {
            "stage_distribution": routed["stage_distribution"],
            "ai_ready_count": len(selected),
            "ordered_candidate_payload_hashes_sha256": _sha(payload_hashes),
            "ordered_envelope_binding_hashes_sha256": _sha(envelope_hashes),
            "ordered_membership_hashes_sha256": _sha(current_ordered),
            "rule_family_counts": _rule_counts(current, current_by_digest),
        },
        "prior_ai_ready41": {
            "comparison_only_not_merged": True,
            "count": len(prior),
            "private_ledger_sha256": prior_ledger_sha256,
            "ordered_membership_hashes_sha256": _sha(prior_ordered),
        },
        "membership_delta": {
            "retained_count": len(retained),
            "added_count": len(added),
            "removed_count": len(removed),
            "added_rule_family_counts": _rule_counts(added, current_by_digest),
            "removed_rule_family_counts": _rule_counts(removed, all_by_digest),
        },
        "evidence_readiness": {
            "current": _readiness([row for _, row in selected]),
            "retained": _readiness(cohort_rows["retained"]),
            "added": _readiness(cohort_rows["added"]),
            "semantic_authorization": "not_measured",
        },
        "router_manifest": routed["reproducibility_manifest"],
        "latency_ms": routed["latency_ms"],
    }


def evaluate(snapshot_path: Path, prior_ledger_path: Path, prior_public_path: Path,
             *, warm_runs: int = 3) -> dict[str, Any]:
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    prior_rows = [json.loads(line) for line in prior_ledger_path.read_text(encoding="utf-8").splitlines()
                  if line.strip()]
    prior_public = json.loads(prior_public_path.read_text(encoding="utf-8"))
    return build(
        snapshot,
        snapshot_file_sha256=hashlib.sha256(snapshot_path.read_bytes()).hexdigest(),
        prior_rows=prior_rows,
        prior_ledger_sha256=hashlib.sha256(prior_ledger_path.read_bytes()).hexdigest(),
        expected_prior_ledger_sha256=str(prior_public.get("private_ledger_sha256") or ""),
        warm_runs=warm_runs,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("--prior-ledger", type=Path, required=True)
    parser.add_argument("--prior-public", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--warm-runs", type=int, default=3)
    args = parser.parse_args()
    result = evaluate(args.snapshot, args.prior_ledger, args.prior_public,
                      warm_runs=args.warm_runs)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
