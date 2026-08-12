"""API-free aggregate chain-input availability audit for current45 LEA-027..030."""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
from typing import Any

from experiments.current_router_snapshot_eval import evaluate as evaluate_router
from experiments.grounded_ai_ready_eval import select_exact_ai_ready
from experiments.workspace_guard import guarded_output_path

TARGET_RULES = ("LEA-027", "LEA-028", "LEA-029", "LEA-030")
BACKEND = Path(__file__).resolve().parents[1]
DEFAULT_FREEZE = BACKEND / "evaluation/public_current_head_ai_ready45_freeze.json"


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _source_index(snapshot: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result = {}
    for row in snapshot.get("sources") or []:
        if not isinstance(row, dict):
            raise ValueError("source_row_invalid")
        source_id, content = row.get("source_id"), row.get("content")
        if not isinstance(source_id, str) or not source_id or source_id in result:
            raise ValueError("source_identity_invalid_or_duplicate")
        if not isinstance(content, str) or _sha(content.encode()) != row.get("sha256"):
            raise ValueError("source_content_hash_mismatch")
        result[source_id] = row
    return result


def _availability(candidate: dict[str, Any], sources: dict[str, dict[str, Any]]) -> dict[str, bool]:
    source = sources.get(candidate.get("source_id"))
    complete_source = isinstance(source, dict)
    # Snapshot payloads are attacker-controlled input.  Neither a manifest nor
    # a self-hashed "verified" receipt can replace runtime HMAC verification by
    # ``verify_and_bind_preprocessing``.  The frozen snapshot has no private
    # replay capture/secret, so these layers must remain unavailable.
    trusted_prep = False
    graph = False
    nonoverlap = False
    return {"complete_source": complete_source, "trusted_preprocessing_manifest": trusted_prep,
            "operation_graph_input_available": graph,
            "callsite_nonoverlap_proved": nonoverlap,
            "chain_available": graph and nonoverlap}


def build(snapshot: dict[str, Any], *, snapshot_sha256: str, freeze: dict[str, Any],
          router_result: dict[str, Any], freeze_sha256: str) -> dict[str, Any]:
    frozen_snapshot, current = freeze.get("snapshot") or {}, freeze.get("current_router") or {}
    if frozen_snapshot.get("file_sha256") != snapshot_sha256:
        raise ValueError("frozen_snapshot_hash_mismatch")
    if (freeze.get("scope") != "clean_current_head_router_universe_freeze_api_free"
            or freeze.get("api_calls") != 0
            or freeze.get("router_manifest", {}).get("git_dirty") is not False):
        raise ValueError("freeze_not_clean_api_free_contract")
    selected = select_exact_ai_ready(snapshot)
    if len(selected) != 45 or current.get("ai_ready_count") != 45:
        raise ValueError("current45_population_invalid")
    universe_hash = router_result.get("ai_ready_universe", {}).get(
        "ordered_envelope_binding_hashes_sha256")
    if universe_hash != current.get("ordered_envelope_binding_hashes_sha256"):
        raise ValueError("frozen_router_membership_mismatch")
    if router_result.get("snapshot", {}).get("file_sha256") != snapshot_sha256:
        raise ValueError("router_snapshot_identity_mismatch")

    targets = [row for _, row in selected if row.get("rule_id") in TARGET_RULES]
    counts = Counter(str(row.get("rule_id")) for row in targets)
    expected = {rule: 1 for rule in TARGET_RULES}
    if len(targets) != 4 or dict(sorted(counts.items())) != expected:
        raise ValueError("new_lea_round_exact_occurrences_invalid")
    if any(current.get("rule_family_counts", {}).get(rule) != 1 for rule in TARGET_RULES):
        raise ValueError("freeze_target_counts_invalid")
    sources = _source_index(snapshot)
    rows = [_availability(candidate, sources) for candidate in targets]
    coverage = {key: sum(row[key] for row in rows) for key in rows[0]}
    return {
        "schema_version": "1.0",
        "evaluation": "frozen_current45_new_lea_round_chain_availability_api_free",
        "population": {"frozen_ai_ready": 45, "target_occurrences": 4},
        "target_rule_counts": expected,
        "coverage": coverage,
        "api_calls": 0, "semantic_authorization": 0, "fact_state": "unknown",
        "provenance": {
            "snapshot_sha256": snapshot_sha256,
            "snapshot_id": frozen_snapshot.get("snapshot_id"),
            "frozen_git_commit": frozen_snapshot.get("git_commit"),
            "router_membership_sha256": universe_hash,
            "freeze_sha256": freeze_sha256,
            "runner_sha256": _sha(Path(__file__).read_bytes()),
        },
        "privacy": "aggregate_only; no candidate id, source, path, snippet, manifest, or callsite persisted",
        "claim_limit": ("Availability only. Graph availability means authenticated inputs exist; "
                        "semantic applicability, accuracy, and ground truth remain unproved."),
    }


def evaluate(snapshot_path: Path, *, freeze_path: Path = DEFAULT_FREEZE,
             warm_runs: int = 1) -> dict[str, Any]:
    snapshot_raw, freeze_raw = snapshot_path.read_bytes(), freeze_path.read_bytes()
    snapshot, freeze = json.loads(snapshot_raw), json.loads(freeze_raw)
    return build(snapshot, snapshot_sha256=_sha(snapshot_raw), freeze=freeze,
                 router_result=evaluate_router(snapshot_path, warm_runs=warm_runs),
                 freeze_sha256=_sha(freeze_raw))


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("--freeze", type=Path, default=DEFAULT_FREEZE)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = evaluate(args.snapshot, freeze_path=args.freeze)
    output = guarded_output_path(args.output)
    output.write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
                      encoding="utf-8")


if __name__ == "__main__":
    main()
