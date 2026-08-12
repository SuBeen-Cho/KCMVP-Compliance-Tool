"""Aggregate-only applicability audit for LEA-027..031 in frozen AI-ready41."""
from __future__ import annotations

import hashlib
import json
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any

TARGET_RULES = ("LEA-027", "LEA-028", "LEA-029", "LEA-030", "LEA-031")
BACKEND_ROOT = Path(__file__).resolve().parents[1]


def _sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _load_ledger_membership(path: Path) -> set[str]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    hashes = [row.get("candidate_id_sha256") for row in rows]
    if (len(rows) != 41 or any(not isinstance(value, str) or len(value) != 64 for value in hashes)
            or len(set(hashes)) != 41):
        raise ValueError("sealed_ai_ready41_membership_invalid")
    return set(hashes)


def _source_index(snapshot: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for row in snapshot.get("sources") or []:
        source_id, content, claimed = row.get("source_id"), row.get("content"), row.get("sha256")
        if not isinstance(source_id, str) or not source_id or source_id in result:
            raise ValueError("source_identity_invalid_or_duplicate")
        if not isinstance(content, str) or _sha_bytes(content.encode()) != claimed:
            raise ValueError("source_content_hash_mismatch")
        result[source_id] = row
    return result


def evaluate(snapshot_path: Path, private_ledger_path: Path) -> dict[str, Any]:
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    membership = _load_ledger_membership(private_ledger_path)
    sources = _source_index(snapshot)
    selected = []
    joined_hashes: list[str] = []
    for envelope in snapshot.get("candidates") or []:
        candidate_id = str(envelope.get("candidate_id"))
        candidate_hash = _sha_bytes(candidate_id.encode())
        if candidate_hash in membership:
            payload = envelope.get("payload")
            if not isinstance(payload, dict):
                raise ValueError("candidate_payload_invalid")
            selected.append(payload)
            joined_hashes.append(candidate_hash)
    if (len(selected) != 41 or len(set(joined_hashes)) != 41
            or set(joined_hashes) != membership):
        raise ValueError(f"sealed_ai_ready41_snapshot_join_incomplete:{len(selected)}")

    target = [row for row in selected if row.get("rule_id") in TARGET_RULES]
    availability = [{
        "source": isinstance(row.get("source_id"), str) and row["source_id"] in sources,
        "manifest": isinstance(row.get("trusted_preprocessing_manifest"), dict),
        "callsite": (isinstance(row.get("trusted_callsite_manifest"), dict)
                     or isinstance(row.get("callsite_context"), dict)),
    } for row in target]
    complete_source = sum(row["source"] for row in availability)
    manifest = sum(row["manifest"] for row in availability)
    callsite = sum(row["callsite"] for row in availability)
    fully_provable = sum(all(row.values()) for row in availability)
    counts = Counter(str(row.get("rule_id")) for row in target)
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=BACKEND_ROOT.parent, check=True,
        capture_output=True, text=True,
    ).stdout.strip()
    return {
        "schema_version": "1.0",
        "evaluation": "frozen_exact_ai_ready41_lea027_031_applicability_audit",
        "population": {"sealed_exact_ai_ready": 41, "target_occurrences": len(target)},
        "target_rule_counts": {rule: counts.get(rule, 0) for rule in TARGET_RULES},
        "coverage": {
            "complete_source_resolved": complete_source,
            "trusted_build_or_preprocessing_manifest": manifest,
            "trusted_callsite_context": callsite,
            "fully_applicability_provable": fully_provable,
        },
        "reason": ("no_target_occurrence_in_frozen_ai_ready41" if not target
                   else "target_occurrences_require_all_three_context_layers"),
        "api_calls": 0,
        "production_authorized": 0,
        "provenance": {
            "git_head_at_audit": head,
            "snapshot_sha256": _sha_bytes(snapshot_path.read_bytes()),
            "private_membership_ledger_sha256": _sha_bytes(private_ledger_path.read_bytes()),
            "runner_sha256": _sha_bytes(Path(__file__).read_bytes()),
        },
        "privacy": "aggregate_only; no source, candidate, path, snippet, command, macro, or callsite identity persisted",
        "claim_limit": "Applicability/input-availability audit only; zero occurrences is not detector accuracy.",
        "lineage_warning": "Membership is the sealed historical AI-ready41; live routing is not recomputed or relabelled.",
    }


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("--private-ledger", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = evaluate(args.snapshot, args.private_ledger)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
