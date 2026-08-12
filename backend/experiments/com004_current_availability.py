"""API-free availability audit for the frozen COM-004 cohort."""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
from typing import Any

from experiments.l1_snapshot import validate_snapshot
from experiments.workspace_guard import guarded_output_path

BACKEND = Path(__file__).resolve().parents[1]
GATE = BACKEND / "mapping/com004_entailment_gate.json"


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def build(snapshot: dict[str, Any], *, snapshot_sha256: str,
          gate: dict[str, Any]) -> dict[str, Any]:
    validate_snapshot(snapshot)
    if gate.get("decision") != "remain_fail_closed" or gate.get("production_authorized") is not False:
        raise ValueError("com004_entailment_gate_not_fail_closed")
    sources = {row["source_id"]: row for row in snapshot["sources"]}
    rows = [row["payload"] for row in snapshot["candidates"]
            if row["payload"].get("rule_id") == "COM-004"]
    if len(rows) != 16:
        raise ValueError("frozen_com004_population_invalid")
    complete = 0
    lexical = Counter()
    for row in rows:
        source = sources.get(row.get("source_id"))
        if source is None or _sha(source["content"].encode()) != source["sha256"]:
            raise ValueError("source_binding_invalid")
        complete += 1
        snippet = str(row.get("snippet") or "")
        lexical["seed_or_time"] += int("srand" in snippet or "time(" in snippet or "clock(" in snippet)
        lexical["weak_output_direct"] += int("rand(" in snippet)
    return {
        "schema_version": "1.0",
        "evaluation": "frozen_com004_program_fact_availability_api_free",
        "population": {"occurrences": 16, "complete_source": complete},
        "untrusted_lexical_observations": dict(sorted(lexical.items())),
        "authenticated_context": {
            "trusted_preprocessing": 0,
            "verified_build_manifest": 0,
            "verified_weak_rng_to_sensitive_sink_defuse": 0,
        },
        "outcome": {"unknown_or_abstain": 16, "production_authorized": 0},
        "api_calls": 0,
        "provenance": {
            "snapshot_id": snapshot["snapshot_id"],
            "snapshot_sha256": snapshot_sha256,
            "entailment_gate_sha256": _sha(GATE.read_bytes()),
            "runner_sha256": _sha(Path(__file__).read_bytes()),
        },
        "privacy": "aggregate_only; no candidate identity, source, path, or snippet",
        "claim_limit": "Availability and lexical triage only; no accuracy, semantic, or dataflow claim.",
    }


def evaluate(snapshot_path: Path) -> dict[str, Any]:
    raw = snapshot_path.read_bytes()
    return build(json.loads(raw), snapshot_sha256=_sha(raw),
                 gate=json.loads(GATE.read_text(encoding="utf-8")))


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = guarded_output_path(args.output)
    output.write_text(json.dumps(evaluate(args.snapshot), ensure_ascii=False,
                                 sort_keys=True, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
