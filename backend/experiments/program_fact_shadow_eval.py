"""API-free baseline for authenticated program facts on exact AI-ready41."""
from __future__ import annotations

import hashlib
import json
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any

from app.services.program_fact_contract import verify_program_fact
from experiments.grounded_ai_ready_eval import _sha, select_exact_ai_ready

SCHEMA_VERSION = "1.0"
BACKEND_ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = BACKEND_ROOT / "mapping/atomic_claim_evidence_registry.json"
CONTRACT_PATH = BACKEND_ROOT / "app/services/program_fact_contract.py"


def _file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def candidate_binding(candidate_id: str, candidate: dict[str, Any]) -> str:
    payload = {key: value for key, value in candidate.items() if key != "sealed_program_fact"}
    return _sha({"candidate_id": candidate_id, "payload": payload})


def validate_sealed_fact(expected: dict[str, str], value: Any,
                         runtime_secret: bytes) -> tuple[bool, str]:
    """Delegate to the production contract; never infer facts from source prose."""
    if not isinstance(value, dict):
        return False, "sealed_program_fact_missing"
    result = verify_program_fact(value, runtime_secret, expected)
    return bool(result["verified"]), str(result["reason"])


def evaluate(snapshot_path: Path, runtime_secret: bytes) -> dict[str, Any]:
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    selected = select_exact_ai_ready(snapshot)
    if len(selected) != 41:
        raise ValueError(f"expected sealed AI-ready universe of 41, got {len(selected)}")
    rows = []
    for candidate_id, candidate in selected:
        binding = candidate_binding(candidate_id, candidate)
        expected = {"candidate_id": str(candidate_id), "rule_id": str(candidate.get("rule_id"))}
        valid, reason = validate_sealed_fact(
            expected, candidate.get("sealed_program_fact"), runtime_secret)
        rows.append({"binding": binding, "valid": valid, "reason": reason,
                     "snippet_present": bool(str(candidate.get("snippet") or "").strip()),
                     "project_artifact_present": bool(candidate.get("project_artifact_evidence"))})

    bindings = [row["binding"] for row in rows]
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=BACKEND_ROOT.parent,
                          check=True, capture_output=True, text=True).stdout.strip()
    valid_count = sum(row["valid"] for row in rows)
    return {
        "schema_version": SCHEMA_VERSION,
        "evaluation": "current_head_ai_ready41_authenticated_program_fact_shadow",
        "population": len(rows), "api_calls": 0,
        "source_observation_availability": {
            "snippet_present": sum(row["snippet_present"] for row in rows),
            "project_artifact_evidence_present": sum(row["project_artifact_present"] for row in rows),
        },
        "authenticated_fact_availability": valid_count,
        "authenticated_fact_structural_validity": valid_count,
        "independently_semantically_authorized": 0,
        "reasons": dict(sorted(Counter(row["reason"] for row in rows).items())),
        "candidate_universe_sha256": _sha(bindings),
        "provenance": {"git_head": head, "snapshot_sha256": _file_sha(snapshot_path),
                       "atomic_registry_sha256": _file_sha(REGISTRY_PATH),
                       "program_fact_contract_sha256": _file_sha(CONTRACT_PATH),
                       "runner_sha256": _file_sha(Path(__file__))},
        "claim_limit": "Availability/authenticity only; no semantic authorization or accuracy without independent GT.",
        "privacy": "aggregate_only; runtime_secret_not_persisted",
    }


def main() -> None:
    import argparse
    import secrets
    parser = argparse.ArgumentParser()
    parser.add_argument("snapshot", type=Path); parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    # No envelopes exist in this baseline. A one-run secret avoids publishing a
    # reusable authentication key while still exercising the fail-closed path.
    result = evaluate(args.snapshot, secrets.token_bytes(32))
    args.output.write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
                           encoding="utf-8")


if __name__ == "__main__":
    main()
