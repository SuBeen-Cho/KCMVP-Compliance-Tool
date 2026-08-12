"""API-free aggregate evaluation of sealed preprocessing provenance for LEA-011."""
from __future__ import annotations

import hashlib
import json
import secrets
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any

from app.services.preprocessing_provenance import (
    unavailable_preprocessing_provenance, verify_preprocessing_provenance,
)
from experiments.grounded_ai_ready_eval import _sha, select_exact_ai_ready
from experiments.lea011_defuse_current_head_eval import _source_index

BACKEND_ROOT = Path(__file__).resolve().parents[1]
SERVICE_PATH = BACKEND_ROOT / "app/services/preprocessing_provenance.py"


def _file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def evaluate(snapshot_path: Path, runtime_secret: bytes) -> dict[str, Any]:
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    selected = select_exact_ai_ready(snapshot)
    if len(selected) != 41:
        raise ValueError(f"expected exact AI-ready universe of 41, got {len(selected)}")
    sources = _source_index(snapshot)
    results: list[dict[str, Any]] = []
    for candidate_id, candidate in selected:
        if candidate.get("rule_id") != "LEA-011":
            continue
        source_id = candidate.get("source_id")
        source = sources.get(source_id) if isinstance(source_id, str) else None
        if source is None:
            results.append({"verified": False, "usable": False,
                            "reason": "complete_source_unresolvable"})
            continue
        envelope = unavailable_preprocessing_provenance(
            source=source, candidate_id=candidate_id, rule_id="LEA-011",
            reason="snapshot_has_no_build_manifest_or_translation_unit_path",
            runtime_secret=runtime_secret,
        )
        results.append(verify_preprocessing_provenance(
            envelope, runtime_secret, envelope["provenance"],
        ))

    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=BACKEND_ROOT.parent,
                          check=True, capture_output=True, text=True).stdout.strip()
    bindings = [_sha({"candidate_id": cid, "payload": row}) for cid, row in selected]
    return {
        "schema_version": "1.0",
        "evaluation": "current_head_exact_ai_ready41_lea011_preprocessing_provenance",
        "population": {"exact_ai_ready": len(selected), "lea011": len(results)},
        "api_calls": 0,
        "authenticated_envelopes": sum(row["verified"] for row in results),
        "usable_preprocessing_context": sum(row["usable"] for row in results),
        "reasons": dict(sorted(Counter(row["reason"] for row in results).items())),
        "production_authorized": 0,
        "candidate_universe_sha256": _sha(bindings),
        "provenance": {
            "git_head_at_snapshot_lineage": head,
            "snapshot_sha256": _file_sha(snapshot_path),
            "contract_sha256": _file_sha(SERVICE_PATH),
            "runner_sha256": _file_sha(Path(__file__)),
        },
        "privacy": "aggregate_only; source, identifiers, paths, commands, macros, and runtime secret are not persisted",
        "claim_limit": "Authenticated absence evidence is not usable preprocessing evidence and cannot authorize a verdict.",
    }


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = evaluate(args.snapshot, secrets.token_bytes(32))
    args.output.write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
                           encoding="utf-8")


if __name__ == "__main__":
    main()
