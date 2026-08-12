"""API-free, aggregate-only LEA-011 def-use evaluation on exact AI-ready41."""
from __future__ import annotations

import hashlib
import json
import secrets
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any

from experiments.grounded_ai_ready_eval import _sha, select_exact_ai_ready
from experiments.lea011_program_fact_shadow import evaluate_candidate

BACKEND_ROOT = Path(__file__).resolve().parents[1]
EXTRACTOR_PATH = BACKEND_ROOT / "app/services/lea011_program_fact_extractor.py"


def _file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _source_index(snapshot: dict[str, Any]) -> dict[str, str]:
    """Verify embedded complete sources and index them without exposing identities."""
    result: dict[str, str] = {}
    for row in snapshot.get("sources") or []:
        source_id, content, claimed = row.get("source_id"), row.get("content"), row.get("sha256")
        if not isinstance(source_id, str) or not source_id or source_id in result:
            raise ValueError("source_identity_invalid_or_duplicate")
        if not isinstance(content, str) or hashlib.sha256(content.encode()).hexdigest() != claimed:
            raise ValueError("source_content_hash_mismatch")
        if row.get("bytes") != len(content.encode()) or row.get("lines") != len(content.splitlines()):
            raise ValueError("source_metadata_mismatch")
        result[source_id] = content
    return result


def evaluate(snapshot_path: Path, runtime_secret: bytes) -> dict[str, Any]:
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    selected = select_exact_ai_ready(snapshot)
    if len(selected) != 41:
        raise ValueError(f"expected exact AI-ready universe of 41, got {len(selected)}")
    sources = _source_index(snapshot)
    rows: list[dict[str, Any]] = []
    for candidate_id, candidate in selected:
        if candidate.get("rule_id") != "LEA-011":
            continue
        source_id = candidate.get("source_id")
        source = sources.get(source_id) if isinstance(source_id, str) else None
        if source is None:
            outcome = {"state": "unknown", "reason": "complete_source_unresolvable",
                       "production_authorized": False}
            resolved = False
        else:
            # Applicability comes from the audited LEA-011 claim, not a filename
            # or function identifier. The extractor still proves the code fact.
            value = dict(candidate)
            value.update({"algorithm": "LEA", "operation": "key_schedule",
                          "complete_source": source})
            outcome = evaluate_candidate(candidate_id, value, runtime_secret)
            resolved = True
        rows.append({"state": outcome["state"],
                     "reason": outcome.get("extraction_reason", outcome["reason"]),
                     "resolved": resolved,
                     "production_authorized": bool(outcome["production_authorized"])})

    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=BACKEND_ROOT.parent,
                          check=True, capture_output=True, text=True).stdout.strip()
    bindings = [_sha({"candidate_id": cid, "payload": row}) for cid, row in selected]
    return {
        "schema_version": "1.0",
        "evaluation": "current_head_exact_ai_ready41_lea011_defuse_shadow",
        "population": {"exact_ai_ready": len(selected), "lea011": len(rows)},
        "api_calls": 0,
        "complete_source_resolution": {
            "resolved": sum(row["resolved"] for row in rows),
            "unresolved": sum(not row["resolved"] for row in rows),
            "method": "snapshot_embedded_content_joined_by_opaque_source_id_and_sha256",
        },
        "fact_states": dict(sorted(Counter(row["state"] for row in rows).items())),
        "reasons": dict(sorted(Counter(row["reason"] for row in rows).items())),
        "production_authorized": sum(row["production_authorized"] for row in rows),
        "candidate_universe_sha256": _sha(bindings),
        "provenance": {"git_head": head, "snapshot_sha256": _file_sha(snapshot_path),
                       "extractor_sha256": _file_sha(EXTRACTOR_PATH),
                       "runner_sha256": _file_sha(Path(__file__))},
        "privacy": "aggregate_only; no source, source_id, path, occurrence, or runtime secret persisted",
        "claim_limit": "Shadow program-fact coverage only; not detector accuracy or production authorization.",
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
