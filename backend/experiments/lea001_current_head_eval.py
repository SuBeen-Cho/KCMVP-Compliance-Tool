"""API-free LEA-001 shadow evaluation on the exact current AI-ready universe."""
from __future__ import annotations

import hashlib
import json
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any

from experiments.grounded_ai_ready_eval import _sha, select_exact_ai_ready
from app.services.lea001_clang_block_proof import prove_lea001_block_semantics

BACKEND_ROOT = Path(__file__).resolve().parents[1]
EXTRACTOR_PATH = BACKEND_ROOT / "app/services/lea001_clang_block_proof.py"


def _file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _source_index(snapshot: dict[str, Any]) -> dict[str, str]:
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


def evaluate(snapshot_path: Path) -> dict[str, Any]:
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    selected = select_exact_ai_ready(snapshot)
    if len(selected) != 41:
        raise ValueError(f"expected exact AI-ready universe of 41, got {len(selected)}")
    sources = _source_index(snapshot)
    rows: list[dict[str, Any]] = []
    for _candidate_id, candidate in selected:
        if candidate.get("rule_id") != "LEA-001":
            continue
        source_id = candidate.get("source_id")
        source = sources.get(source_id) if isinstance(source_id, str) else None
        if source is None:
            rows.append({"resolved": False, "manifest": False, "structural_complete": False,
                         "state": "unknown", "reason": "complete_source_unresolvable"})
            continue
        # A source blob is not a compiler manifest.  The frozen snapshot contains
        # no compiler binary/argv/cwd/include/macro capture, so treating it as an
        # already-preprocessed translation unit would manufacture provenance.
        manifest = candidate.get("trusted_preprocessing_manifest")
        if not isinstance(manifest, dict):
            outcome = prove_lea001_block_semantics(source, preprocessed=False)
            rows.append({"resolved": True, "manifest": False,
                         "structural_complete": bool(outcome.get("structural_complete")),
                         "state": outcome["state"], "reason": "trusted_preprocessing_manifest_unavailable"})
            continue
        # This evaluator deliberately does not accept an unverified embedded dict.
        # Replay must be performed by the sealed capture service in a future run.
        rows.append({"resolved": True, "manifest": False, "structural_complete": False,
                     "state": "unknown", "reason": "trusted_preprocessing_manifest_unverified"})

    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=BACKEND_ROOT.parent,
                          check=True, capture_output=True, text=True).stdout.strip()
    bindings = [_sha({"candidate_id": candidate_id, "payload": row})
                for candidate_id, row in selected]
    return {
        "schema_version": "1.0",
        "evaluation": "current_head_exact_ai_ready41_lea001_ast_shadow",
        "population": {"exact_ai_ready": len(selected), "lea001": len(rows)},
        "api_calls": 0,
        "complete_source_resolution": {
            "resolved": sum(row["resolved"] for row in rows),
            "unresolved": sum(not row["resolved"] for row in rows),
        },
        "trusted_preprocessing": {
            "usable": sum(row["manifest"] for row in rows),
            "unavailable_or_unverified": sum(not row["manifest"] for row in rows),
        },
        "structural_complete": sum(row["structural_complete"] for row in rows),
        "fact_states": dict(sorted(Counter(row["state"] for row in rows).items())),
        "reasons": dict(sorted(Counter(row["reason"] for row in rows).items())),
        "production_authorized": 0,
        "candidate_universe_sha256": _sha(bindings),
        "provenance": {"git_head": head, "snapshot_sha256": _file_sha(snapshot_path),
                       "extractor_sha256": _file_sha(EXTRACTOR_PATH),
                       "runner_sha256": _file_sha(Path(__file__))},
        "privacy": "aggregate_only; no source, source_id, path, occurrence, or secret persisted",
        "claim_limit": "Shadow preprocessing/AST coverage only; not detector accuracy or authorization.",
    }


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = evaluate(args.snapshot)
    args.output.write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
                           encoding="utf-8")


if __name__ == "__main__":
    main()
