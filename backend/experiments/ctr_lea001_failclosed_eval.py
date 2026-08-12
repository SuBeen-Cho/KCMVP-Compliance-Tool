"""API-free aggregate evaluation of the CTR-LEA-001 evidence gate."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from experiments.full_stage_boundary_benchmark import load_candidates
from experiments.workspace_guard import guarded_output_path

BACKEND = Path(__file__).resolve().parents[1]
AUDIT_PATH = BACKEND / "mapping/ctr_lea001_entailment_gate.json"
PRIORITY_PATH = BACKEND / "mapping/hold_proxy_violation_priority_after_promotion.json"
FREEZE_PATH = BACKEND / "evaluation/public_current_head_ai_ready45_freeze.json"
RULE_ID = "CTR-LEA-001"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(snapshot: dict[str, Any], *, snapshot_sha256: str, audit: dict[str, Any],
          priority: dict[str, Any], freeze: dict[str, Any]) -> dict[str, Any]:
    if audit.get("rule_id") != RULE_ID or audit.get("decision") != "remain_fail_closed":
        raise ValueError("ctr_lea001_failclosed_audit_invalid")
    if audit.get("extractor_gate") != "blocked_until_complete_claim_has_direct_normative_entailment":
        raise ValueError("ctr_lea001_extractor_gate_invalid")
    if audit.get("production_authorized") is not False:
        raise ValueError("ctr_lea001_production_authorization_invalid")
    frozen = freeze.get("snapshot") or {}
    if frozen.get("file_sha256") != snapshot_sha256 or freeze.get("api_calls") != 0:
        raise ValueError("frozen_snapshot_identity_mismatch")

    candidates = load_candidates(snapshot)
    target_count = sum(row.get("rule_id") == RULE_ID for row in candidates)
    priority_row = None
    for value in priority.values():
        if isinstance(value, list):
            priority_row = next((row for row in value if isinstance(row, dict)
                                 and row.get("rule_id") == RULE_ID), None)
            if priority_row:
                break
    proxy_count = int((priority_row or {}).get("proxy_violation_occurrences", -1))
    if target_count != 6 or proxy_count != 3:
        raise ValueError("ctr_lea001_frozen_population_invalid")

    return {
        "schema_version": "1.0",
        "evaluation": "frozen_current265_ctr_lea001_entailment_gate_api_free",
        "population": {"frozen_candidates": len(candidates),
                       "ctr_lea001_occurrences": target_count,
                       "prioritized_proxy_violations": proxy_count},
        "evidence_gate": {"exact_complete_claim_entailed": 0,
                          "remain_fail_closed": target_count,
                          "extractor_implemented": 0},
        "authenticated_program_context": {"verified_preprocessing_binding": 0,
            "verified_build_manifest": 0, "clang_extent_and_symbol_role_fact": 0,
            "unknown_or_abstain": target_count},
        "api_calls": 0, "production_authorized": 0,
        "provenance": {"snapshot_sha256": snapshot_sha256,
            "snapshot_id": frozen.get("snapshot_id"),
            "frozen_git_commit": frozen.get("git_commit"),
            "entailment_audit_sha256": _sha(AUDIT_PATH),
            "priority_report_sha256": _sha(PRIORITY_PATH),
            "freeze_sha256": _sha(FREEZE_PATH),
            "runner_sha256": _sha(Path(__file__))},
        "privacy": "aggregate_only; no candidate id, source, path, snippet, span, or manifest persisted",
        "claim_limit": "Evidence/extractor gating only; no detector accuracy or semantic correctness claim."
    }


def evaluate(snapshot_path: Path) -> dict[str, Any]:
    raw = snapshot_path.read_bytes()
    return build(json.loads(raw), snapshot_sha256=hashlib.sha256(raw).hexdigest(),
        audit=json.loads(AUDIT_PATH.read_text(encoding="utf-8")),
        priority=json.loads(PRIORITY_PATH.read_text(encoding="utf-8")),
        freeze=json.loads(FREEZE_PATH.read_text(encoding="utf-8")))


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
