"""Aggregate-only, API-free shadow audit of legacy decisions against atomic contracts."""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path

from app.services.atomic_claim_contract import build_atomic_contract, verify_atomic_assessments
from app.services.rag_grounding import verify_citation_bound_decision
from experiments.grounded_ai_ready_eval import select_exact_ai_ready


def run(snapshot_path: Path, ledger_path: Path) -> dict:
    selected = select_exact_ai_ready(json.loads(snapshot_path.read_text(encoding="utf-8")))
    rows = [json.loads(x) for x in ledger_path.read_text(encoding="utf-8").splitlines() if x]
    grounded = {int(r["index"]): r for r in rows if r.get("condition") == "grounded"}
    if len(selected) != 41 or set(grounded) != set(range(41)):
        raise ValueError("expected the sealed 41-case grounded population")
    reasons, rules, legacy = Counter(), defaultdict(Counter), 0
    allowed_choice, structural = 0, 0
    for index, (_, candidate) in enumerate(selected):
        row = grounded[index]
        decision = row.get("decision") or {}
        reason = str(row.get("verifier_reason"))
        rule_id = str(candidate.get("rule_id"))
        reasons[reason] += 1; rules[rule_id][reason] += 1
        legacy += bool(verify_citation_bound_decision(candidate, decision)["verified"])
        contract = build_atomic_contract(rule_id, list(candidate.get("rag_evidence_bundle") or []))
        allowed = {x for c in contract.get("claims", []) for x in c["allowed_evidence_unit_ids"]}
        chosen = decision.get("evidence_unit_ids") or []
        allowed_choice += bool(chosen) and all(x in allowed for x in chosen)
        structural += bool(verify_atomic_assessments(contract, decision).get("structurally_valid"))
    return {
        "schema_version": "1.0", "evaluation": "atomic_claim_v3_shadow_replay",
        "api_calls": 0, "population": 41,
        "three_stage_metrics": {
            "citation_choice_within_audited_set": allowed_choice,
            "atomic_contract_structurally_valid": structural,
            "independently_semantically_authorized": 0,
        },
        "legacy_v2_verifier_pass": legacy,
        "legacy_failure_reasons": dict(sorted(reasons.items())),
        "rule_reason_counts": {k: dict(sorted(v.items())) for k, v in sorted(rules.items())},
        "interpretation": "Shadow compatibility only. Legacy decisions lack atomic assessments; no fields are imputed and no final verdict is newly authorized.",
        "privacy": "aggregate-only; no occurrence identity, source path, snippet, prompt, span, or decision text",
        "snapshot_sha256": hashlib.sha256(snapshot_path.read_bytes()).hexdigest(),
        "private_ledger_sha256": hashlib.sha256(ledger_path.read_bytes()).hexdigest(),
    }


def main() -> None:
    p = argparse.ArgumentParser(); p.add_argument("snapshot", type=Path); p.add_argument("ledger", type=Path)
    p.add_argument("--output", type=Path, required=True); a = p.parse_args()
    result = run(a.snapshot, a.ledger)
    a.output.write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2)+"\n", encoding="utf-8")


if __name__ == "__main__": main()
