"""API-free aggregate audit of the live 45-occurrence AI-ready boundary."""
from __future__ import annotations

from collections import Counter
import hashlib
import json
import math
from pathlib import Path
from typing import Any

from experiments.current_router_snapshot_eval import evaluate as evaluate_router
from experiments.grounded_ai_ready_eval import select_exact_ai_ready


BACKEND = Path(__file__).resolve().parents[1]
AUDIT_PATH = BACKEND / "mapping/rule_evidence_audit.json"
ATOMIC_PATH = BACKEND / "mapping/atomic_claim_evidence_registry.json"
HISTORICAL_ATOMIC_PATH = BACKEND / "evaluation/public_atomic_claim_v3_current_head.json"
NEW_LEA_ROUND_RULES = frozenset({"LEA-027", "LEA-028", "LEA-029", "LEA-030", "LEA-031"})


def _sha_bytes(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _unit_is_bound(unit: Any, *, source_sha256: str) -> bool:
    return bool(
        isinstance(unit, dict)
        and isinstance(unit.get("unit_id"), str)
        and unit.get("status") == "verified"
        and unit.get("source_sha256") == source_sha256
        and isinstance(unit.get("span"), str)
        and hashlib.sha256(unit["span"].encode()).hexdigest() == unit.get("span_sha256")
    )


def _binding_complete(candidate: dict[str, Any], audit: dict[str, Any]) -> bool:
    rule_id = str(candidate.get("rule_id") or "").upper()
    row = audit.get("rules", {}).get(rule_id, {})
    bundle = candidate.get("rag_evidence_bundle")
    required = row.get("evidence_unit_ids")
    provenance = candidate.get("rule_provenance_sha256")
    bundle_ids = [unit.get("unit_id") for unit in bundle if isinstance(unit, dict)] \
        if isinstance(bundle, list) else []
    return bool(
        row.get("status") == "verified"
        and row.get("review_required") is False
        and isinstance(required, list)
        and required
        and isinstance(bundle, list)
        and bundle
        and isinstance(provenance, str)
        and len(provenance) == 64
        and len(required) == len(set(required))
        and len(bundle_ids) == len(set(bundle_ids))
        and set(required) == set(bundle_ids)
        and all(_unit_is_bound(unit, source_sha256=str(row.get("source_sha256"))) for unit in bundle)
    )


def build(snapshot: dict[str, Any], *, snapshot_sha256: str,
          router_result: dict[str, Any], audit: dict[str, Any], atomic: dict[str, Any],
          historical_atomic: dict[str, Any]) -> dict[str, Any]:
    selected = select_exact_ai_ready(snapshot)
    if len(selected) != 45:
        raise ValueError(f"live AI-ready population must be exactly 45, got {len(selected)}")
    if router_result.get("stage_distribution", {}).get("ai_ready", {}).get("count") != 45:
        raise ValueError("router and selector population disagree")
    if router_result.get("snapshot", {}).get("file_sha256") != snapshot_sha256:
        raise ValueError("router and stage evaluation snapshot identity disagree")

    candidates = [row for _, row in selected]
    rule_counts = Counter(str(row.get("rule_id") or "") for row in candidates)
    new_round_counts = {rule: rule_counts[rule] for rule in sorted(NEW_LEA_ROUND_RULES)}
    new_round_total = sum(new_round_counts.values())
    bound = sum(_binding_complete(row, audit) for row in candidates)
    atomic_rules = atomic.get("rules", {})
    atomic_bound = sum(bool(atomic_rules.get(str(row.get("rule_id") or ""))) for row in candidates)
    sealed_facts = sum(bool(row.get("sealed_program_fact")) for row in candidates)
    project_facts = sum(bool(row.get("project_artifact_evidence")) for row in candidates)

    old_population = int(historical_atomic["population"])
    if old_population != 41 or int(historical_atomic["api_calls"]) != 41:
        raise ValueError("historical atomic baseline is not the sealed 41-call run")
    scale = len(candidates) / old_population
    projected_input = math.ceil(int(historical_atomic["input_tokens"]) * scale)
    projected_output = math.ceil(int(historical_atomic["output_tokens"]) * scale)
    projected_cost = round(float(historical_atomic["estimated_cost_usd"]) * scale, 9)

    return {
        "schema_version": "1.0",
        "evaluation": "live_current45_stage_and_evidence_api_free",
        "claim_limit": (
            "Routing, binding, and budget projection only; no model decision, semantic "
            "authorization, detector accuracy, or billing upper-bound claim."
        ),
        "api_calls": 0,
        "population": {"snapshot_candidates": len(snapshot["candidates"]), "live_ai_ready": 45},
        "stage_distribution": router_result["stage_distribution"],
        "evidence_binding": {
            "verified_rule_and_required_units_complete": bound,
            "atomic_claim_registry_available": atomic_bound,
            "incomplete": len(candidates) - bound,
        },
        "program_fact": {
            "authenticated_sealed_fact_available": sealed_facts,
            "unsealed_project_artifact_text_available": project_facts,
            "production_semantic_authorized": 0,
        },
        "newly_mapped_lea_round": {
            "rule_counts": new_round_counts,
            "occurrences": new_round_total,
            "all_remain_ai_review_only": True,
        },
        "historical41_comparison": {
            "population_delta": 4,
            "call_count_if_one_grounded_call_each": {"historical": 41, "current": 45, "delta": 4},
            "atomic_v3_observed_linear_budget_projection": {
                "method": "ceil tokens and scale observed aggregate cost by 45/41",
                "input_tokens": projected_input,
                "output_tokens": projected_output,
                "estimated_cost_usd": projected_cost,
                "warning": "Planning projection from one historical run, not a guaranteed token or price upper bound.",
            },
            "paired_rag_no_rag_call_count_if_run": 90,
        },
        "provenance": {
            "snapshot_sha256": snapshot_sha256,
            "router_ai_ready_universe_sha256": router_result["ai_ready_universe"]["ordered_envelope_binding_hashes_sha256"],
            "rule_evidence_audit_sha256": _sha_bytes(AUDIT_PATH),
            "atomic_registry_sha256": _sha_bytes(ATOMIC_PATH),
            "historical_atomic_public_sha256": _sha_bytes(HISTORICAL_ATOMIC_PATH),
            "router_manifest": router_result.get("manifest"),
        },
        "privacy": "aggregate_only; no candidate identifiers, paths, snippets, prompts, or source text",
    }


def evaluate(snapshot_path: Path, *, warm_runs: int = 5) -> dict[str, Any]:
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    router = evaluate_router(snapshot_path, warm_runs=warm_runs)
    return build(
        snapshot,
        snapshot_sha256=_sha_bytes(snapshot_path),
        router_result=router,
        audit=json.loads(AUDIT_PATH.read_text(encoding="utf-8")),
        atomic=json.loads(ATOMIC_PATH.read_text(encoding="utf-8")),
        historical_atomic=json.loads(HISTORICAL_ATOMIC_PATH.read_text(encoding="utf-8")),
    )
