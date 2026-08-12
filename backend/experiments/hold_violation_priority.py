"""Closed aggregate triage for proxy violations routed to hold.

Private occurrence data are read in memory.  The returned artifact contains
only rule/family/gap counts and deliberately excludes occurrence identities,
paths, source text, line numbers, and snippets.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from app.services.llm.candidate_selector import _select_l3_candidates
from app.services.rag_service import run_l2_rag_context
from experiments.full_stage_boundary_benchmark import load_candidates


class HoldTriageInputError(ValueError):
    pass


ACTIONABILITY = {
    "exact_locator_gap": "evidence_mapping",
    "authority_gap": "source_acquisition_then_mapping",
    "applicability_gap": "applicability_contract_then_mapping",
    "detector_scope": "detector_change_not_mapping_only",
    "routing_or_selector_gap": "routing_or_selector_review",
}


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _ratio(n: int, d: int) -> float:
    return round(n / d, 8) if d else 0.0


def summarize(rows: list[dict[str, str]], gap_audit: dict[str, Any], *,
              evidence_audit: dict[str, Any] | None = None,
              input_sha256: dict[str, str]) -> dict[str, Any]:
    """Build a disclosure-minimized priority table from already joined rows."""
    required = {"rule_id", "family", "group_id", "stage", "label"}
    if not rows or any(set(row) != required for row in rows):
        raise HoldTriageInputError("closed joined rows required")
    if any(not all(isinstance(row[key], str) and row[key] for key in required) for row in rows):
        raise HoldTriageInputError("joined row values must be non-empty strings")
    gaps = {row["rule_id"]: row for row in gap_audit.get("rules", [])}
    if len(gaps) != gap_audit.get("failclosed_rule_count"):
        raise HoldTriageInputError("invalid failclosed gap registry")

    target = [row for row in rows if row["stage"] == "hold" and row["label"] == "violation"]
    if not target:
        raise HoldTriageInputError("hold proxy-violation population is empty")
    registry = (evidence_audit or {}).get("rules", {})
    missing = sorted({row["rule_id"] for row in target} - set(gaps) - set(registry))
    if missing:
        raise HoldTriageInputError("target rules missing from evidence audit registries")

    per_rule: dict[str, list[dict[str, str]]] = defaultdict(list)
    per_family: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in target:
        per_rule[row["rule_id"]].append(row)
        per_family[row["family"]].append(row)

    priority = []
    for rule_id, members in per_rule.items():
        status = registry.get(rule_id, {}).get("status", "review_required")
        gap = ("routing_or_selector_gap" if status == "verified" else
               gaps[rule_id]["primary_gap"] if rule_id in gaps else "routing_or_selector_gap")
        priority.append({
            "rule_id": rule_id,
            "family": members[0]["family"],
            "audit_status": status,
            "primary_gap": gap,
            "required_action": ACTIONABILITY[gap],
            "proxy_violation_occurrences": len(members),
            "unique_clone_groups": len({row["group_id"] for row in members}),
        })
    priority.sort(key=lambda row: (-row["proxy_violation_occurrences"],
                                   -row["unique_clone_groups"], row["rule_id"]))
    cumulative = 0
    for rank, row in enumerate(priority, 1):
        cumulative += row["proxy_violation_occurrences"]
        row["rank"] = rank
        row["cumulative_occurrences"] = cumulative
        row["cumulative_population_ratio"] = _ratio(cumulative, len(target))

    mapping_priority = [dict(row) for row in priority
                        if row["primary_gap"] in
                        {"exact_locator_gap", "authority_gap", "applicability_gap"}]
    mapping_cumulative = 0
    for rank, row in enumerate(mapping_priority, 1):
        mapping_cumulative += row["proxy_violation_occurrences"]
        row["mapping_rank"] = rank
        row["cumulative_mapping_occurrences"] = mapping_cumulative
        row["cumulative_target_population_ratio"] = _ratio(mapping_cumulative, len(target))

    family_rows = []
    for family, members in per_family.items():
        gap_counts = Counter(
            "routing_or_selector_gap"
            if registry.get(row["rule_id"], {}).get("status") == "verified"
            else gaps[row["rule_id"]]["primary_gap"] if row["rule_id"] in gaps
            else "routing_or_selector_gap"
            for row in members
        )
        family_rows.append({
            "family": family,
            "proxy_violation_occurrences": len(members),
            "unique_rules": len({row["rule_id"] for row in members}),
            "unique_clone_groups": len({row["group_id"] for row in members}),
            "gap_counts": dict(sorted(gap_counts.items())),
        })
    family_rows.sort(key=lambda row: (-row["proxy_violation_occurrences"], row["family"]))

    gap_counts = Counter(
        "routing_or_selector_gap"
        if registry.get(row["rule_id"], {}).get("status") == "verified"
        else gaps[row["rule_id"]]["primary_gap"] if row["rule_id"] in gaps
        else "routing_or_selector_gap"
        for row in target
    )
    mapping_upper = sum(gap_counts[gap] for gap in
                        ("exact_locator_gap", "authority_gap", "applicability_gap"))
    return {
        "schema_version": "1.0",
        "analysis_scope": {
            "population": "historical_265_hold_same_model_proxy_violation",
            "claim_limit": "Prioritization proxy only; not independent human ground truth or measured accuracy gain.",
            "content_policy": "aggregate_only_no_occurrence_id_source_path_line_or_snippet",
            "input_sha256": dict(sorted(input_sha256.items())),
        },
        "target": {
            "proxy_violation_occurrences": len(target),
            "unique_rules": len(per_rule),
            "unique_families": len(per_family),
            "unique_clone_groups": len({row["group_id"] for row in target}),
        },
        "gap_distribution": dict(sorted(gap_counts.items())),
        "coverage_potential_upper_bound": {
            "evidence_or_contract_work_occurrences": mapping_upper,
            "evidence_or_contract_work_ratio": _ratio(mapping_upper, len(target)),
            "detector_change_occurrences": gap_counts["detector_scope"],
            "detector_change_ratio": _ratio(gap_counts["detector_scope"], len(target)),
            "warning": "Potential means candidates eligible for remediation review, not automatic promotion or realized AI-ready coverage.",
        },
        "family_priority": family_rows,
        "evidence_mapping_priority": mapping_priority,
        "rule_priority": priority,
    }


def evaluate(snapshot_path: Path, sidecar_path: Path, gt_path: Path,
             gap_path: Path, evidence_audit_path: Path | None = None) -> dict[str, Any]:
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
    gt = json.loads(gt_path.read_text(encoding="utf-8"))
    gap = json.loads(gap_path.read_text(encoding="utf-8"))
    evidence_audit = (json.loads(evidence_audit_path.read_text(encoding="utf-8"))
                      if evidence_audit_path else None)
    candidates = load_candidates(snapshot)
    envelopes = snapshot.get("candidates", [])
    by_id = {row.get("candidate_id"): payload for row, payload in zip(envelopes, candidates, strict=True)}
    occurrences = sidecar.get("occurrences")
    labels = gt.get("rows")
    if not isinstance(occurrences, list) or not isinstance(labels, list):
        raise HoldTriageInputError("closed occurrence and label arrays required")
    by_label = {row.get("occurrence_id"): row.get("label") for row in labels}
    if len(by_id) != len(envelopes) or len(by_label) != len(labels) or len(occurrences) != len(envelopes):
        raise HoldTriageInputError("non-bijective private inputs")
    joined = []
    payloads = []
    metadata = []
    for occurrence in occurrences:
        payload = by_id.get(occurrence.get("frozen_candidate_id"))
        label = by_label.get(occurrence.get("occurrence_id"))
        if not isinstance(payload, dict) or not isinstance(label, str):
            raise HoldTriageInputError("private join failure")
        if payload.get("rule_id") != occurrence.get("rule_id"):
            raise HoldTriageInputError("sidecar rule binding failure")
        payloads.append(dict(payload))
        metadata.append((str(label), str(occurrence.get("group_id"))))
    with contextlib.redirect_stdout(io.StringIO()):
        routed = run_l2_rag_context(payloads)
        selected = {id(row) for row in _select_l3_candidates(routed)}
    for row, (label, group_id) in zip(routed, metadata, strict=True):
        disposition = row.get("disposition")
        stage = ("deterministic" if disposition == "deterministic" else
                 "ai_ready" if disposition == "ai_required" and row.get("ai_need") == "required"
                 and id(row) in selected else "hold")
        rule_id = str(row.get("rule_id"))
        joined.append({"rule_id": rule_id, "family": rule_id.split("-", 1)[0],
                       "group_id": group_id, "stage": stage, "label": label})
    hashes = {
        "snapshot": _sha(snapshot_path), "sidecar": _sha(sidecar_path),
        "proxy_gt": _sha(gt_path), "gap_audit": _sha(gap_path),
    }
    if evidence_audit_path:
        hashes["evidence_audit"] = _sha(evidence_audit_path)
    return summarize(joined, gap, evidence_audit=evidence_audit, input_sha256=hashes)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("sidecar", type=Path)
    parser.add_argument("proxy_gt", type=Path)
    parser.add_argument("gap_audit", type=Path)
    parser.add_argument("evidence_audit", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = evaluate(args.snapshot, args.sidecar, args.proxy_gt, args.gap_audit,
                      args.evidence_audit)
    args.output.write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
                           encoding="utf-8")


if __name__ == "__main__":
    main()
