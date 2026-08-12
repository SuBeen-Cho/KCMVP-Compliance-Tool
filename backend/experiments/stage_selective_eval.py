"""Evaluate stage routing against an explicitly limited proxy reference.

The output intentionally contains aggregates only.  It is not a replacement
for an occurrence-level, independently adjudicated human ground truth.
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
from collections import Counter
from pathlib import Path
from typing import Any

from app.services.rag_service import run_l2_rag_context
from app.services.llm.candidate_selector import _select_l3_candidates


LABELS = frozenset({"violation", "non_violation", "insufficient_context", "not_applicable"})
BINARY = frozenset({"violation", "non_violation"})


class SelectiveEvalInputError(ValueError):
    pass


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 8) if denominator else None


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def summarize(stage_rows: list[dict[str, str]], *, snapshot_id: str, gt_id: str,
              input_sha256: dict[str, str]) -> dict[str, Any]:
    """Summarize closed stage/label rows without publishing occurrence data."""
    if not stage_rows:
        raise SelectiveEvalInputError("non-empty stage rows required")
    allowed = {"deterministic", "ai_ready", "hold"}
    if any(set(row) != {"stage", "label"} or row["stage"] not in allowed
           or row["label"] not in LABELS for row in stage_rows):
        raise SelectiveEvalInputError("invalid closed stage row")

    total = len(stage_rows)
    stages = Counter(row["stage"] for row in stage_rows)
    labels = Counter(row["label"] for row in stage_rows)
    cross = Counter((row["stage"], row["label"]) for row in stage_rows)
    binary_total = sum(labels[label] for label in BINARY)
    proxy_abstention_total = total - binary_total
    det_binary = sum(cross[("deterministic", label)] for label in BINARY)

    def partition(stage: str, denominator: int, scope_labels: set[str]) -> dict[str, Any]:
        count = sum(cross[(stage, label)] for label in scope_labels)
        return {"count": count, "coverage": _ratio(count, denominator)}

    all_labels = set(LABELS)
    return {
        "schema_version": "1.0",
        "evaluation_design": {
            "snapshot_id": snapshot_id,
            "proxy_gt_id": gt_id,
            "reference": "same_model_temperature_0_test_retest_unanimous_proxy",
            "evaluation_scope": "historical_265_snapshot_policy_replay",
            "claim_limit": (
                "Internal routing/selective-behavior estimate only; the proxy is not independent "
                "human ground truth. This historical-policy replay is not a current end-to-end "
                "performance estimate or external precision, recall, or F1."
            ),
            "deterministic_verdict_semantics": "routing_only_no_final_verdict",
            "input_sha256": dict(sorted(input_sha256.items())),
        },
        "population": {
            "total": total,
            "proxy_labels": dict(sorted(labels.items())),
            "binary_eligible": binary_total,
            "proxy_abstention_labels": proxy_abstention_total,
        },
        "routing_all": {
            stage: partition(stage, total, all_labels)
            for stage in ("deterministic", "ai_ready", "hold")
        },
        "routing_binary_eligible": {
            stage: partition(stage, binary_total, set(BINARY))
            for stage in ("deterministic", "ai_ready", "hold")
        },
        "stage_proxy_label_distributions": {
            stage: {label: cross[(stage, label)] for label in sorted(LABELS)}
            for stage in ("deterministic", "ai_ready", "hold")
        },
        "full_verifier_outcomes": {
            "count": 0, "coverage": 0.0, "accuracy": None,
            "reason": "This routing replay invokes no LLM and therefore has no citation-entailment-verified final decisions.",
        },
        "deterministic_selective_performance": {
            "binary_eligible_verdicts": det_binary,
            "accuracy_abstention_excluded": None,
            "selective_risk_abstention_excluded": None,
            "binary_population_coverage": _ratio(det_binary, binary_total),
            "proxy_label_distribution": {
                label: cross[("deterministic", label)] for label in sorted(LABELS)
            },
            "reason_unavailable": (
                "The stage contract records routing disposition but no explicit final verdict; "
                "a deterministic route must not be coerced to violation or non_violation."
            ),
        },
        "hold_analysis": {
            "count": stages["hold"],
            "coverage": _ratio(stages["hold"], total),
            "proxy_label_distribution": {
                label: cross[("hold", label)] for label in sorted(LABELS)
            },
            "proxy_violation_count": cross[("hold", "violation")],
            "warning": "Hold is abstention and is never counted as a correct prediction.",
        },
    }


def evaluate(snapshot_path: Path, sidecar_path: Path, gt_path: Path) -> dict[str, Any]:
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
    gt = json.loads(gt_path.read_text(encoding="utf-8"))
    snapshot_id = snapshot.get("snapshot_id")
    if not snapshot_id or sidecar.get("snapshot_id") != snapshot_id:
        raise SelectiveEvalInputError("snapshot identity mismatch")
    candidates = snapshot.get("candidates")
    occurrences = sidecar.get("occurrences")
    labels = gt.get("rows")
    if not all(isinstance(value, list) for value in (candidates, occurrences, labels)):
        raise SelectiveEvalInputError("closed input arrays required")
    by_candidate = {row.get("candidate_id"): row.get("payload") for row in candidates}
    by_label = {row.get("occurrence_id"): row.get("label") for row in labels}
    if len(by_candidate) != len(candidates) or len(by_label) != len(labels):
        raise SelectiveEvalInputError("duplicate input identity")
    if len(occurrences) != len(candidates) or len(occurrences) != len(labels):
        raise SelectiveEvalInputError("non-bijective population")

    joined: list[tuple[dict[str, Any], str]] = []
    for occurrence in occurrences:
        payload = by_candidate.get(occurrence.get("frozen_candidate_id"))
        label = by_label.get(occurrence.get("occurrence_id"))
        if not isinstance(payload, dict) or label not in LABELS:
            raise SelectiveEvalInputError("sidecar join failure")
        joined.append((dict(payload), label))

    # Existing services emit diagnostic prints; the closed evaluator keeps its
    # stdout machine-readable and does not persist candidate content.  Route
    # the frozen population as one batch because the production selector cap is
    # population-relative; singleton routing would measure a different policy.
    with contextlib.redirect_stdout(io.StringIO()):
        routed_batch = run_l2_rag_context([payload for payload, _ in joined])
        selected_for_l3 = _select_l3_candidates(routed_batch)
    if len(routed_batch) != len(joined):
        raise SelectiveEvalInputError("router changed population cardinality")
    selected_ids = {id(row) for row in selected_for_l3}
    rows: list[dict[str, str]] = []
    for routed, (_, label) in zip(routed_batch, joined, strict=True):
            disposition = routed.get("disposition")
            stage = (
                "deterministic" if disposition == "deterministic" else
                "ai_ready" if disposition == "ai_required" and routed.get("ai_need") == "required"
                and id(routed) in selected_ids else
                "hold"
            )
            rows.append({"stage": stage, "label": label})
    return summarize(
        rows, snapshot_id=snapshot_id, gt_id=str(gt.get("gt_id") or ""),
        input_sha256={
            "snapshot": _sha256(snapshot_path), "sidecar": _sha256(sidecar_path),
            "proxy_gt": _sha256(gt_path),
        },
    )
