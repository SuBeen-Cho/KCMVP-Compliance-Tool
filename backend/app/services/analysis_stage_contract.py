"""Closed production contract for deterministic, RAG, and LLM stages."""

from __future__ import annotations

from typing import Any, Dict


CONTRACT_VERSION = "1.0"
DISPOSITIONS = frozenset({
    "deterministic", "retrieval_required", "evidence_verified",
    "ai_required", "hold",
})
AI_NEEDS = frozenset({"required", "not_required", "prohibited"})


def stamp(
    candidate: Dict[str, Any], disposition: str, reason: str, ai_need: str,
    *, history: list[str] | None = None,
) -> None:
    """Attach the complete contract; partial/ad-hoc states are not valid."""
    if disposition not in DISPOSITIONS or ai_need not in AI_NEEDS or not reason:
        raise ValueError("invalid analysis stage contract")
    candidate["analysis_contract_version"] = CONTRACT_VERSION
    candidate["disposition"] = disposition
    candidate["disposition_reason"] = reason
    candidate["ai_need"] = ai_need
    candidate["disposition_history"] = list(history or [disposition])


def close_for_l3(candidate: Dict[str, Any]) -> Dict[str, Any]:
    """Return a valid contract, converting every legacy/invalid bypass to hold."""
    item = dict(candidate)
    valid = (
        item.get("analysis_contract_version") == CONTRACT_VERSION
        and item.get("disposition") in DISPOSITIONS
        and item.get("ai_need") in AI_NEEDS
        and isinstance(item.get("disposition_reason"), str)
        and bool(item.get("disposition_reason"))
    )
    if not valid:
        stamp(item, "hold", "legacy_or_invalid_stage_contract", "prohibited")
        return item
    if item["disposition"] == "ai_required" and item["ai_need"] != "required":
        stamp(item, "hold", "contradictory_ai_stage_contract", "prohibited")
    elif item["ai_need"] == "required" and item["disposition"] != "ai_required":
        stamp(item, "hold", "contradictory_ai_stage_contract", "prohibited")
    return item


def ai_is_authorized(candidate: Dict[str, Any]) -> bool:
    return (
        candidate.get("analysis_contract_version") == CONTRACT_VERSION
        and candidate.get("disposition") == "ai_required"
        and candidate.get("ai_need") == "required"
    )
