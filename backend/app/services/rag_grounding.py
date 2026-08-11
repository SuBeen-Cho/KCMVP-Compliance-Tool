"""Adaptive retrieval routing and fail-closed evidence verification.

The module deliberately accepts both the legacy guideline chunks and the
official evidence-unit schema.  Legacy chunks remain useful context, but they
cannot by themselves authorize removal of an L1 candidate.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Any, Dict, Iterable, List


_NORMATIVE_ROLES = frozenset({
    "requirement", "submission_requirement", "normative", "definition", "exception",
    "test_procedure",
})
_NORMATIVE_TIERS = frozenset({
    "1", "tier1", "primary", "official", "normative_guidance", "standard",
    "normative_test_interface",
})
_CONFLICT_STATUSES = frozenset({"conflict", "conflicting", "superseded", "withdrawn"})
_TRUSTED_STATUSES = frozenset({"active", "current", "verified"})


def grounding_enabled() -> bool:
    return os.environ.get("KCMVP_GROUNDED_RAG", "1") != "0"


def route_rag(candidate: Dict[str, Any]) -> Dict[str, str]:
    """Choose retrieval only when authority/applicability can affect judgment."""
    if not grounding_enabled():
        return {"decision": "legacy", "reason": "feature_disabled"}
    semantics = str(candidate.get("detection_semantics") or "").lower()
    pattern_type = str(candidate.get("pattern_type") or "").lower()
    if not semantics:
        semantics = (
            "prohibited_presence" if pattern_type == "regex" else
            "structural_violation" if pattern_type == "ast" else
            "required_absence"
        )
    ast_evidence = str(candidate.get("ast_evidence") or "").strip()
    # A parser-confirmed positive structural contradiction is code-grounded;
    # retrieval is not needed to establish the observed program fact.
    if pattern_type == "ast" and ast_evidence and semantics not in {
        "required_absence", "unknown"
    }:
        return {"decision": "skip", "reason": "deterministic_structural_evidence"}
    return {"decision": "retrieve", "reason": "authority_or_applicability_required"}


def _unit_id(chunk: Dict[str, Any]) -> str:
    existing = chunk.get("unit_id") or chunk.get("evidence_unit_id") or chunk.get("id")
    if existing:
        return str(existing)
    canonical = json.dumps({
        "source": chunk.get("source_id") or chunk.get("source") or "",
        "page": chunk.get("page"), "section": chunk.get("section") or chunk.get("title"),
        "span": chunk.get("span") or chunk.get("content") or "",
    }, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return "legacy:" + hashlib.sha256(canonical.encode()).hexdigest()[:20]


def normalize_evidence_bundle(chunks: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Preserve citation coordinates while normalising evolving index schemas."""
    units: List[Dict[str, Any]] = []
    for chunk in chunks:
        span = str(chunk.get("text") or chunk.get("span") or chunk.get("content") or "").strip()
        source_id = str(chunk.get("source_id") or chunk.get("source") or "").strip()
        role = str(chunk.get("evidence_role") or chunk.get("role") or "author_guidance").lower()
        locator = chunk.get("locator") if isinstance(chunk.get("locator"), dict) else {}
        units.append({
            "unit_id": _unit_id(chunk),
            # Transitional alias for older experiment packets.
            "evidence_unit_id": _unit_id(chunk),
            "source_id": source_id,
            "locator": dict(locator),
            "page": locator.get("page") or chunk.get("page"),
            "section": locator.get("section") or chunk.get("section") or chunk.get("title") or "",
            "span": span,
            "span_sha256": str(chunk.get("text_sha256") or chunk.get("span_sha256") or hashlib.sha256(span.encode()).hexdigest()),
            "evidence_role": role,
            # Missing trust metadata is unverified, never implicitly active or
            # official. The sealed index emits both fields explicitly.
            "status": str(chunk.get("status") or "unverified").lower(),
            "authority": str(chunk.get("authority") or "unknown"),
            "authority_tier": chunk.get("authority_tier"),
            "collection": chunk.get("collection"),
            "version": chunk.get("version"),
            "effective_date": chunk.get("effective_date"),
            "applicability": chunk.get("applicability"),
        })
    return units


def render_evidence_bundle(units: Iterable[Dict[str, Any]], max_chars: int = 4000) -> str:
    parts: List[str] = []
    used = 0
    for unit in units:
        header = (
            f"[EVIDENCE {unit['unit_id']}] source={unit['source_id']} "
            f"page={unit.get('page') or '-'} section={unit.get('section') or '-'} "
            f"role={unit.get('evidence_role')} span_sha256={unit.get('span_sha256')}"
        )
        piece = header + "\n" + str(unit.get("span") or "")
        if parts and used + len(piece) > max_chars:
            break
        parts.append(piece)
        used += len(piece)
    return "\n\n".join(parts)


def verify_citation_bound_decision(
    candidate: Dict[str, Any], decision: Dict[str, Any]
) -> Dict[str, Any]:
    """Verify L3 citations deterministically; uncertain evidence never removes."""
    route = candidate.get("rag_route")
    # Candidates produced before the router existed preserve legacy behaviour;
    # newly routed candidates always carry this field and fail closed.
    if not grounding_enabled() or route is None:
        return {"verified": True, "reason": "retrieval_not_required", "cited_unit_ids": []}
    if not isinstance(route, dict):
        return {"verified": False, "reason": "invalid_rag_route", "cited_unit_ids": []}
    route_decision = route.get("decision")
    if route_decision == "skip":
        # Never trust a caller-supplied skip label without recomputing it.
        expected = route_rag({k: v for k, v in candidate.items() if k != "rag_route"})
        if expected.get("decision") != "skip":
            return {"verified": False, "reason": "rag_route_mismatch", "cited_unit_ids": []}
        return {"verified": True, "reason": "retrieval_not_required", "cited_unit_ids": []}
    if route_decision != "retrieve":
        return {"verified": False, "reason": "invalid_rag_route", "cited_unit_ids": []}
    raw_units = candidate.get("rag_evidence_bundle") or []
    if not isinstance(raw_units, list) or any(not isinstance(u, dict) for u in raw_units):
        return {"verified": False, "reason": "invalid_evidence_bundle", "cited_unit_ids": []}
    units = normalize_evidence_bundle(raw_units)
    if not units:
        return {"verified": False, "reason": "evidence_absent", "cited_unit_ids": []}
    by_id = {str(u.get("unit_id") or u.get("evidence_unit_id")): u for u in units}
    citations = decision.get("evidence_unit_ids") or decision.get("citations") or []
    cited_ids: List[str] = []
    for citation in citations:
        if isinstance(citation, str):
            cited_ids.append(citation)
        elif isinstance(citation, dict):
            cited_ids.append(str(citation.get("evidence_unit_id") or citation.get("unit_id") or ""))
    cited_ids = [item for item in cited_ids if item]
    if not cited_ids:
        return {"verified": False, "reason": "citation_missing", "cited_unit_ids": []}
    if any(item not in by_id for item in cited_ids):
        return {"verified": False, "reason": "citation_unknown", "cited_unit_ids": cited_ids}
    cited = [by_id[item] for item in cited_ids]
    if any(str(u.get("status") or "").lower() in _CONFLICT_STATUSES for u in units):
        return {"verified": False, "reason": "evidence_conflict", "cited_unit_ids": cited_ids}
    if any(str(u.get("status") or "").lower() not in _TRUSTED_STATUSES for u in cited):
        return {"verified": False, "reason": "evidence_unverified", "cited_unit_ids": cited_ids}
    if not any(
        str(u.get("evidence_role") or "").lower() in _NORMATIVE_ROLES
        and (
            str(u.get("authority") or "").lower() in {"official", "normative"}
            or str(u.get("authority_tier") or "").lower() in _NORMATIVE_TIERS
        )
        for u in cited
    ):
        return {"verified": False, "reason": "no_normative_official_citation", "cited_unit_ids": cited_ids}
    for unit in cited:
        locator = unit.get("locator")
        if (
            not unit.get("source_id")
            or not isinstance(locator, dict)
            or not any(locator.get(key) not in (None, "", []) for key in ("page", "pages", "section", "block", "blocks"))
        ):
            return {"verified": False, "reason": "source_locator_missing", "cited_unit_ids": cited_ids}
        span = str(unit.get("span") or "")
        expected_hash = hashlib.sha256(span.encode()).hexdigest()
        if not span or not unit.get("span_sha256") or unit.get("span_sha256") != expected_hash:
            return {"verified": False, "reason": "evidence_hash_mismatch", "cited_unit_ids": cited_ids}
        if not unit.get("version") or not unit.get("effective_date"):
            return {"verified": False, "reason": "version_metadata_missing", "cited_unit_ids": cited_ids}
    rule_id = str(candidate.get("rule_id") or "").upper()
    for unit in cited:
        applicability = unit.get("applicability") or {}
        if not isinstance(applicability, dict):
            return {"verified": False, "reason": "invalid_applicability_metadata", "cited_unit_ids": cited_ids}
        def values(key: str) -> set[str]:
            raw = applicability.get(key, [])
            if isinstance(raw, str):
                raw = [raw]
            if not isinstance(raw, list):
                return set()
            return {str(v).upper() for v in raw if str(v).strip()}
        algorithms = values("algorithm")
        modes = values("mode")
        if algorithms and not any(token in rule_id for token in algorithms):
            return {"verified": False, "reason": "source_applicability_mismatch", "cited_unit_ids": cited_ids}
        if modes and not any(token in rule_id for token in modes):
            return {"verified": False, "reason": "source_applicability_mismatch", "cited_unit_ids": cited_ids}
    quoted = decision.get("supporting_spans") or []
    if isinstance(quoted, str):
        quoted = [quoted]
    if not quoted:
        return {"verified": False, "reason": "supporting_span_missing", "cited_unit_ids": cited_ids}
    normalized_spans = [re.sub(r"\s+", " ", str(u.get("span") or "")).strip() for u in cited]
    if any(
        re.sub(r"\s+", " ", str(span)).strip() not in source_span
        for span in quoted for source_span in normalized_spans
    ):
        # Every quoted support span must occur in at least one cited unit.
        for span in quoted:
            needle = re.sub(r"\s+", " ", str(span)).strip()
            if not needle or not any(needle in source for source in normalized_spans):
                return {"verified": False, "reason": "supporting_span_mismatch", "cited_unit_ids": cited_ids}
    if decision.get("evidence_entails_verdict") is not True:
        return {"verified": False, "reason": "entailment_unconfirmed", "cited_unit_ids": cited_ids}
    if decision.get("applicability") not in {True, "applicable"}:
        return {"verified": False, "reason": "applicability_unconfirmed", "cited_unit_ids": cited_ids}
    exceptions = decision.get("exceptions_checked")
    if not isinstance(exceptions, list):
        return {"verified": False, "reason": "exceptions_unchecked", "cited_unit_ids": cited_ids}
    counterevidence = decision.get("counterevidence")
    if not isinstance(counterevidence, list):
        return {"verified": False, "reason": "counterevidence_unchecked", "cited_unit_ids": cited_ids}
    if counterevidence:
        return {"verified": False, "reason": "counterevidence_present", "cited_unit_ids": cited_ids}
    return {"verified": True, "reason": "citation_bound_verified", "cited_unit_ids": cited_ids}
