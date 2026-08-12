"""Adaptive retrieval routing and fail-closed evidence verification.

The module deliberately accepts both the legacy guideline chunks and the
official evidence-unit schema.  Legacy chunks remain useful context, but they
cannot by themselves authorize removal of an L1 candidate.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
from typing import Any, Dict, Iterable, List

import yaml


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
_DETERMINISTIC_LITERAL_RULES = frozenset({"GCM-002", "CCM-003", "CMAC-004"})
_DETERMINISTIC_SEAL_KEY = secrets.token_bytes(32)


def _literal_candidate_seal_payload(candidate: Dict[str, Any], span_hash: str) -> bytes | None:
    """Return the closed, type-checked identity bound by the process seal."""
    if (
        not isinstance(candidate.get("rule_id"), str)
        or not isinstance(candidate.get("file"), str)
        or not isinstance(candidate.get("line"), int)
        or isinstance(candidate.get("line"), bool)
        or not isinstance(candidate.get("end_line"), int)
        or isinstance(candidate.get("end_line"), bool)
        or not isinstance(candidate.get("snippet"), str)
        or candidate.get("scope") != "line-range"
        or not re.fullmatch(r"[0-9a-f]{64}", span_hash)
    ):
        return None
    return json.dumps({
        "rule_id": candidate["rule_id"].upper(),
        "file": candidate["file"],
        "line": candidate["line"],
        "end_line": candidate["end_line"],
        "scope": candidate["scope"],
        "snippet": candidate["snippet"],
        "matched_span_sha256": span_hash,
    }, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def seal_deterministic_literal_evidence(candidate: Dict[str, Any], span: str) -> Dict[str, str]:
    """Seal scanner output to this exact in-process candidate occurrence."""
    span_hash = hashlib.sha256(span.encode()).hexdigest()
    payload = _literal_candidate_seal_payload(candidate, span_hash)
    if payload is None:
        return {}
    return {
        "scanner_id": "kcmvp_explicit_tag_literal_v1",
        "matched_span": span,
        "matched_span_sha256": span_hash,
        "candidate_seal": hmac.new(_DETERMINISTIC_SEAL_KEY, payload, hashlib.sha256).hexdigest(),
    }


def grounding_enabled() -> bool:
    return os.environ.get("KCMVP_GROUNDED_RAG", "1") != "0"


def _verified_rule_binding(rule_id: str) -> Dict[str, Any] | None:
    """Load and content-address the audited binding plus its live YAML rule.

    Applicability is deliberately obtained from repository-owned artifacts.
    Candidate fields are observations, not a trust root.
    """
    if not rule_id:
        return None
    from app.services.mapping_service import get_evidence_audit

    row = get_evidence_audit(rule_id)
    locator = row.get("source_locator") or {}
    unit_ids = row.get("evidence_unit_ids") or []
    applicability = row.get("applicability") or {}
    rule_file = row.get("rule_file")
    if (
        row.get("status") != "verified"
        or row.get("review_required", False)
        or row.get("evidence_role") != "normative_requirement"
        or not isinstance(locator, dict)
        or not isinstance(unit_ids, list)
        or not unit_ids
        or not locator.get("source_id")
        or not re.fullmatch(r"[0-9a-f]{64}", str(row.get("source_sha256") or ""))
        or not isinstance(applicability, dict)
        or not isinstance(rule_file, str)
    ):
        return None
    backend = Path(__file__).resolve().parents[2]
    path = (backend / rule_file.removeprefix("backend/")).resolve()
    rules_root = (backend / "rules").resolve()
    try:
        path.relative_to(rules_root)
        raw = path.read_bytes()
        payload = yaml.safe_load(raw) or {}
        rules = payload.get("rules", []) if isinstance(payload, dict) else payload
        live = next(
            item for item in rules
            if isinstance(item, dict) and str(item.get("id") or "").upper() == rule_id.upper()
        )
    except (OSError, ValueError, TypeError, StopIteration, yaml.YAMLError):
        return None

    def values(source: Dict[str, Any], key: str) -> frozenset[str]:
        value = source.get(key, [])
        if isinstance(value, str):
            value = [value]
        if not isinstance(value, list):
            return frozenset()
        return frozenset(str(item).upper() for item in value if str(item).strip())

    audited_algorithms = values(applicability, "algorithm")
    audited_modes = values(applicability, "mode")
    live_algorithms = values(live, "algorithm")
    live_modes = values(live, "mode")
    # An audited restriction may not disagree with the active YAML contract.
    # Absence in both is a valid generic rule; absence on only one side is not.
    if (
        (audited_algorithms or live_algorithms)
        and (not audited_algorithms or not live_algorithms or not live_algorithms.issubset(audited_algorithms))
    ) or (
        (audited_modes or live_modes)
        and (not audited_modes or not live_modes or not live_modes.issubset(audited_modes))
    ):
        return None
    provenance = {
        "rule_id": rule_id.upper(),
        "rule_file": str(path.relative_to(backend)),
        "rule_file_sha256": hashlib.sha256(raw).hexdigest(),
        "algorithm": sorted(audited_algorithms),
        "mode": sorted(audited_modes),
        "source_id": str(locator["source_id"]),
        "source_sha256": str(row["source_sha256"]),
        "unit_ids": sorted(str(value) for value in unit_ids),
    }
    return {
        "source_id": str(locator["source_id"]),
        "source_sha256": str(row["source_sha256"]),
        "unit_ids": frozenset(str(value) for value in unit_ids),
        "algorithms": audited_algorithms,
        "modes": audited_modes,
        "rule_provenance_sha256": hashlib.sha256(json.dumps(
            provenance, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode()).hexdigest(),
    }


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
    if _is_verified_literal_candidate(candidate):
        return {"decision": "deterministic_verified_rule", "reason": "verified_mapping_and_explicit_literal_scanner"}
    # A parser-confirmed positive structural contradiction is code-grounded;
    # retrieval is not needed to establish the observed program fact.
    if pattern_type == "ast" and ast_evidence and semantics not in {
        "required_absence", "unknown"
    }:
        return {"decision": "skip", "reason": "deterministic_structural_evidence"}
    return {"decision": "retrieve", "reason": "authority_or_applicability_required"}


def _is_verified_literal_candidate(candidate: Dict[str, Any]) -> bool:
    """Recognize only sealed scanner output for three audited numeric rules."""
    rule_id = str(candidate.get("rule_id") or "").upper()
    marker = candidate.get("deterministic_literal_evidence")
    if (
        rule_id not in _DETERMINISTIC_LITERAL_RULES
        or _verified_rule_binding(rule_id) is None
        or candidate.get("pattern_type") != "regex"
        or candidate.get("confidence") != "확정"
        or candidate.get("needs_ai_review") is not False
        or not isinstance(marker, dict)
        or marker.get("scanner_id") != "kcmvp_explicit_tag_literal_v1"
    ):
        return False
    span = marker.get("matched_span")
    if not isinstance(span, str) or not span or hashlib.sha256(span.encode()).hexdigest() != marker.get("matched_span_sha256"):
        return False
    payload = _literal_candidate_seal_payload(candidate, marker.get("matched_span_sha256"))
    seal = marker.get("candidate_seal")
    if (
        payload is None
        or not isinstance(seal, str)
        or not hmac.compare_digest(
            seal,
            hmac.new(_DETERMINISTIC_SEAL_KEY, payload, hashlib.sha256).hexdigest(),
        )
    ):
        return False
    # Re-run the same narrow scanner. Caller-supplied metadata alone can never
    # opt a general semantic/regex candidate out of LLM review.
    from app.services.rule_engine_service import (
        _iter_kcmvp_cmac_tag_length_matches,
        _iter_kcmvp_tag_length_matches,
    )
    matches = list(
        _iter_kcmvp_cmac_tag_length_matches(span)
        if rule_id == "CMAC-004"
        else _iter_kcmvp_tag_length_matches(span, rule_id)
    )
    return len(matches) == 1 and matches[0].group(0) == span


def is_deterministic_verified_bypass(candidate: Dict[str, Any]) -> bool:
    """Revalidate scanner seal and live official provenance before L3 bypass."""
    if not _is_verified_literal_candidate(candidate):
        return False
    if (
        (candidate.get("rag_route") or {}).get("decision") != "deterministic_verified_rule"
        or candidate.get("decision_source") != "deterministic_l1_official_evidence"
        or candidate.get("rag_grounding_status") != "deterministic_official_evidence"
        or candidate.get("llm_calls_avoided") != 1
    ):
        return False
    provenance = candidate.get("official_evidence_provenance")
    bundle = candidate.get("rag_evidence_bundle")
    if not isinstance(provenance, list) or not provenance or not isinstance(bundle, list):
        return False
    rule_id = candidate["rule_id"].upper()
    binding = _verified_rule_binding(rule_id)
    if binding is None:
        return False
    from app.services.rag_service import _load_verified_official_units
    live = _load_verified_official_units(rule_id)
    live_by_id = {str(unit.get("unit_id")): unit for unit in live if isinstance(unit, dict)}
    if set(live_by_id) != set(binding["unit_ids"]):
        return False
    if {str(row.get("unit_id")) for row in provenance if isinstance(row, dict)} != set(binding["unit_ids"]):
        return False
    if {str(row.get("unit_id")) for row in bundle if isinstance(row, dict)} != set(binding["unit_ids"]):
        return False
    provenance_by_id = {str(row.get("unit_id")): row for row in provenance if isinstance(row, dict)}
    bundle_by_id = {str(row.get("unit_id")): row for row in bundle if isinstance(row, dict)}
    for unit_id, live_unit in live_by_id.items():
        prov = provenance_by_id.get(unit_id)
        normalized = bundle_by_id.get(unit_id)
        if not isinstance(prov, dict) or not isinstance(normalized, dict):
            return False
        text_hash = str(live_unit.get("text_sha256") or "")
        if (
            prov.get("source_id") != binding["source_id"]
            or prov.get("source_sha256") != binding["source_sha256"]
            or prov.get("span_sha256") != text_hash
            or prov.get("locator") != live_unit.get("locator")
            or normalized.get("span_sha256") != text_hash
            or normalized.get("source_sha256") != binding["source_sha256"]
        ):
            return False
    return True


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
            "source_sha256": chunk.get("source_sha256"),
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
    if not grounding_enabled():
        return {"verified": True, "reason": "retrieval_not_required", "cited_unit_ids": []}
    if route is None:
        return {"verified": False, "reason": "route_missing", "cited_unit_ids": []}
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
    rule_id = str(candidate.get("rule_id") or "").upper()
    binding = _verified_rule_binding(rule_id)
    if binding is None:
        return {"verified": False, "reason": "rule_evidence_binding_missing", "cited_unit_ids": cited_ids}
    expected_rule_seal = binding.get("rule_provenance_sha256")
    if expected_rule_seal and candidate.get("rule_provenance_sha256") != expected_rule_seal:
        return {"verified": False, "reason": "rule_provenance_mismatch", "cited_unit_ids": cited_ids}
    if any(item not in binding["unit_ids"] for item in cited_ids):
        return {"verified": False, "reason": "citation_not_bound_to_rule", "cited_unit_ids": cited_ids}
    if any(str(unit.get("source_id")) != binding["source_id"] for unit in cited):
        return {"verified": False, "reason": "citation_source_not_bound_to_rule", "cited_unit_ids": cited_ids}
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
        if not unit.get("version"):
            return {"verified": False, "reason": "version_metadata_missing", "cited_unit_ids": cited_ids}
        if not unit.get("effective_date"):
            # Some approved local artifacts have no published effective date.
            # They are usable only through an audited, content-addressed source
            # binding; ``local-artifact`` alone is never trusted.
            if (
                unit.get("version") != "local-artifact"
                or unit.get("source_sha256") != binding["source_sha256"]
            ):
                return {"verified": False, "reason": "undated_artifact_provenance_unverified", "cited_unit_ids": cited_ids}
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
        if algorithms and not algorithms.intersection(binding.get("algorithms") or set()):
            return {"verified": False, "reason": "source_applicability_mismatch", "cited_unit_ids": cited_ids}
        if modes and not modes.intersection(binding.get("modes") or set()):
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
    # Caller/search-cache material is never its own trust root. Compare every
    # otherwise-valid citation with the current sealed official index.
    from app.services.rag_service import _load_verified_official_units
    live_by_id = {
        str(unit.get("unit_id")): normalize_evidence_bundle([unit])[0]
        for unit in _load_verified_official_units(rule_id)
    }
    if any(unit_id not in live_by_id for unit_id in cited_ids):
        return {"verified": False, "reason": "citation_not_in_live_official_index", "cited_unit_ids": cited_ids}
    exact_fields = (
        "source_id", "source_sha256", "locator", "span", "span_sha256",
        "status", "version", "effective_date", "evidence_role",
        "authority", "authority_tier", "applicability",
    )
    for unit in cited:
        live = live_by_id[str(unit["unit_id"])]
        if any(unit.get(field) != live.get(field) for field in exact_fields):
            return {"verified": False, "reason": "citation_live_index_mismatch", "cited_unit_ids": cited_ids}
    return {"verified": True, "reason": "citation_bound_verified", "cited_unit_ids": cited_ids}
