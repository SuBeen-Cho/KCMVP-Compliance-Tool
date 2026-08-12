"""Fail-closed contract for independently extracted program facts.

The evidence registry establishes what a rule means.  This module only seals
what a deterministic extractor observed in a particular source snapshot.  A
model assertion is deliberately not accepted as a program fact.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

SCHEMA_VERSION = "1.0"
FACT_STATES = {"observed", "contradicted", "unknown"}
POLARITIES = {"required", "required_all", "allowed_set", "prohibited"}
_REQUIRED_PROVENANCE = {
    "extractor_id", "extractor_version", "extractor_sha256",
    "source_sha256", "candidate_id", "rule_id", "claim_id",
}
_ENVELOPE_KEYS = {
    "schema_version", "provenance", "state", "observations", "missing_context",
    "content_sha256", "seal",
}


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


def _valid_observations(value: Any) -> bool:
    return isinstance(value, list) and bool(value) and all(
        isinstance(row, dict)
        and set(row).issuperset({"kind", "locator", "value"})
        and isinstance(row.get("kind"), str) and bool(row["kind"])
        and isinstance(row.get("locator"), dict) and bool(row["locator"])
        and isinstance(row.get("value"), (str, int, bool, list, dict))
        for row in value
    )


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def content_sha256(payload: dict[str, Any]) -> str:
    """Stable content digest; this detects drift but is not authentication."""
    return hashlib.sha256(_canonical(payload)).hexdigest()


def build_program_fact(*, provenance: dict[str, str], state: str,
                       observations: list[dict[str, Any]],
                       missing_context: list[str] | None = None) -> dict[str, Any]:
    """Build an unsigned fact envelope, coercing incomplete input to unknown."""
    valid_provenance = (
        isinstance(provenance, dict)
        and set(provenance) == _REQUIRED_PROVENANCE
        and all(isinstance(provenance.get(k), str) and provenance[k] for k in _REQUIRED_PROVENANCE)
        and _is_sha256(provenance.get("extractor_sha256"))
        and _is_sha256(provenance.get("source_sha256"))
    )
    valid_observations = _valid_observations(observations)
    valid_missing = (
        missing_context is None
        or (isinstance(missing_context, list)
            and all(isinstance(item, str) and item for item in missing_context))
    )
    missing = list(missing_context) if valid_missing and missing_context else []
    effective_state = state if state in FACT_STATES else "unknown"
    if not valid_provenance or not valid_observations or not valid_missing or missing:
        effective_state = "unknown"
    body = {
        "schema_version": SCHEMA_VERSION,
        "provenance": dict(provenance),
        "state": effective_state,
        "observations": observations if valid_observations else [],
        "missing_context": missing,
    }
    return {**body, "content_sha256": content_sha256(body)}


def seal_program_fact(envelope: dict[str, Any], secret: bytes) -> dict[str, Any]:
    """Authenticate an envelope for transport; the secret must stay runtime-only."""
    if not isinstance(secret, bytes) or len(secret) < 32:
        raise ValueError("program fact seal requires at least 32 secret bytes")
    unsigned = {k: v for k, v in envelope.items() if k != "seal"}
    tag = hmac.new(secret, _canonical(unsigned), hashlib.sha256).hexdigest()
    return {**unsigned, "seal": {"algorithm": "HMAC-SHA256", "tag": tag}}


def verify_program_fact(envelope: dict[str, Any], secret: bytes,
                        expected: dict[str, str]) -> dict[str, Any]:
    """Verify schema, provenance binding, digest, and MAC; otherwise abstain."""
    if not isinstance(envelope, dict) or set(envelope) != _ENVELOPE_KEYS:
        return {"verified": False, "state": "unknown", "reason": "fact_envelope_schema_invalid"}
    if envelope.get("schema_version") != SCHEMA_VERSION:
        return {"verified": False, "state": "unknown", "reason": "fact_schema_mismatch"}
    if (not isinstance(expected, dict) or set(expected) != _REQUIRED_PROVENANCE
            or not all(isinstance(expected.get(k), str) and expected[k]
                       for k in _REQUIRED_PROVENANCE)
            or not _is_sha256(expected.get("extractor_sha256"))
            or not _is_sha256(expected.get("source_sha256"))):
        return {"verified": False, "state": "unknown", "reason": "fact_expected_provenance_invalid"}
    provenance = envelope.get("provenance")
    if (not isinstance(provenance, dict) or set(provenance) != _REQUIRED_PROVENANCE
            or provenance != expected):
        return {"verified": False, "state": "unknown", "reason": "fact_provenance_mismatch"}
    body = {k: v for k, v in envelope.items() if k not in {"content_sha256", "seal"}}
    if envelope.get("content_sha256") != content_sha256(body):
        return {"verified": False, "state": "unknown", "reason": "fact_content_hash_mismatch"}
    seal = envelope.get("seal")
    unsigned = {k: v for k, v in envelope.items() if k != "seal"}
    if (not isinstance(secret, bytes) or len(secret) < 32 or not isinstance(seal, dict)
            or seal.get("algorithm") != "HMAC-SHA256" or not isinstance(seal.get("tag"), str)):
        return {"verified": False, "state": "unknown", "reason": "fact_seal_missing"}
    expected_tag = hmac.new(secret, _canonical(unsigned), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(seal["tag"], expected_tag):
        return {"verified": False, "state": "unknown", "reason": "fact_seal_mismatch"}
    state = envelope.get("state")
    missing = envelope.get("missing_context")
    observations = envelope.get("observations")
    if (not isinstance(missing, list) or not all(isinstance(item, str) and item for item in missing)
            or (observations and not _valid_observations(observations))
            or (state != "unknown" and not observations)
            or state not in FACT_STATES or (state != "unknown" and missing)):
        return {"verified": False, "state": "unknown", "reason": "fact_state_invalid"}
    return {"verified": True, "state": state, "reason": "fact_verified"}


def verdict_from_fact(polarity: str, verified_fact: dict[str, Any]) -> str:
    """Map only authenticated facts; every ambiguity remains abstain."""
    if polarity not in POLARITIES or not verified_fact.get("verified"):
        return "abstain"
    state = verified_fact.get("state")
    if state == "unknown":
        return "abstain"
    if polarity == "prohibited":
        return "violation" if state == "observed" else "non_violation"
    return "non_violation" if state == "observed" else "violation"
