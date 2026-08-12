"""Fail-closed COM-004 structural shadow observations.

This is deliberately not a semantic verifier.  It records a narrowly shaped
same-function assignment only after authentic preprocessing binding; final
state and production authorization always remain unknown/false.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

from app.services.clang_straightline_reaching_def import (
    VerifiedPreprocessingBinding, verified_binding_matches_source,
)

EXTRACTOR_ID = "com004-weak-rng-direct-store-shadow"
EXTRACTOR_VERSION = "1.0.0"
_WEAK = re.compile(r"\b(?:rand|random|drand48|clock|time)\s*\(")
_DIRECT = re.compile(
    r"\b(?P<sink>[A-Za-z_]\w*)\s*\[[^;\]]+\]\s*=\s*"
    r"(?:\([^;]+\)\s*)?(?P<source>rand|random|drand48|clock|time)\s*\([^;]*\)\s*;"
)
_CONTROL = re.compile(r"\b(?:if|switch|while|goto)\b|\?|\b(?:memcpy|memmove)\s*\(")


def observe_direct_store(source: str, *, preprocessing_binding: VerifiedPreprocessingBinding | None,
                         audited_sink_names: frozenset[str]) -> dict[str, Any]:
    base = {"extractor_id": EXTRACTOR_ID, "extractor_version": EXTRACTOR_VERSION,
            "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
            "state": "unknown", "production_authorized": False,
            "semantic_authorized": False}
    if not verified_binding_matches_source(preprocessing_binding, source):
        return {**base, "reason": "authenticated_preprocessing_unavailable"}
    if not audited_sink_names:
        return {**base, "reason": "audited_sensitive_sink_registry_unavailable"}
    if "#" in source or _CONTROL.search(source):
        return {**base, "reason": "control_alias_or_macro_dataflow_unproved"}
    weak = list(_WEAK.finditer(source))
    direct = list(_DIRECT.finditer(source))
    if not weak:
        return {**base, "reason": "weak_rng_call_absent"}
    if len(direct) != 1:
        return {**base, "reason": "unique_direct_store_unproved"}
    match = direct[0]
    if match.group("sink") not in audited_sink_names:
        return {**base, "reason": "sensitive_sink_identity_unproved"}
    return {**base, "reason": "direct_store_shape_observed_semantics_unproved",
            "structural_observation": True, "weak_source": match.group("source"),
            "sink_registry_match": True,
            "limitations": ["reachability_unproved", "alias_freedom_unproved",
                            "test_or_kat_context_unproved", "interprocedural_flow_unproved"]}
