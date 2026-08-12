from copy import deepcopy

import pytest

from app.services.rag_grounding import (
    _verified_rule_binding,
    normalize_evidence_bundle,
    verify_citation_bound_decision,
)
from app.services.rag_service import _load_verified_official_units


@pytest.mark.parametrize("rule_id", ["CBC-001", "CTR-001", "CTR-002"])
def test_live_audited_applicability_accepts_lea_mode_rules(rule_id):
    binding = _verified_rule_binding(rule_id)
    assert binding is not None
    units = normalize_evidence_bundle(_load_verified_official_units(rule_id))
    assert units
    cited = [unit["unit_id"] for unit in units]
    candidate = {
        "rule_id": rule_id,
        "rag_route": {"decision": "retrieve"},
        "rag_evidence_bundle": units,
        "rule_provenance_sha256": binding["rule_provenance_sha256"],
    }
    decision = {
        "evidence_unit_ids": cited,
        "supporting_spans": [unit["span"] for unit in units],
        "evidence_entails_verdict": True,
        "applicability": True,
        "exceptions_checked": [],
        "counterevidence": [],
    }
    assert verify_citation_bound_decision(candidate, decision)["verified"] is True


def test_candidate_controlled_applicability_cannot_override_rule_contract():
    rule_id = "CBC-001"
    binding = _verified_rule_binding(rule_id)
    units = normalize_evidence_bundle(_load_verified_official_units(rule_id))
    candidate = {
        "rule_id": rule_id,
        "algorithm": "AES",
        "mode": "GCM",
        "applicability": {"algorithm": ["AES"], "mode": ["GCM"]},
        "rag_route": {"decision": "retrieve"},
        "rag_evidence_bundle": units,
        "rule_provenance_sha256": binding["rule_provenance_sha256"],
    }
    decision = {
        "evidence_unit_ids": [unit["unit_id"] for unit in units],
        "supporting_spans": [unit["span"] for unit in units],
        "evidence_entails_verdict": True,
        "applicability": True,
        "exceptions_checked": [],
        "counterevidence": [],
    }
    # Forged observation metadata is ignored; the live CBC/LEA rule contract wins.
    assert verify_citation_bound_decision(candidate, decision)["verified"] is True
    missing = deepcopy(candidate)
    missing.pop("rule_provenance_sha256")
    assert verify_citation_bound_decision(missing, decision)["reason"] == "rule_provenance_mismatch"
    forged = deepcopy(candidate)
    forged["rule_provenance_sha256"] = "0" * 64
    assert verify_citation_bound_decision(forged, decision)["reason"] == "rule_provenance_mismatch"
