import pytest

from app.services import rag_grounding
from app.services.rag_grounding import (
    normalize_evidence_bundle,
    render_evidence_bundle,
    route_rag,
    verify_citation_bound_decision,
)


@pytest.fixture(autouse=True)
def _audited_binding(monkeypatch):
    monkeypatch.setattr(rag_grounding, "_verified_rule_binding", lambda _rule_id: {
        "source_id": "guide", "source_sha256": "a" * 64,
        "unit_ids": frozenset({"guide:p10:s2:requirement:abc"}),
    })


def _official_unit(**overrides):
    unit = {
        "unit_id": "guide:p10:s2:requirement:abc",
        "source_id": "guide",
        "authority": "KISA",
        "authority_tier": 1,
        "locator": {"page": 10, "section": "2"},
        "role": "requirement",
        "text": "인증값의 길이는 112비트 이상이어야 한다.",
        "status": "active",
        "version": "2024.03",
        "effective_date": "2024-03-01",
    }
    unit.update(overrides)
    return normalize_evidence_bundle([unit])[0]


def _decision(**overrides):
    value = {
        "is_real_issue": False,
        "evidence_unit_ids": ["guide:p10:s2:requirement:abc"],
        "supporting_spans": ["인증값의 길이는 112비트 이상이어야 한다."],
        "applicability": "applicable",
        "exceptions_checked": [],
        "counterevidence": [],
        "evidence_entails_verdict": True,
    }
    value.update(overrides)
    return value


def test_router_skips_deterministic_structural_evidence():
    route = route_rag({
        "pattern_type": "ast", "detection_semantics": "structural_violation",
        "ast_evidence": "AST confirmed a wrong loop bound",
    })
    assert route == {"decision": "skip", "reason": "deterministic_structural_evidence"}
    assert route_rag({"pattern_type": "ast", "ast_evidence": "parser fact"})["decision"] == "skip"


def test_router_retrieves_for_applicability_or_absence():
    assert route_rag({"pattern_type": "missing"})["decision"] == "retrieve"
    assert route_rag({
        "pattern_type": "ast", "detection_semantics": "required_absence",
        "ast_evidence": "no call found",
    })["decision"] == "retrieve"


def test_verifier_accepts_bound_official_span():
    candidate = {"rag_route": {"decision": "retrieve"}, "rag_evidence_bundle": [_official_unit()]}
    assert verify_citation_bound_decision(candidate, _decision())["verified"] is True


def test_renderer_never_truncates_the_first_atomic_evidence_unit():
    unit = _official_unit(text="A" * 1000)
    rendered = render_evidence_bundle([unit], max_chars=80)
    assert "A" * 1000 in rendered
    assert unit["unit_id"] in rendered


def test_verifier_blocks_missing_or_wrong_citation():
    candidate = {"rag_route": {"decision": "retrieve"}, "rag_evidence_bundle": [_official_unit()]}
    assert verify_citation_bound_decision(candidate, _decision(evidence_unit_ids=[]))["reason"] == "citation_missing"
    result = verify_citation_bound_decision(candidate, _decision(evidence_unit_ids=["invented"] ))
    assert result == {"verified": False, "reason": "citation_unknown", "cited_unit_ids": ["invented"]}


def test_verifier_blocks_official_distractor_not_bound_to_rule(monkeypatch):
    distractor = _official_unit(
        unit_id="other:p1:b1", source_id="other",
        applicability={},
    )
    monkeypatch.setattr(rag_grounding, "_verified_rule_binding", lambda _rule_id: {
        "source_id": "guide", "source_sha256": "a" * 64,
        "unit_ids": frozenset({"guide:p10:s2:requirement:abc"}),
    })
    candidate = {
        "rule_id": "GCM-002", "rag_route": {"decision": "retrieve"},
        "rag_evidence_bundle": [distractor],
    }
    decision = _decision(
        evidence_unit_ids=["other:p1:b1"],
        supporting_spans=["인증값의 길이는 112비트 이상이어야 한다."],
    )
    assert verify_citation_bound_decision(candidate, decision)["reason"] == "citation_not_bound_to_rule"


def test_verifier_blocks_rule_without_verified_binding(monkeypatch):
    monkeypatch.setattr(rag_grounding, "_verified_rule_binding", lambda _rule_id: None)
    candidate = {
        "rule_id": "UNMAPPED-001", "rag_route": {"decision": "retrieve"},
        "rag_evidence_bundle": [_official_unit()],
    }
    assert verify_citation_bound_decision(candidate, _decision())["reason"] == "rule_evidence_binding_missing"


def test_verifier_blocks_author_guidance_and_conflicting_evidence():
    author = _official_unit(authority="author", authority_tier=3, evidence_role="author_guidance")
    candidate = {"rag_route": {"decision": "retrieve"}, "rag_evidence_bundle": [author]}
    assert verify_citation_bound_decision(candidate, _decision())["reason"] == "no_normative_official_citation"

    conflict = _official_unit(unit_id="conflict", status="conflict")
    candidate["rag_evidence_bundle"] = [_official_unit(), conflict]
    assert verify_citation_bound_decision(candidate, _decision())["reason"] == "evidence_conflict"


def test_verifier_blocks_span_mismatch_and_unconfirmed_entailment():
    candidate = {"rag_route": {"decision": "retrieve"}, "rag_evidence_bundle": [_official_unit()]}
    assert verify_citation_bound_decision(
        candidate, _decision(supporting_spans=["원문에 없는 문장"])
    )["reason"] == "supporting_span_mismatch"
    assert verify_citation_bound_decision(
        candidate, _decision(evidence_entails_verdict=False)
    )["reason"] == "entailment_unconfirmed"


def test_verifier_blocks_source_applicability_mismatch():
    unit = _official_unit(applicability={"algorithm": ["LEA"]})
    candidate = {
        "rule_id": "AES-001", "rag_route": {"decision": "retrieve"},
        "rag_evidence_bundle": [unit],
    }
    assert verify_citation_bound_decision(candidate, _decision())["reason"] == "source_applicability_mismatch"


def test_safe_no_rag_structural_route_does_not_require_citation():
    candidate = {
        "pattern_type": "ast", "detection_semantics": "structural_violation",
        "ast_evidence": "parser-confirmed contradiction",
        "rag_route": {"decision": "skip", "reason": "deterministic_structural_evidence"},
    }
    assert verify_citation_bound_decision(candidate, {"is_real_issue": False}) == {
        "verified": True, "reason": "retrieval_not_required", "cited_unit_ids": [],
    }


def test_forged_skip_route_is_blocked():
    candidate = {
        "pattern_type": "regex", "detection_semantics": "prohibited_presence",
        "rag_route": {"decision": "skip", "reason": "forged"},
    }
    assert verify_citation_bound_decision(candidate, {"is_real_issue": False})["reason"] == "rag_route_mismatch"


def test_unverified_or_implicitly_official_chunk_is_blocked():
    raw = {
        "unit_id": "guide:p10:s2:requirement:abc", "source_id": "guide",
        "locator": {"page": 10}, "role": "requirement",
        "text": "인증값의 길이는 112비트 이상이어야 한다.",
        "version": "2024.03", "effective_date": "2024-03-01",
    }
    candidate = {"rag_route": {"decision": "retrieve"}, "rag_evidence_bundle": [raw]}
    assert verify_citation_bound_decision(candidate, _decision())["reason"] == "evidence_unverified"


def test_locator_hash_and_version_are_enforced():
    candidate = {"rag_route": {"decision": "retrieve"}, "rag_evidence_bundle": [_official_unit(locator={})]}
    assert verify_citation_bound_decision(candidate, _decision())["reason"] == "source_locator_missing"
    candidate["rag_evidence_bundle"] = [_official_unit(span_sha256="0" * 64)]
    assert verify_citation_bound_decision(candidate, _decision())["reason"] == "evidence_hash_mismatch"
    candidate["rag_evidence_bundle"] = [_official_unit(version=None)]
    assert verify_citation_bound_decision(candidate, _decision())["reason"] == "version_metadata_missing"


def test_undated_local_artifact_requires_content_addressed_binding(monkeypatch):
    candidate = {
        "rule_id": "LEA-048", "rag_route": {"decision": "retrieve"},
        "rag_evidence_bundle": [_official_unit(
            version="local-artifact", effective_date=None,
            source_sha256="a" * 64,
        )],
    }
    assert verify_citation_bound_decision(candidate, _decision())["verified"] is True
    candidate["rag_evidence_bundle"] = [_official_unit(
        version="local-artifact", effective_date=None,
        source_sha256="b" * 64,
    )]
    assert verify_citation_bound_decision(candidate, _decision())["reason"] == "undated_artifact_provenance_unverified"


def test_counterevidence_forces_abstention():
    candidate = {"rag_route": {"decision": "retrieve"}, "rag_evidence_bundle": [_official_unit()]}
    result = verify_citation_bound_decision(candidate, _decision(counterevidence=["exception applies"]))
    assert result["reason"] == "counterevidence_present"


def test_l3_removal_is_blocked_when_routed_evidence_is_absent(monkeypatch):
    from app.services.llm import l3_judge

    monkeypatch.setattr(l3_judge, "_fp_removal_verified", lambda *args, **kwargs: True)
    candidate = {
        "rule_id": "TEST-001", "file": "impl.c", "line": 1,
        "pattern_type": "regex", "detection_semantics": "prohibited_presence",
        "rag_route": {"decision": "retrieve", "reason": "authority_or_applicability_required"},
        "rag_evidence_bundle": [],
    }
    results = []
    rejected = set()
    l3_judge._apply_l3_decision(
        v=candidate,
        obj={"is_real_issue": False, "confidence": 10},
        code_block="int x;", file_path="impl.c", results=results,
        rejected_tracker=rejected,
    )
    assert rejected == set()
    assert results[0]["l3_removal_blocked_reason"] == "grounding_evidence_absent"
