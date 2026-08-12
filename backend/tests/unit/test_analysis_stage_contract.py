from app.services.analysis_stage_contract import ai_is_authorized, close_for_l3
from app.services import rag_service
from app.services.llm import l3_judge
from app.services import rag_grounding
from app.services.rag_grounding import normalize_evidence_bundle, verify_citation_bound_decision


def test_retrieval_success_explicitly_authorizes_ai(monkeypatch):
    monkeypatch.delenv("ABLATION_NO_RAG", raising=False)
    monkeypatch.setattr(rag_service, "search_evidence", lambda *a, **k: [{
        "unit_id": "u1", "source_id": "official", "content": "requirement",
        "status": "verified", "authority": "official",
    }])
    item = rag_service.run_l2_rag_context([{"rule_id": "LEA-001"}])[0]
    assert item["disposition"] == "ai_required"
    assert item["ai_need"] == "required"
    assert item["disposition_history"] == [
        "retrieval_required", "evidence_verified", "ai_required"
    ]


def test_missing_evidence_closes_to_hold(monkeypatch):
    monkeypatch.delenv("ABLATION_NO_RAG", raising=False)
    monkeypatch.setattr(rag_service, "search_evidence", lambda *a, **k: [])
    item = rag_service.run_l2_rag_context([{"rule_id": "LEA-001"}])[0]
    assert (item["disposition"], item["ai_need"]) == ("hold", "prohibited")


def test_legacy_candidate_is_not_ai_authorized():
    closed = close_for_l3({"rule_id": "LEA-001", "needs_ai_review": True})
    assert closed["disposition"] == "hold"
    assert closed["disposition_reason"] == "legacy_or_invalid_stage_contract"
    assert not ai_is_authorized(closed)


def test_l3_legacy_bypass_does_not_call_provider(monkeypatch):
    monkeypatch.setattr(l3_judge, "_call_gemini_with_retry", lambda *a, **k: (_ for _ in ()).throw(AssertionError("AI called")))
    monkeypatch.setattr(l3_judge, "_call_gemini_batch_with_retry", lambda *a, **k: (_ for _ in ()).throw(AssertionError("AI called")))
    assert l3_judge.run_l3_contextualizer(
        {"files": []}, [{"rule_id": "LEA-001", "pattern_type": "regex", "needs_ai_review": True}]
    ) == []


def test_verifier_rejects_missing_route():
    result = verify_citation_bound_decision({}, {})
    assert result == {"verified": False, "reason": "route_missing", "cited_unit_ids": []}


def test_forged_contract_cannot_bypass_recomputed_route(monkeypatch):
    monkeypatch.setattr(l3_judge, "_call_gemini_with_retry", lambda *a, **k: (_ for _ in ()).throw(AssertionError("AI called")))
    forged = {
        "analysis_contract_version": "1.0", "disposition": "ai_required",
        "disposition_reason": "forged", "ai_need": "required",
        "rag_route": {"decision": "skip"}, "rule_id": "LEA-001",
        "pattern_type": "regex", "needs_ai_review": True,
    }
    assert l3_judge.run_l3_contextualizer({"files": []}, [forged], _preselected=True) == []


def test_citation_must_exist_in_live_official_index(monkeypatch):
    text = "official requirement"
    unit = normalize_evidence_bundle([{
        "unit_id": "u1", "source_id": "source", "text": text,
        "status": "verified", "authority": "official", "role": "requirement",
        "authority_tier": 1, "locator": {"page": 1}, "version": "1",
        "effective_date": "2026-01-01", "source_sha256": "a" * 64,
    }])[0]
    monkeypatch.setattr(rag_grounding, "_verified_rule_binding", lambda rid: {
        "source_id": "source", "source_sha256": "a" * 64, "unit_ids": frozenset({"u1"}),
    })
    monkeypatch.setattr(rag_service, "_load_verified_official_units", lambda rid: [])
    result = verify_citation_bound_decision(
        {"rule_id": "LEA-001", "rag_route": {"decision": "retrieve"}, "rag_evidence_bundle": [unit]},
        {"evidence_unit_ids": ["u1"], "supporting_spans": [text],
         "evidence_entails_verdict": True, "applicability": "applicable",
         "exceptions_checked": [], "counterevidence": []},
    )
    assert result["reason"] == "citation_not_in_live_official_index"
