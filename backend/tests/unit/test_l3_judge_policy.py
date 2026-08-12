"""L3 risk-tier decision policy tests."""

from app.services.llm import l3_judge


def _authorize(candidate):
    candidate.update({
        "analysis_contract_version": "1.0", "disposition": "ai_required",
        "disposition_reason": "retrieved_evidence_requires_contextual_judgment",
        "ai_need": "required",
        "rag_route": {"decision": "retrieve", "reason": "authority_or_applicability_required"},
    })
    return candidate


def test_no_dual_verify_ablation_skips_second_pass(monkeypatch):
    called = False

    def fail_if_called(*_args, **_kwargs):
        nonlocal called
        called = True
        return False

    monkeypatch.setenv("ABLATION_NO_DUAL_VERIFY", "1")
    monkeypatch.setattr(l3_judge, "_verify_fp_removal", fail_if_called)

    assert l3_judge._fp_removal_verified({}, {}, "code", "src/test.c") is True
    assert called is False


def test_dual_verify_default_requires_second_pass(monkeypatch):
    calls = []

    def fake_verify(v, obj, code_block, file_path):
        calls.append((v, obj, code_block, file_path))
        return False

    monkeypatch.delenv("ABLATION_NO_DUAL_VERIFY", raising=False)
    monkeypatch.setattr(l3_judge, "_verify_fp_removal", fake_verify)

    assert l3_judge._fp_removal_verified({"rule_id": "LEA-030"}, {}, "code", "src/lea.c") is False
    assert calls == [({"rule_id": "LEA-030"}, {}, "code", "src/lea.c")]


def test_never_remove_rule_is_kept_even_when_l3_says_false(monkeypatch):
    monkeypatch.setenv("ABLATION_NO_DUAL_VERIFY", "1")
    results = []
    rejected = set()
    violation = {
        "rule_id": "CBC-001",
        "pattern_type": "ast",
        "file": "src/cipher.c",
        "line": 10,
    }
    judgment = {
        "is_real_issue": False,
        "confidence": 95,
        "description": "오탐으로 보임",
        "suggestion": "",
    }

    l3_judge._apply_l3_decision(
        v=violation,
        obj=judgment,
        code_block="code",
        file_path="src/cipher.c",
        results=results,
        rejected_tracker=rejected,
    )

    assert len(results) == 1
    assert rejected == set()
    assert results[0]["l3_risk_tier"] == "D"
    assert results[0]["l3_removal_allowed"] is False
    assert results[0]["l3_removal_blocked_reason"] == "never_remove"


def test_grounded_missing_relax_removes_low_risk_auxiliary(monkeypatch):
    monkeypatch.setenv("L3_GROUNDED_RELAX", "1")
    monkeypatch.setenv("ABLATION_NO_DUAL_VERIFY", "1")
    results = []
    rejected = set()
    monkeypatch.setattr(l3_judge, "verify_citation_bound_decision", lambda *_a, **_k: {
        "verified": True, "reason": "citation_bound_verified", "cited_unit_ids": ["u1"],
    })
    violation = {
        "rule_id": "LEA-048",
        "pattern_type": "missing",
        "file": "src/test_lea.c",
        "line": None,
    }
    judgment = {
        "is_real_issue": False,
        "confidence": 20,
        "description": "제출 산출물 증거가 별도 존재함",
        "suggestion": "",
        "evidence_type": "delegated_to_other_file",
        "delegated_target": "rsp/lea_cbc_mmt.rsp",
    }

    l3_judge._apply_l3_decision(
        v=violation,
        obj=judgment,
        code_block="code",
        file_path="src/test_lea.c",
        results=results,
        rejected_tracker=rejected,
    )

    assert results == []
    assert rejected == {("src/test_lea.c", "LEA-048", None)}
    assert "removal_allowed" not in judgment


def test_experimental_grounded_relax_is_opt_in(monkeypatch):
    monkeypatch.delenv("L3_GROUNDED_ARTIFACT_RELAX", raising=False)
    assert l3_judge._grounded_artifact_relax() is False


def test_preselected_path_preserves_exact_content_and_skips_second_selection(monkeypatch):
    original = "int a;\r\nBAD();\r\n"
    observed = {}
    monkeypatch.setattr(l3_judge, "L3_PROVIDER", "local")
    monkeypatch.setattr(
        l3_judge, "_select_l3_candidates",
        lambda _items: (_ for _ in ()).throw(AssertionError("second selection")),
    )

    def fake_context(content, *args, **kwargs):
        observed["content"] = content
        return "BAD();"

    monkeypatch.setattr(l3_judge, "_get_code_context", fake_context)
    monkeypatch.setattr(
        l3_judge, "_call_gemini_batch_with_retry",
        lambda *args, **kwargs: [{"idx": 1, "is_real_issue": True, "confidence": 90}],
    )
    candidate = _authorize({
        "candidate_id": "set::a.c::X-1::2::1::hash",
        "file": "a.c", "line": 2, "rule_id": "X-1",
        "pattern_type": "regex", "detection_semantics": "prohibited_presence",
    })
    result = l3_judge.run_l3_contextualizer(
        {"files": [{"path": "a.c", "content": original, "lines": original.splitlines()}]},
        [candidate], _preselected=True, _rejected_candidate_ids=True,
    )
    assert observed["content"] == original
    assert result[0]["candidate_id"] == candidate["candidate_id"]
    assert result[0]["detection_semantics"] == "prohibited_presence"


def test_retrieval_required_candidate_cannot_be_precondition_rejected(monkeypatch):
    monkeypatch.setattr(l3_judge, "L3_PROVIDER", "local")
    monkeypatch.setattr(l3_judge, "_get_code_context", lambda *_a, **_k: "int plain;")
    monkeypatch.setattr(
        l3_judge, "_call_gemini_batch_with_retry",
        lambda *_a, **_k: [{"idx": 1, "is_real_issue": True, "confidence": 90}],
    )
    candidate = _authorize({
        "candidate_id": "routed-com-001", "file": "plain.c", "line": 1,
        "rule_id": "COM-001", "pattern_type": "regex",
        "detection_semantics": "prohibited_presence",
        "rag_evidence_bundle": [], "rag_guideline_text": "",
    })
    rejected = set()
    results = l3_judge.run_l3_contextualizer(
        {"files": [{"path": "plain.c", "content": "int plain;"}]},
        [candidate], _preselected=True, _rejected_tracker=rejected,
    )
    assert rejected == set()
    assert len(results) == 1
    assert results[0]["rule_id"] == "COM-001"


def test_occurrence_rejection_key_is_opt_in_and_legacy_default_remains(monkeypatch):
    monkeypatch.setenv("ABLATION_NO_DUAL_VERIFY", "1")
    monkeypatch.setattr(l3_judge, "verify_citation_bound_decision", lambda *_a, **_k: {
        "verified": True, "reason": "citation_bound_verified", "cited_unit_ids": ["u1"],
    })
    violation = {
        "candidate_id": "occurrence-2", "rule_id": "X-1", "file": "a.c",
        "line": 4, "pattern_type": "regex",
    }
    judgment = {"is_real_issue": False, "confidence": 10}
    occurrence_tracker = set()
    records = []
    judgment.update({
        "_initial_violation_probability": 90,
        "_rejudge_violation_probability": 15,
        "_rejudge_applied": True,
    })
    l3_judge._apply_l3_decision(
        v=violation, obj=judgment, code_block="code", file_path="a.c",
        results=[], rejected_tracker=occurrence_tracker, rejected_candidate_ids=True,
        decision_records=records,
    )
    assert occurrence_tracker == {"occurrence-2"}
    assert records == [{
        "candidate_id": "occurrence-2", "initial_violation_probability": 90,
        "rejudge_violation_probability": 15, "rejudge_applied": True,
        "score_provenance": "prompt_contract_confidence_proxy_not_calibrated_probability",
        "decision": "rejected",
    }]
    assert l3_judge._reject_key(violation) == ("a.c", "X-1", 4)


def test_required_absence_fp_verify_requires_grounded_evidence(monkeypatch):
    responses = iter([
        {"is_real_issue": False, "confidence": 90, "description": "근거 없음"},
        {
            "is_real_issue": False, "confidence": 90, "description": "위임 확인",
            "evidence_type": "delegated_to_other_file", "delegated_target": "core.c",
        },
    ])
    monkeypatch.setattr(l3_judge, "_call_gemini_with_retry", lambda *_a, **_k: next(responses))
    candidate = {
        "rule_id": "X-AST", "pattern_type": "ast",
        "detection_semantics": "required_absence", "line": None,
    }
    assert l3_judge._verify_fp_removal(candidate, {}, "code", "wrapper.c") is False
    assert l3_judge._verify_fp_removal(candidate, {}, "code", "wrapper.c") is True


def test_rejudge_merge_preserves_omitted_structured_evidence():
    first = {
        "is_real_issue": True, "confidence": 70,
        "evidence_type": "direct_violation", "supporting_symbol": "rounds",
    }
    merged = l3_judge._merge_rejudge_result(
        first, {"is_real_issue": False, "confidence": 20, "description": "second"},
    )
    assert merged["is_real_issue"] is False
    assert merged["evidence_type"] == "direct_violation"
    assert merged["supporting_symbol"] == "rounds"


def test_violation_confidence_proxy_is_not_inverted_by_binary_verdict():
    assert l3_judge._violation_confidence_proxy({
        "is_real_issue": False, "confidence": 20,
    }) == 20
    assert l3_judge._violation_confidence_proxy({
        "is_real_issue": True, "confidence": 80,
    }) == 80


def test_unknown_detection_semantics_is_never_removed(monkeypatch):
    monkeypatch.setenv("ABLATION_NO_DUAL_VERIFY", "1")
    results = []
    rejected = set()
    l3_judge._apply_l3_decision(
        v={
            "rule_id": "X-AST", "pattern_type": "ast",
            "detection_semantics": "unknown", "file": "x.c", "line": None,
        },
        obj={"is_real_issue": False, "confidence": 0, "description": "unknown"},
        code_block="code", file_path="x.c", results=results,
        rejected_tracker=rejected,
    )
    assert len(results) == 1
    assert results[0]["l3_removal_blocked_reason"] == "unknown_semantics"
    assert rejected == set()
