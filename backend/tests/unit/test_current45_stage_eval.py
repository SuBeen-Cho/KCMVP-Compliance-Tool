from experiments.current45_stage_eval import _binding_complete, build


def unit(uid="U1"):
    import hashlib
    span = "official span"
    return {"unit_id": uid, "status": "verified", "source_sha256": "a" * 64,
            "span": span, "span_sha256": hashlib.sha256(span.encode()).hexdigest()}


def candidate(rule="LEA-027"):
    return {"rule_id": rule, "rule_provenance_sha256": "b" * 64,
            "rag_evidence_bundle": [unit()]}


def test_binding_requires_every_required_unit_and_live_span_hash():
    audit = {"rules": {"LEA-027": {"status": "verified", "review_required": False,
             "source_sha256": "a" * 64, "evidence_unit_ids": ["U1"]}}}
    assert _binding_complete(candidate(), audit)
    bad = candidate()
    bad["rag_evidence_bundle"][0]["span_sha256"] = "0" * 64
    assert not _binding_complete(bad, audit)
    audit["rules"]["LEA-027"]["evidence_unit_ids"].append("U2")
    assert not _binding_complete(candidate(), audit)
    injected = candidate()
    injected["rag_evidence_bundle"].append(unit("EXTRA"))
    assert not _binding_complete(injected, {"rules": {"LEA-027": {
        "status": "verified", "review_required": False,
        "source_sha256": "a" * 64, "evidence_unit_ids": ["U1"]}}})


def test_build_separates_routing_binding_fact_and_projection(monkeypatch):
    rows = [(str(i), candidate("LEA-027" if i < 4 else "CBC-001")) for i in range(45)]
    monkeypatch.setattr("experiments.current45_stage_eval.select_exact_ai_ready", lambda _: rows)
    audit_rows = {rule: {"status": "verified", "review_required": False,
                          "source_sha256": "a" * 64, "evidence_unit_ids": ["U1"]}
                  for rule in ("LEA-027", "CBC-001")}
    router = {"stage_distribution": {"deterministic": {"count": 30},
              "ai_ready": {"count": 45}, "hold": {"count": 190}},
              "snapshot": {"file_sha256": "d" * 64}, "manifest": {"git_dirty": True},
              "ai_ready_universe": {"ordered_envelope_binding_hashes_sha256": "c" * 64}}
    result = build({"candidates": [{}] * 265}, snapshot_sha256="d" * 64,
                   router_result=router, audit={"rules": audit_rows},
                   atomic={"rules": {"LEA-027": [{}], "CBC-001": [{}]}},
                   historical_atomic={"population": 41, "api_calls": 41,
                       "input_tokens": 4100, "output_tokens": 820, "estimated_cost_usd": .0082})
    assert result["stage_distribution"]["hold"]["count"] == 190
    assert result["evidence_binding"]["verified_rule_and_required_units_complete"] == 45
    assert result["program_fact"]["authenticated_sealed_fact_available"] == 0
    assert result["newly_mapped_lea_round"]["occurrences"] == 4
    assert result["historical41_comparison"]["atomic_v3_observed_linear_budget_projection"]["input_tokens"] == 4500
    assert result["provenance"]["router_manifest"]["git_dirty"] is True


def test_build_rejects_non_45_selector(monkeypatch):
    monkeypatch.setattr("experiments.current45_stage_eval.select_exact_ai_ready", lambda _: [])
    import pytest
    with pytest.raises(ValueError, match="exactly 45"):
        build({"candidates": []}, snapshot_sha256="d" * 64,
              router_result={}, audit={}, atomic={}, historical_atomic={})
