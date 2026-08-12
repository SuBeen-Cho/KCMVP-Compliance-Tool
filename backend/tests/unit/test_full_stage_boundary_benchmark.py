import copy
import hashlib
import json

import pytest

from experiments.full_stage_boundary_benchmark import SnapshotError, benchmark, load_candidates


def _snapshot(payload):
    digest = hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True,
                                      separators=(",", ":")).encode()).hexdigest()
    return {"schema_version": "1.0", "candidates": [
        {"candidate_id": "private-id", "payload": payload, "payload_sha256": digest}
    ]}


def test_benchmark_is_aggregate_only(monkeypatch):
    payload = {"rule_id": "PRIVATE-RULE", "message": "private source text"}
    monkeypatch.setattr("experiments.full_stage_boundary_benchmark.run_l2_rag_context",
                        lambda rows: [dict(rows[0], analysis_contract_version="1.0",
                                           disposition="hold", disposition_reason="no evidence",
                                           ai_need="prohibited", disposition_history=["hold"],
                                           rag_route={"decision": "retrieve"}, rag_evidence_bundle=[])])
    result = benchmark(_snapshot(payload), warm_runs=2)
    rendered = json.dumps(result)
    assert "private-id" not in rendered
    assert "PRIVATE-RULE" not in rendered
    assert "private source text" not in rendered
    assert result["stage_distribution"]["hold"]["count"] == 1
    assert result["execution"]["external_api_calls"] == 0
    assert result["dataset"]["interpretation_scope"] == "historical_policy_replay_not_current_end_to_end"
    assert result["verified_evidence"]["verifier_full_pass_coverage"] is None
    assert result["projected_llm_calls"]["measured_calls_avoided"] is None


def test_rejects_payload_tamper():
    snapshot = _snapshot({"rule_id": "LEA-001"})
    altered = copy.deepcopy(snapshot)
    altered["candidates"][0]["payload"]["rule_id"] = "LEA-002"
    with pytest.raises(SnapshotError, match="integrity"):
        load_candidates(altered)


def test_rejects_unknown_envelope_field():
    snapshot = _snapshot({"rule_id": "LEA-001"})
    snapshot["candidates"][0]["extra"] = True
    with pytest.raises(SnapshotError, match="closed"):
        load_candidates(snapshot)
