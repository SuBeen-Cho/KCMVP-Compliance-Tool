import pytest

from experiments.current_router_universe_freeze import build
from experiments.grounded_ai_ready_eval import _sha


def _snapshot():
    candidates = [
        {"candidate_id": f"id-{index}", "payload_sha256": "x", "payload": {"rule_id": rule}}
        for index, rule in enumerate(("OLD", "KEEP", "NEW"))
    ]
    return {
        "schema_version": "1.0", "snapshot_id": "s", "set_id": "x",
        "source_tree_sha256": "a" * 64, "provenance": {"git_commit": "b" * 40},
        "sources": [], "candidates": candidates,
    }


def _patch(monkeypatch):
    span = "text"
    span_sha256 = __import__("hashlib").sha256(span.encode()).hexdigest()
    monkeypatch.setattr("experiments.current_router_universe_freeze.validate_snapshot", lambda value: {})
    monkeypatch.setattr("experiments.current_router_universe_freeze.select_exact_ai_ready", lambda value: [
        ("id-1", {"rule_id": "KEEP", "rag_evidence_bundle": [{
            "unit_id": "u", "source_id": "s", "locator": "p1", "span": span,
            "span_sha256": span_sha256}]}),
        ("id-2", {"rule_id": "NEW", "rag_evidence_bundle": [{
            "unit_id": "u", "source_id": "s", "locator": "p1", "span": span,
            "span_sha256": span_sha256}]}),
    ])
    monkeypatch.setattr("experiments.current_router_universe_freeze.benchmark", lambda value, warm_runs: {
        "stage_distribution": {"deterministic": {"count": 1}, "ai_ready": {"count": 2},
                               "hold": {"count": 0}},
        "reproducibility_manifest": {}, "latency_ms": {},
    })
    monkeypatch.setattr("experiments.current_router_universe_freeze._load_verified_official_units",
                        lambda rule: [{"unit_id": "u"}])
    monkeypatch.setattr("experiments.current_router_universe_freeze.build_atomic_contract",
                        lambda rule, units: {"claims": [{}]})


def test_freeze_compares_membership_without_merging(monkeypatch):
    _patch(monkeypatch)
    prior = [{"index": 0, "candidate_id_sha256": _sha(b"id-0")},
             {"index": 1, "candidate_id_sha256": _sha(b"id-1")}] + [
        {"index": index, "candidate_id_sha256": f"{index:064x}"} for index in range(2, 41)]
    snapshot = _snapshot()
    # Add harmless envelopes so every sealed historical occurrence can be joined.
    snapshot["candidates"].extend(
        {"candidate_id": f"extra-{index}", "payload_sha256": "x", "payload": {"rule_id": "OLD"}}
        for index in range(2, 41)
    )
    for index in range(2, 41):
        prior[index]["candidate_id_sha256"] = _sha(f"extra-{index}".encode())
    result = build(snapshot, snapshot_file_sha256="f" * 64, prior_rows=prior,
                   prior_ledger_sha256="l" * 64, expected_prior_ledger_sha256="l" * 64,
                   warm_runs=1)
    assert result["prior_ai_ready41"]["comparison_only_not_merged"] is True
    assert result["membership_delta"]["retained_count"] == 1
    assert result["membership_delta"]["added_rule_family_counts"] == {"NEW": 1}
    assert result["membership_delta"]["removed_count"] == 40
    assert result["evidence_readiness"]["semantic_authorization"] == "not_measured"
    assert "candidate_id_sha256" not in str(result)


def test_freeze_rejects_unsealed_prior_ledger(monkeypatch):
    _patch(monkeypatch)
    with pytest.raises(ValueError, match="ledger hash"):
        build(_snapshot(), snapshot_file_sha256="f" * 64, prior_rows=[],
              prior_ledger_sha256="a", expected_prior_ledger_sha256="b")
