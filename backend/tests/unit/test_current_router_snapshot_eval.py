from experiments.current_router_snapshot_eval import build


def test_current_report_binds_ai_universe_and_never_claims_accuracy(monkeypatch):
    snapshot={"schema_version":"1.0","snapshot_id":"s","set_id":"x","source_tree_sha256":"a"*64,
              "provenance":{},"sources":[],"candidates":[]}
    monkeypatch.setattr("experiments.current_router_snapshot_eval.validate_snapshot",lambda x: {})
    monkeypatch.setattr("experiments.current_router_snapshot_eval.benchmark",lambda x,warm_runs:{
        "stage_distribution":{k:{"count":n,"ratio":n/3} for k,n in (("deterministic",1),("ai_ready",1),("hold",1))},
        "latency_ms":{},"reproducibility_manifest":{}})
    monkeypatch.setattr("experiments.current_router_snapshot_eval.select_exact_ai_ready",lambda x:[("id",{"rule_id":"R"})])
    result=build(snapshot,snapshot_file_sha256="f"*64,warm_runs=1)
    assert result["api_calls"]==0 and result["ai_ready_universe"]["count"]==1
    assert "accuracy" in result["claim_limit"]
    assert len(result["ai_ready_universe"]["ordered_envelope_binding_hashes_sha256"])==64
