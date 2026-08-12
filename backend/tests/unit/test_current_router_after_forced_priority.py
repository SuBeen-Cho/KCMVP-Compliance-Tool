import json
from pathlib import Path

def test_clean_router_result_preserves_stage_gate_after_forced_priority():
    path=Path(__file__).resolve().parents[2]/"evaluation/public_current_router_after_forced_priority.json"
    value=json.loads(path.read_text())
    assert value["manifest"]["git_dirty"] is False
    assert value["manifest"]["git_head"].startswith("8023f85")
    assert value["snapshot"]["candidate_count"]==265
    assert {k:v["count"] for k,v in value["stage_distribution"].items()}=={"deterministic":30,"ai_ready":45,"hold":190}
    assert value["ai_ready_universe"]["count"]==45
    assert value["api_calls"]==0
