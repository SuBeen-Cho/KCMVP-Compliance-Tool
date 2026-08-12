import json
from pathlib import Path


def test_external_input_contract_is_closed_and_keeps_proxy_gt_out():
    path=Path(__file__).resolve().parents[2]/"evaluation/final_external_inputs_contract.json"
    value=json.loads(path.read_text())
    assert value["build_context"]["required_sets"]==7
    assert value["ground_truth"]["reviewers"]==2
    assert value["ground_truth"]["adjudicators"]==1
    assert "same_model_test_retest" in value["ground_truth"]["prohibited_as_final_gt"]
    assert len(value["acceptance"]["clone_split_must_match"])==64
