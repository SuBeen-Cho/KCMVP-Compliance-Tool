import json
from pathlib import Path


def test_com004_gt_protocol_is_clone_disjoint_and_not_proxy_gt():
    path = Path(__file__).resolve().parents[2] / "evaluation/com004_manual_gt_protocol.json"
    value = json.loads(path.read_text())
    assert value["population"] == 16 and value["known_clone_groups"] == 10
    assert value["label_unit"] == "clone_group_representative"
    assert value["adjudication"]["same_model_proxy_gt_forbidden"] is True
    assert value["split"]["candidate_overlap_forbidden"] is True
    assert value["split"]["clone_group_overlap_forbidden"] is True
    assert value["status"] == "preregistered_not_executed"


def test_accuracy_is_blocked_until_human_gt_and_program_facts():
    path = Path(__file__).resolve().parents[2] / "evaluation/com004_manual_gt_protocol.json"
    value = json.loads(path.read_text())
    assert value["adjudication"]["reviewers"] >= 2
    assert value["acceptance_gates"]["authenticated_preprocessing_coverage_min"] >= 0.95
    assert "No accuracy metric" in value["claim_limit"]
