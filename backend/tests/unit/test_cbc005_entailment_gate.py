import json
from pathlib import Path

def gate(): return json.loads((Path(__file__).resolve().parents[2]/"mapping/cbc005_entailment_gate.json").read_text())

def test_padding_oracle_goal_is_separate_from_generic_negative_return_example():
    value=gate(); assert value["decision"]=="remain_fail_closed"
    assert value["lexical_error_name_is_sufficient"] is False
    assert any("padding-oracle" in x for x in value["directly_entailed"])
    assert any("generic negative" in x for x in value["not_directly_entailed"])
    assert value["production_authorized"] is False

def test_official_named_padding_error_is_a_counterexample_to_name_only_detection():
    value=gate(); assert value["counterexample_units"]==["KCMVP_SUBMISSION_GUIDE_2025_09:p0026:b028"]
    assert any("named padding-error" in x for x in value["not_directly_entailed"])

def test_external_observability_and_all_paths_are_required_program_facts():
    facts=gate()["required_program_facts"]
    assert any("attacker-observable" in x for x in facts)
    assert any("all return paths" in x for x in facts)
    assert any("verify-before-release" in x for x in facts)
