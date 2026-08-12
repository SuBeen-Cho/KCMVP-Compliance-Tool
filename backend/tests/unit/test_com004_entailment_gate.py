import json
from pathlib import Path


BACKEND = Path(__file__).resolve().parents[2]


def _audit():
    return json.loads((BACKEND / "mapping/com004_entailment_gate.json").read_text())


def test_com004_separates_normative_rng_requirement_from_c_api_examples():
    audit = _audit()
    assert audit["decision"] == "remain_fail_closed"
    assert audit["mapping_verified"] is False
    assert audit["production_authorized"] is False
    assert len(audit["entailed_claims"]) == 2
    assert len(audit["not_exactly_entailed_claims"]) == 3


def test_lexical_function_match_cannot_authorize_a_program_fact():
    gate = _audit()["program_fact_gate"]
    assert gate["lexical_match_is_sufficient"] is False
    assert any("def-use" in item for item in gate["required"])
    assert any("test-vector" in item for item in gate["required"])


def test_evidence_units_are_exact_official_locators():
    units = _audit()["evidence_units"]
    assert units == [
        "KCMVP_GVI_PART2_2024_03:p0009:b006",
        "KCMVP_GVI_PART2_2024_03:p0103:b005",
        "KCMVP_GVI_PART2_2024_03:p0103:b006",
    ]
