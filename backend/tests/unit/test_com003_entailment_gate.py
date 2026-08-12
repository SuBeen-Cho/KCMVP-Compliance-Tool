import json
from pathlib import Path


def _gate():
    path = Path(__file__).resolve().parents[2] / "mapping/com003_entailment_gate.json"
    return json.loads(path.read_text())


def test_hardcoding_claim_is_split_from_allowed_protected_and_kat_cases():
    gate = _gate()
    assert gate["decision"] == "remain_fail_closed"
    assert gate["lexical_initializer_is_sufficient"] is False
    assert gate["mapping_verified"] is gate["production_authorized"] is False
    assert any("KAT" in claim for claim in gate["directly_entailed"])
    assert any("KMS" in claim for claim in gate["not_directly_entailed"])


def test_program_fact_requires_operational_use_and_protection_status():
    facts = _gate()["required_program_facts"]
    assert any("operative secret" in fact for fact in facts)
    assert any("S-box" in fact for fact in facts)
    assert any("masking" in fact for fact in facts)


def test_units_are_closed_exact_official_locators():
    units = _gate()["official_evidence_units"]
    assert len(units) == 4 and len(set(units)) == 4
    assert all(unit.startswith("KCMVP_") and ":p" in unit and ":b" in unit for unit in units)
