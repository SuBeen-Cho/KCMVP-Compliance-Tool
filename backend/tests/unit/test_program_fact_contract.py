import copy

import pytest

from app.services.program_fact_contract import (
    build_program_fact, seal_program_fact, verify_program_fact, verdict_from_fact,
)


SECRET = b"test-only-program-fact-secret-32bytes!"


def provenance():
    return {"extractor_id":"ast-v1", "extractor_version":"1",
            "extractor_sha256":"a"*64, "source_sha256":"b"*64,
            "candidate_id":"c1", "rule_id":"LEA-001", "claim_id":"LEA-001:C1"}


def sealed(state="observed"):
    fact = build_program_fact(provenance=provenance(), state=state,
                              observations=[{"kind":"integer_literal", "value":16,
                                             "locator":{"line":7, "column":3}}])
    return seal_program_fact(fact, SECRET)


def test_round_trip_binds_fact_to_candidate_rule_claim_and_extractor():
    result = verify_program_fact(sealed(), SECRET, provenance())
    assert result == {"verified": True, "state":"observed", "reason":"fact_verified"}


@pytest.mark.parametrize("field", ["candidate_id", "rule_id", "claim_id", "source_sha256",
                                    "extractor_id", "extractor_version", "extractor_sha256"])
def test_wrong_expected_provenance_fails_closed(field):
    expected = provenance(); expected[field] += "x"
    assert verify_program_fact(sealed(), SECRET, expected)["state"] == "unknown"


def test_mutation_and_wrong_secret_are_rejected():
    value = sealed(); value["observations"][0]["value"] = 32
    assert verify_program_fact(value, SECRET, provenance())["reason"] == "fact_content_hash_mismatch"
    assert verify_program_fact(sealed(), b"x"*32, provenance())["reason"] == "fact_seal_mismatch"


def test_closed_schema_and_complete_expected_provenance_are_required():
    value = sealed(); value["model_guess"] = True
    assert verify_program_fact(value, SECRET, provenance())["reason"] == "fact_envelope_schema_invalid"
    expected = provenance(); expected.pop("claim_id")
    assert verify_program_fact(sealed(), SECRET, expected)["reason"] == "fact_expected_provenance_invalid"


def test_hashes_must_be_lowercase_hex_and_observations_are_revalidated():
    bad_provenance = provenance(); bad_provenance["source_sha256"] = "z" * 64
    fact = build_program_fact(provenance=bad_provenance, state="observed",
                              observations=[{"kind":"literal", "value":16, "locator":{"line":1}}])
    assert fact["state"] == "unknown"
    value = sealed(); value["observations"] = [{"kind":"literal", "value":16, "locator":{}}]
    body = {k: v for k, v in value.items() if k not in {"content_sha256", "seal"}}
    from app.services.program_fact_contract import content_sha256
    value["content_sha256"] = content_sha256(body)
    value = seal_program_fact(value, SECRET)
    assert verify_program_fact(value, SECRET, provenance())["reason"] == "fact_state_invalid"


def test_missing_context_or_invalid_observation_forces_unknown():
    fact = build_program_fact(provenance=provenance(), state="observed",
                              observations=[{"kind":"literal", "value":16, "locator":{"line":1}}],
                              missing_context=["unit"])
    assert fact["state"] == "unknown"
    fact = build_program_fact(provenance=provenance(), state="observed", observations=[])
    assert fact["state"] == "unknown"


def test_builder_rejects_extra_provenance_and_malformed_missing_context():
    extra = provenance(); extra["model_id"] = "untrusted"
    fact = build_program_fact(provenance=extra, state="observed",
                              observations=[{"kind":"literal", "value":16,
                                             "locator":{"line":1}}])
    assert fact["state"] == "unknown"
    fact = build_program_fact(provenance=provenance(), state="observed",
                              observations=[{"kind":"literal", "value":16,
                                             "locator":{"line":1}}],
                              missing_context="unit")
    assert fact["state"] == "unknown"
    assert fact["missing_context"] == []


def test_short_secret_is_never_accepted():
    with pytest.raises(ValueError):
        seal_program_fact(build_program_fact(provenance=provenance(), state="unknown",
                                             observations=[]), b"short")


def test_polarity_mapping_requires_verified_non_unknown_fact():
    assert verdict_from_fact("required", {"verified":True, "state":"observed"}) == "non_violation"
    assert verdict_from_fact("required", {"verified":True, "state":"contradicted"}) == "violation"
    assert verdict_from_fact("prohibited", {"verified":True, "state":"observed"}) == "violation"
    assert verdict_from_fact("prohibited", {"verified":True, "state":"contradicted"}) == "non_violation"
    assert verdict_from_fact("required_all", {"verified":True, "state":"unknown"}) == "abstain"
    assert verdict_from_fact("allowed_set", {"verified":False, "state":"observed"}) == "abstain"
