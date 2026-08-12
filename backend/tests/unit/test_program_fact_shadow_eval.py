from app.services.program_fact_contract import build_program_fact, seal_program_fact
from experiments.program_fact_shadow_eval import candidate_binding, validate_sealed_fact

SECRET = b"test-only-program-fact-secret-32bytes!"


def provenance():
    return {"extractor_id":"ast-v1", "extractor_version":"1", "extractor_sha256":"a"*64,
            "source_sha256":"b"*64, "candidate_id":"c1", "rule_id":"CBC-001",
            "claim_id":"CBC-001:C1"}


def fact():
    value = build_program_fact(provenance=provenance(), state="observed",
                               observations=[{"kind":"call", "value":"lea_encrypt",
                                              "locator":{"line":1}}])
    return seal_program_fact(value, SECRET)


def test_accepts_authenticated_provenance_bound_fact():
    assert validate_sealed_fact(provenance(), fact(), SECRET) == (True, "fact_verified")


def test_missing_fact_is_not_inferred_from_candidate_text():
    assert validate_sealed_fact(provenance(), None, SECRET) == (
        False, "sealed_program_fact_missing")


def test_rejects_candidate_rebinding_and_content_tamper():
    expected = provenance(); expected["candidate_id"] = "c2"
    assert validate_sealed_fact(expected, fact(), SECRET)[1] == "fact_provenance_mismatch"
    value = fact(); value["observations"][0]["value"] = "lea_decrypt"
    assert validate_sealed_fact(provenance(), value, SECRET)[1] == "fact_content_hash_mismatch"


def test_rejects_wrong_secret():
    assert validate_sealed_fact(provenance(), fact(), b"x"*32)[1] == "fact_seal_mismatch"


def test_candidate_binding_excludes_fact_to_avoid_self_reference():
    candidate = {"snippet":"x", "sealed_program_fact":fact()}
    first = candidate_binding("c1", candidate)
    candidate["sealed_program_fact"]["state"] = "contradicted"
    assert candidate_binding("c1", candidate) == first
