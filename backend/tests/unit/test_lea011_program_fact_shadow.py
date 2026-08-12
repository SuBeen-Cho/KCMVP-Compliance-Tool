from app.services.lea011_program_fact_extractor import EXPECTED_DELTA
from experiments.lea011_program_fact_shadow import evaluate_candidate

SECRET = b"test-only-lea011-shadow-secret-32b"
SOURCE = "uint32_t k[8]={" + ",".join(f"0x{x:x}U" for x in EXPECTED_DELTA) + "};"


def proven_source():
    table = "const uint32_t k[8]={" + ",".join(f"0x{x:x}U" for x in EXPECTED_DELTA) + "};\n"
    return table + "".join(
        f"void lea_key_schedule_{bits}(uint32_t t) {{ t=rotl32(t+k[i&7],1); }}\n"
        for bits in (128, 192, 256)
    )


def test_shadow_keeps_declaration_only_source_unknown_and_never_authorizes():
    candidate = {"rule_id":"LEA-011", "algorithm":"LEA", "operation":"key_schedule",
                 "complete_source":SOURCE}
    result = evaluate_candidate("c1", candidate, SECRET)
    assert result["state"] == "unknown"
    assert result["extraction_reason"] == "delta_table_missing"
    assert result["production_authorized"] is False


def test_snippet_is_not_promoted_to_complete_source():
    candidate = {"rule_id":"LEA-011", "algorithm":"LEA", "operation":"key_schedule",
                 "snippet":SOURCE}
    assert evaluate_candidate("c1", candidate, SECRET)["state"] == "unknown"


def test_even_proved_complete_source_remains_shadow_only():
    candidate = {"rule_id":"LEA-011", "algorithm":"LEA", "operation":"key_schedule",
                 "complete_source":proven_source()}
    result = evaluate_candidate("c1", candidate, SECRET)
    assert result["state"] == "unknown"
    assert result["extraction_reason"] == "semantic_defuse_and_reachability_unproved"
    assert result["production_authorized"] is False


def test_other_rules_fail_closed():
    result = evaluate_candidate("c1", {"rule_id":"LEA-001"}, SECRET)
    assert result == {"candidate_id":"c1", "state":"unknown",
                      "reason":"rule_not_supported", "production_authorized":False}
