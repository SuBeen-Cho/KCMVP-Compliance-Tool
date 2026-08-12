import hashlib

import pytest

from app.services.lea011_program_fact_extractor import (
    EXPECTED_DELTA, extract_lea011_program_fact, extractor_sha256,
)
from app.services.program_fact_contract import verify_program_fact

SECRET = b"test-only-lea011-extractor-secret!!"
TABLE = "const uint32_t constants[8] = {" + ",".join(f"0x{x:08X}U" for x in EXPECTED_DELTA) + "};\n"


def complete_source(table=TABLE, *, missing=None, indirect=False):
    functions = []
    for bits in (128, 192, 256):
        if bits == missing:
            continue
        expression = ("apply_delta(t, constants, i)" if indirect else
                      "rotl32(t + constants[i & 7], 1)")
        functions.append(
            f"void lea_key_schedule_{bits}(uint32_t t) {{ t = {expression}; }}\n")
    return table + "".join(functions)


GOOD = complete_source()


def extract(source=GOOD, **overrides):
    args = {"candidate_id":"candidate-1", "claim_id":"LEA-011:C1",
            "applicability":{"algorithm":"LEA", "operation":"key_schedule"},
            "source_complete":True, "runtime_secret":SECRET}
    args.update(overrides)
    return extract_lea011_program_fact(source, **args)


def expected(source=GOOD, candidate_id="candidate-1"):
    return {"extractor_id":"lea011-delta-defuse", "extractor_version":"2.0.0",
            "extractor_sha256":extractor_sha256(),
            "source_sha256":hashlib.sha256(source.encode()).hexdigest(),
            "candidate_id":candidate_id, "rule_id":"LEA-011", "claim_id":"LEA-011:C1"}


def verified(source=GOOD, **kwargs):
    envelope = extract(source, **kwargs)
    return envelope, verify_program_fact(envelope, SECRET,
        expected(source, kwargs.get("candidate_id", "candidate-1")))


def test_exact_complete_table_and_direct_all_variant_use_remains_unknown():
    envelope, result = verified()
    assert result == {"verified":True, "state":"unknown", "reason":"fact_verified"}
    assert envelope["observations"][0]["value"][0] == "0xc3efe9db"
    assert [row["locator"]["key_bits"] for row in envelope["observations"][1:]] == [128, 192, 256]
    assert envelope["missing_context"] == ["semantic_defuse_and_reachability_unproved"]


def test_wrong_lexically_used_table_remains_unknown_without_semantic_defuse():
    source = GOOD.replace("0xC3EFE9DBU", "0xC3EFE9DAU")
    envelope, result = verified(source)
    assert result["state"] == "unknown"
    assert envelope["missing_context"] == ["semantic_defuse_and_reachability_unproved"]


@pytest.mark.parametrize("mutation", [
    lambda s: s.replace("t = rotl32", "if (0) t = rotl32"),
    lambda s: s.replace("constants[i & 7]", "constants[0]"),
    lambda s: s.replace("constants[i & 7]", "constants[(i + 1) & 7]"),
])
def test_dead_or_wrong_index_regex_matches_never_promote(mutation):
    envelope, result = verified(mutation(GOOD))
    assert result["state"] == "unknown"
    assert envelope["missing_context"] == ["semantic_defuse_and_reachability_unproved"]


@pytest.mark.parametrize("source,reason", [
    (complete_source(missing=256), "key_schedule_256_function_unproved"),
    (complete_source(indirect=True), "delta_direct_defuse_128_unproved"),
    (GOOD.replace("lea_key_schedule_192", "lea_key_schedule_128_copy"),
     "key_schedule_128_function_unproved"),
    (GOOD.replace("rotl32(t + constants[i & 7], 1)", "rotl32(t, 1) + constants[i & 7]", 1),
     "delta_direct_defuse_128_unproved"),
    (GOOD.replace("rotl32(t + constants[i & 7], 1)", "rotl32(t + 1, constants[i & 7])", 1),
     "delta_direct_defuse_128_unproved"),
])
def test_incomplete_applicability_or_defuse_abstains(source, reason):
    envelope, result = verified(source)
    assert result["state"] == "unknown"
    assert envelope["missing_context"] == [reason]


@pytest.mark.parametrize("source,reason", [
    ("#include <stdint.h>\n" + GOOD, "preprocessor_context_present"),
    ("#define D 0xC3EFE9DBU\n" + GOOD, "preprocessor_context_present"),
    (GOOD.replace("0xC3EFE9DBU", "DELTA0"), "initializer_not_eight_hex_literals"),
    (GOOD + GOOD.replace("constants", "other"), "ambiguous_typed_tables"),
    (GOOD.replace("const uint32_t constants", "unsigned int constants"), "delta_table_missing"),
    (GOOD.replace(",0xE5C40957U", ""), "initializer_not_eight_hex_literals"),
    (GOOD.replace("0xC3EFE9DBU", "(0xC3EFE9DBU)"), "initializer_not_eight_hex_literals"),
    ("/* " + GOOD + " */", "delta_table_missing"),
    ('const char *s = "' + GOOD.replace('"', '\\"') + '";', "delta_table_missing"),
    ('const char *s = R"tag(' + GOOD + ')tag";', "unsupported_raw_string_context"),
])
def test_attack_and_ambiguous_inputs_abstain(source, reason):
    envelope, result = verified(source)
    assert result["state"] == "unknown"
    assert envelope["missing_context"] == [reason]


def test_partial_source_and_wrong_applicability_abstain():
    assert verified(source_complete=False)[1]["state"] == "unknown"
    assert verified(applicability={"algorithm":"LEA", "operation":"encrypt"})[1]["state"] == "unknown"


def test_candidate_binding_and_runtime_hmac_are_enforced():
    envelope = extract()
    wrong = expected(candidate_id="candidate-2")
    assert verify_program_fact(envelope, SECRET, wrong)["reason"] == "fact_provenance_mismatch"
    assert verify_program_fact(envelope, b"x" * 32, expected())["reason"] == "fact_seal_mismatch"
