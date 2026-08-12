import pytest

from app.services.lea001_clang_block_proof import prove_lea001_block_semantics


GOOD = """
typedef unsigned char uint8_t;
void helper(uint8_t *, const uint8_t *, unsigned int);
void lea_encrypt_block(const uint8_t *input, uint8_t *output) {
  for (unsigned int i = 0; i < 16; ++i) { output[i] = input[i]; }
}
"""


def test_exact_typed_operative_shape_is_only_structural_evidence():
    result = prove_lea001_block_semantics(GOOD, preprocessed=True)
    assert result["state"] == "unknown"
    assert result["structural_complete"] is True
    assert result["observation"]["extent"] == 16
    assert result["observation"]["bits"] == 128
    assert result["reason"] == "interprocedural_ssa_and_algorithm_identity_unproved"


@pytest.mark.parametrize("mutated,reason", [
    (GOOD.replace("i < 16", "i < 15"), "exact_16_byte_bound_unproved"),
    (GOOD.replace("output[i] = input[i]", "output[i] = 16"), "direct_block_io_influence_unproved"),
    (GOOD.replace("output[i] = input[i]", "output[0] = input[0]"), "direct_block_io_influence_unproved"),
    (GOOD.replace("output[i] = input[i]", "if (0) output[i] = input[i]"),
     "control_or_call_effect_unproved"),
    (GOOD.replace("output[i] = input[i]", "helper(output, input, 16)"),
     "control_or_call_effect_unproved"),
    (GOOD.replace("const uint8_t *input", "const unsigned int *input"),
     "octet_io_types_unproved"),
    (GOOD.replace("typedef unsigned char uint8_t", "typedef unsigned short uint8_t"),
     "octet_io_types_unproved"),
    (GOOD.replace("lea_encrypt_block", "diagnostic_buffer_copy"),
     "canonical_lea_entrypoint_unproved"),
])
def test_unrelated_or_ambiguous_16_never_promotes(mutated, reason):
    result = prove_lea001_block_semantics(mutated, preprocessed=True)
    assert result["state"] == "unknown"
    assert result["reason"] == reason
    assert "structural_complete" not in result


def test_unsealed_preprocessing_and_later_overwrite_abstain():
    assert prove_lea001_block_semantics(GOOD, preprocessed=False)["reason"] == \
        "preprocessor_provenance_unproved"
    attacked = GOOD.replace("output[i] = input[i];", "output[i] = input[i]; output[i] = 0;")
    result = prove_lea001_block_semantics(attacked, preprocessed=True)
    assert result["state"] == "unknown"
    assert result["reason"] == "direct_block_io_influence_unproved"
