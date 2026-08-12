import app.services.clang_straightline_reaching_def as rd
from app.services.lea001_rhs_coverage_proof import prove_lea001_rhs_coverage


def binding(source: str):
    return rd.VerifiedPreprocessingBinding(
        original_source_sha256="a" * 64,
        preprocessed_sha256=rd._sha(source.encode()),
        input_manifest_sha256="b" * 64,
        compiler_binary_sha256="c" * 64,
        _attestor=rd._BINDING_ATTESTOR,
    )


def prove(source: str):
    return prove_lea001_rhs_coverage(
        source, function_name="block", preprocessing_binding=binding(source))


LOOP = """
void block(const unsigned char *input, unsigned char *output) {
  for (unsigned i = 0; i < 16; ++i) output[i] = input[i];
}
"""


def unrolled(rhs=lambda i: f"input[{i}]", indices=range(16)):
    stores = " ".join(f"output[{i}] = {rhs(i)};" for i in indices)
    return f"void block(const unsigned char *input, unsigned char *output) {{ {stores} }}"


def test_canonical_loop_proves_coverage_and_rhs_but_never_algorithm_identity():
    result = prove(LOOP)
    assert result["structural_complete"] is True
    assert result["coverage"]["indices"] == list(range(16))
    assert result["coverage"]["bits"] == 128
    assert result["rhs_origin"] == "direct_input_same_index"
    assert result["reaching_definition_proved"] is True
    assert result["algorithm_identity_proved"] is False
    assert result["semantic_authorized"] is False
    assert result["state"] == "unknown"
    assert result["reason"] == "direct_copy_proved_but_lea_algorithm_identity_unproved"


def test_unrolled_copy_proves_all_exact_indices_through_reaching_def_substrate():
    result = prove(unrolled())
    assert result["structural_complete"] is True
    assert result["shape"] == "unrolled_direct_copy"
    assert result["coverage"]["indices"] == list(range(16))
    assert result["semantic_authorized"] is False


def test_missing_duplicate_shifted_and_constant_rhs_do_not_prove():
    assert prove(unrolled(indices=range(15)))["reason"] == "exact_16_octet_coverage_unproved"
    duplicate = unrolled(indices=[*range(15), 14])
    assert prove(duplicate)["reason"] in {
        "caller_visible_reaching_definition_unproved", "exact_16_octet_coverage_unproved"}
    assert prove(unrolled(lambda i: f"input[{(i + 1) % 16}]"))["reason"] == "rhs_origin_unproved"
    assert prove(unrolled(lambda i: "0"))["reason"] == "rhs_origin_unproved"


def test_hostile_loop_bounds_steps_branches_calls_and_dead_stores_abstain():
    attacks = [
        LOOP.replace("i < 16", "i <= 16"),
        LOOP.replace("++i", "i += 2"),
        LOOP.replace("input[i]", "input[(i + 1) & 15]"),
        LOOP.replace("output[i] = input[i];", "if (i != 7) output[i] = input[i];"),
        LOOP.replace("output[i] = input[i];", "output[i] = helper(input[i]);"),
        LOOP.replace("output[i] = input[i];", "output[i] = input[i]; output[0] = 0;"),
        LOOP.replace("output[i] = input[i];", "input++; output[i] = input[i];"),
        LOOP.replace("unsigned i", "_Bool i"),
    ]
    for source in attacks:
        assert prove(source).get("structural_complete") is not True


def test_copy_does_not_claim_input_output_non_aliasing():
    result = prove(LOOP)
    assert result["input_output_non_aliasing_proved"] is False


def test_writable_alias_extra_pointer_and_non_octet_types_abstain():
    writable = LOOP.replace("const unsigned char *input", "unsigned char *input")
    assert prove(writable)["reason"] == "non_aliasing_octet_io_unproved"
    extra = LOOP.replace("unsigned char *output", "unsigned char *output, const unsigned char *key")
    assert prove(extra)["reason"] == "non_aliasing_octet_io_unproved"
    wide = LOOP.replace("unsigned char", "unsigned short")
    assert prove(wide)["reason"] == "non_aliasing_octet_io_unproved"


def test_binding_is_mandatory_and_bound_to_exact_source_bytes():
    assert prove_lea001_rhs_coverage(LOOP, function_name="block")["reason"] == \
        "preprocessor_provenance_unproved"
    result = prove_lea001_rhs_coverage(
        LOOP + "\n", function_name="block", preprocessing_binding=binding(LOOP))
    assert result["reason"] == "preprocessor_provenance_unproved"
