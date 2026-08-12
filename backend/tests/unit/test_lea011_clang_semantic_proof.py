import pytest

from app.services.lea011_clang_semantic_proof import prove_lea011_clang_semantics


TABLE = "typedef unsigned int uint32_t;\nconst uint32_t delta[8]={0};\n"


def function(bits, modulus, *, rhs=None, statement=None):
    rhs = rhs or f"rotate(t + delta[round % {modulus}], 1)"
    statement = statement or f"round_keys[round % {modulus}] = {rhs};"
    return (f"uint32_t rotate(uint32_t x, uint32_t n);\n"
            f"void lea_key_schedule_{bits}(uint32_t t, uint32_t round, "
            f"uint32_t *round_keys) {{ {statement} }}\n")


def source(**replacements):
    result = TABLE + "".join(function(bits, modulus)
                             for bits, modulus in ((128, 4), (192, 6), (256, 8)))
    for old, new in replacements.items():
        result = result.replace(old, new)
    return result


def test_direct_canonical_ast_shape_remains_unknown_without_ssa():
    result = prove_lea011_clang_semantics(source(), preprocessed=True)
    assert result["state"] == "unknown"
    assert result["structural_complete"] is True
    assert result["reason"] == "ssa_reaching_definition_unproved"
    assert result["variants"] == {"128": "proved", "192": "proved", "256": "proved"}


@pytest.mark.parametrize("mutated,variant_reason", [
    (source(**{"round_keys[round % 4] =": "if (0) round_keys[round % 4] ="}),
     "straight_line_reachability_unproved"),
    (source(**{"delta[round % 4]": "delta[0]"}),
     "direct_round_key_influence_unproved"),
    (source(**{"delta[round % 4]": "delta[(round + 1) % 4]"}),
     "direct_round_key_influence_unproved"),
    (source(**{"round_keys[round % 4] =": "uint32_t unused ="}),
     "direct_round_key_influence_unproved"),
    (source(**{"round_keys[round % 4] =": "uint32_t *alias = round_keys; alias[round % 4] ="}),
     "direct_round_key_influence_unproved"),
    (source(**{"round_keys[round % 4] =": "return; round_keys[round % 4] ="}),
     "straight_line_reachability_unproved"),
    (source(**{"rotate(t + delta[round % 4], 1)": "(t + delta[round % 4]) && 0"}),
     "direct_round_key_influence_unproved"),
])
def test_attack_remains_unknown(mutated, variant_reason):
    result = prove_lea011_clang_semantics(mutated, preprocessed=True)
    assert result["state"] == "unknown"
    assert result["variants"]["128"] == variant_reason


def test_unsealed_preprocessing_and_shadowed_table_abstain():
    assert prove_lea011_clang_semantics(source(), preprocessed=False)["reason"] == \
        "preprocessor_provenance_unproved"
    shadowed = source(**{"{ round_keys[round % 4]": "{ const uint32_t delta[8]={0}; round_keys[round % 4]"})
    assert prove_lea011_clang_semantics(shadowed, preprocessed=True)["state"] == "unknown"


def test_later_output_overwrite_never_promotes_structural_shape():
    attacked = source(**{
        "round_keys[round % 4] = rotate(t + delta[round % 4], 1);":
        "round_keys[round % 4] = rotate(t + delta[round % 4], 1); "
        "round_keys[round % 4] = 0;"
    })
    result = prove_lea011_clang_semantics(attacked, preprocessed=True)
    assert result["state"] == "unknown"
