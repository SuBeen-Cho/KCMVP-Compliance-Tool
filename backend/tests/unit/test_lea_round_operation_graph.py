import pytest
import shutil
import hashlib
from pathlib import Path

import app.services.clang_straightline_reaching_def as rd
from app.services.lea_round_operation_graph import prove_lea_round_operation_graph

GOOD = """
typedef unsigned int uint32_t;
void lea_round_graph_fixture(uint32_t *restrict out, const uint32_t *restrict in,
                             const uint32_t *restrict rk) {
 out[0]=(((in[0]^rk[0])+(in[1]^rk[1]))<<9)|(((in[0]^rk[0])+(in[1]^rk[1]))>>23);
 out[1]=(((in[1]^rk[2])+(in[2]^rk[3]))>>5)|(((in[1]^rk[2])+(in[2]^rk[3]))<<27);
 out[2]=(((in[2]^rk[4])+(in[3]^rk[5]))>>3)|(((in[2]^rk[4])+(in[3]^rk[5]))<<29);
 out[3]=in[0];
}
"""


def binding(source):
    compiler = shutil.which("clang")
    assert compiler is not None
    return rd.VerifiedPreprocessingBinding(
        original_source_sha256="a" * 64, preprocessed_sha256=rd._sha(source.encode()),
        input_manifest_sha256="b" * 64,
        compiler_binary_sha256=hashlib.sha256(Path(compiler).read_bytes()).hexdigest(),
        _attestor=rd._BINDING_ATTESTOR)


def test_exact_graph_is_only_structural_and_binds_current_evidence_gap():
    result = prove_lea_round_operation_graph(GOOD, preprocessing_binding=binding(GOOD))
    assert result["state"] == "unknown"
    assert result["structural_complete"] and result["graph_equal"]
    assert result["observed_graph_sha256"] == result["expected_graph_sha256"]
    assert result["claim_id"] == "LEA.014"
    assert result["rule_ids"] == ["LEA-027", "LEA-028", "LEA-029", "LEA-030", "LEA-031"]
    assert result["evidence_unit_ids"] == []
    assert result["evidence_binding_complete"] is False
    assert len(result["function_ast_sha256"]) == 64
    assert result["reason"] == "official_evidence_units_unbound_and_independent_audit_pending"


@pytest.mark.parametrize("old,new,reason", [
    ("<<9", "<<8", "closed_operation_vocabulary_unproved"),
    ("rk[1]", "rk[2]", "normative_graph_mismatch"),
    ("out[3]=in[0]", "out[3]=in[1]", "normative_graph_mismatch"),
    ("out[1]=", "out[0]=", "normative_graph_mismatch"),
    ("+(in[1]^rk[1])", "^(in[1]+rk[1])", "normative_graph_mismatch"),
])
def test_non_equivalent_attacks_mismatch(old, new, reason):
    attacked = GOOD.replace(old, new)
    result = prove_lea_round_operation_graph(attacked, preprocessing_binding=binding(attacked))
    assert result["state"] == "unknown"
    assert result.get("graph_equal") is not True
    assert result["reason"] == reason


def test_extra_store_alias_control_effect_and_signed_width_fail_closed():
    extra = GOOD.replace("out[3]=in[0];", "out[3]=in[0]; out[3]=in[0];")
    assert prove_lea_round_operation_graph(extra, preprocessing_binding=binding(extra))["reason"] \
        == "normative_graph_mismatch"
    controlled = GOOD.replace("out[3]=in[0];", "if(in[0]) out[3]=in[0];")
    assert prove_lea_round_operation_graph(controlled, preprocessing_binding=binding(controlled))["reason"] \
        == "closed_straightline_body_unproved"
    effect = GOOD.replace("in[0]^rk[0]", "in[0]++^rk[0]")
    assert prove_lea_round_operation_graph(effect, preprocessing_binding=binding(effect))["reason"] \
        == "clang_parse_failed"
    signed = GOOD.replace("typedef unsigned int uint32_t", "typedef int uint32_t")
    assert prove_lea_round_operation_graph(signed, preprocessing_binding=binding(signed))["reason"] \
        == "closed_uint32_io_shape_unproved"
    endian = GOOD.replace("in[0]^rk[0]", "*((const uint32_t*)((const char*)in+1))^rk[0]")
    assert prove_lea_round_operation_graph(endian, preprocessing_binding=binding(endian))["reason"] \
        == "closed_straightline_body_unproved"


def test_unsealed_or_wrong_function_never_extracts():
    assert prove_lea_round_operation_graph(GOOD)["reason"] == "preprocessor_provenance_unproved"
    wrong = GOOD.replace("lea_round_graph_fixture", "lea_round")
    assert prove_lea_round_operation_graph(wrong, preprocessing_binding=binding(wrong))["reason"] \
        == "bounded_entrypoint_unproved"


def test_capture_and_proof_compiler_must_be_identical():
    value = binding(GOOD)
    object.__setattr__(value, "compiler_binary_sha256", "0" * 64)
    assert prove_lea_round_operation_graph(
        GOOD, preprocessing_binding=value)["reason"] == "proof_capture_toolchain_mismatch"


def test_alias_freedom_must_be_in_the_function_contract():
    aliased = GOOD.replace(" *restrict", " *")
    result = prove_lea_round_operation_graph(aliased, preprocessing_binding=binding(aliased))
    assert result["state"] == "unknown"
    assert result.get("structural_complete") is not True
    assert result["reason"] == "closed_uint32_io_shape_unproved"
