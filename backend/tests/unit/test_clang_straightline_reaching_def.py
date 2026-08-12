import pytest

import app.services.clang_straightline_reaching_def as rd
from app.services.clang_straightline_reaching_def import prove_straightline_output_reaching_defs


def binding(source):
    return rd.VerifiedPreprocessingBinding(
        original_source_sha256="a" * 64,
        preprocessed_sha256=rd._sha(source.encode()),
        input_manifest_sha256="b" * 64,
        compiler_binary_sha256="c" * 64,
        _attestor=rd._BINDING_ATTESTOR,
    )


def prove(body: str, *, source_prefix: str = ""):
    source = source_prefix + f"void schedule(unsigned round, unsigned *out) {{ {body} }}"
    return prove_straightline_output_reaching_defs(
        source, function_name="schedule", output_parameter="out",
        preprocessing_binding=binding(source),
    )


def test_proves_unique_direct_caller_visible_stores_but_keeps_state_unknown():
    result = prove("out[0] = round + 1; out[1] = round + 2;")
    assert result["state"] == "unknown"
    assert result["structural_complete"] is True
    assert result["reason"] == "straight_line_caller_visible_reaching_definition_proved"
    assert len(result["reaching_definitions"]) == 2
    assert result["reaching_definitions"][0]["source_offset"] < \
        result["reaching_definitions"][1]["source_offset"]
    assert len(result["toolchain"]["ast_sha256"]) == 64
    assert len(result["source_sha256"]) == 64


def test_later_exact_output_overwrite_abstains():
    result = prove("out[round % 4] = 1; out[round % 4] = 2;")
    assert result["state"] == "unknown"
    assert result["reason"] == "later_output_overwrite_detected"


def test_distinct_dynamic_index_syntax_does_not_prove_disjoint_locations():
    result = prove("out[round % 4] = 1; out[(round + 1) % 4] = 2;")
    assert result["reason"] == "output_location_disjointness_unproved"


def test_no_store_and_non_pointer_output_abstain():
    assert prove("(void)round;")["reason"] == "caller_visible_store_unproved"
    source = "void schedule(unsigned round, unsigned out) { out = round; }"
    result = prove_straightline_output_reaching_defs(
        source, function_name="schedule", output_parameter="out",
        preprocessing_binding=binding(source))
    assert result["reason"] == "output_pointer_identity_unproved"

    pointer_to_pointer = "void schedule(unsigned **out) { out[0] = 0; }"
    result = prove_straightline_output_reaching_defs(
        pointer_to_pointer, function_name="schedule", output_parameter="out",
        preprocessing_binding=binding(pointer_to_pointer))
    assert result["reason"] == "output_pointer_identity_unproved"


def test_preprocessing_and_unique_definition_are_required():
    source = "void schedule(unsigned round, unsigned *out) { out[round] = 1; }"
    result = prove_straightline_output_reaching_defs(
        source, function_name="schedule", output_parameter="out", preprocessed=False)
    assert result["reason"] == "preprocessor_provenance_unproved"
    duplicate = source + source
    result = prove_straightline_output_reaching_defs(
        duplicate, function_name="schedule", output_parameter="out",
        preprocessing_binding=binding(duplicate))
    assert result["reason"] == "clang_parse_failed"


def test_control_flow_call_and_hidden_mutation_abstain():
    assert prove("if (round) out[0] = 1;")["reason"] == "straight_line_effects_unproved"
    called = prove("out[0] = helper(round);", source_prefix="unsigned helper(unsigned);\n")
    assert called["reason"] == "straight_line_effects_unproved"
    assert prove("out[round++] = 1;")["reason"] == "straight_line_effects_unproved"
    assert prove("return; out[0] = 1;")["reason"] == "straight_line_effects_unproved"


def test_aliases_and_unmodelled_writes_abstain():
    source = "void schedule(unsigned *input, unsigned *out) { out[0] = input[0]; }"
    result = prove_straightline_output_reaching_defs(
        source, function_name="schedule", output_parameter="out",
        preprocessing_binding=binding(source))
    assert result["reason"] == "output_alias_freedom_unproved"
    assert prove("unsigned *alias = out; out[0] = 1;")["reason"] == \
        "output_alias_freedom_unproved"
    assert prove("unsigned temporary; temporary = 1; out[0] = temporary;")["reason"] == \
        "non_output_write_effect_unproved"


def test_macro_text_without_preprocessed_contract_is_rejected():
    source = "#define PUT(x) out[0] = (x)\nvoid schedule(unsigned round, unsigned *out){PUT(round);}"
    result = prove_straightline_output_reaching_defs(
        source, function_name="schedule", output_parameter="out", preprocessed=False)
    assert result["reason"] == "preprocessor_provenance_unproved"


def test_toolchain_and_ast_binding_changes_with_source():
    first = prove("out[0] = 1;")
    second = prove("out[0] = 2;")
    assert first["source_sha256"] != second["source_sha256"]
    assert first["toolchain"]["ast_sha256"] != second["toolchain"]["ast_sha256"]
    assert first["reaching_definitions"][0]["rhs_ast_sha256"] != \
        second["reaching_definitions"][0]["rhs_ast_sha256"]


def test_legacy_true_and_wrong_source_binding_never_complete():
    source = "void schedule(unsigned round, unsigned *out) { out[0] = round; }"
    legacy = prove_straightline_output_reaching_defs(
        source, function_name="schedule", output_parameter="out", preprocessed=True)
    assert legacy["reason"] == "legacy_preprocessed_flag_untrusted"
    assert "structural_complete" not in legacy
    result = prove_straightline_output_reaching_defs(
        source, function_name="schedule", output_parameter="out",
        preprocessing_binding=binding(source + "\n"))
    assert result["reason"] == "preprocessor_provenance_unproved"
    assert "structural_complete" not in result


@pytest.mark.parametrize("declaration", [
    "unsigned **out", "void *out", "volatile unsigned *out",
    "unsigned (*out)(unsigned)", "struct opaque *out",
])
def test_non_complete_or_non_one_level_output_pointer_rejected(declaration):
    source = f"struct opaque; void schedule(unsigned round, {declaration}) {{ (void)round; }}"
    result = prove_straightline_output_reaching_defs(
        source, function_name="schedule", output_parameter="out",
        preprocessing_binding=binding(source))
    assert result["reason"] in {"output_pointer_identity_unproved", "clang_parse_failed"}


def test_binding_factory_requires_usable_verification_and_exact_preprocessed_bytes(monkeypatch):
    source = "void f(void) {}\n"
    digest = rd._sha(source.encode())
    envelope = {
        "provenance": {"source_sha256": "a" * 64,
                       "input_manifest_sha256": "b" * 64},
        "preprocessed_output": {"sha256": digest},
        "compile_command": {"compiler_binary_sha256": "c" * 64},
    }
    monkeypatch.setattr(rd, "verify_preprocessing_provenance",
                        lambda *args: {"verified": True, "usable": True})
    token = rd.verify_and_bind_preprocessing(
        envelope=envelope, runtime_secret=b"x" * 32, expected={},
        private_capture={}, analyzed_source=source)
    assert token is not None and token.preprocessed_sha256 == digest
    assert rd.verify_and_bind_preprocessing(
        envelope=envelope, runtime_secret=b"x" * 32, expected={},
        private_capture={}, analyzed_source=source + " ") is None
    monkeypatch.setattr(rd, "verify_preprocessing_provenance",
                        lambda *args: {"verified": True, "usable": False})
    assert rd.verify_and_bind_preprocessing(
        envelope=envelope, runtime_secret=b"x" * 32, expected={},
        private_capture={}, analyzed_source=source) is None
