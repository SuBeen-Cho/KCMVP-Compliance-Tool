import json
from pathlib import Path

import pytest

from experiments.l3_advisory_checker import extract_pad002_facts, load_specs, run

BACKEND = Path(__file__).resolve().parents[2]
FIXTURES = BACKEND / "tests/fixtures"


def test_closed_spec_and_three_advisories():
    spec = load_specs(BACKEND / "rag/l3_advisory_specs.json")
    assert [row["advisory_id"] for row in spec["advisories"]] == ["GCM-006", "CTR-006", "PAD-002"]
    assert spec["default_enforcement"] == "disabled"
    index = json.loads((BACKEND / "data/evidence/official_units.local.json").read_text())
    known = {unit["unit_id"] for unit in index["units"]}
    assert all(set(row["evidence_unit_ids"]) <= known for row in spec["advisories"])


def test_open_advisory_schema_rejected(tmp_path):
    data = json.loads((BACKEND / "rag/l3_advisory_specs.json").read_text())
    data["advisories"][0]["extra"] = True
    path = tmp_path / "spec.json"
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="open advisory"):
        load_specs(path)


@pytest.mark.parametrize("fixture,outcome", [
    ("pad002_satisfied.c", "satisfied"),
    ("pad002_early_return_satisfied.c", "satisfied"),
    ("pad002_unsafe.c", "unsafe_observed"),
    ("pad002_release_before_validation.c", "unsafe_observed"),
    ("pad002_branch_unknown.c", "unknown"),
    ("pad002_unknown.c", "unknown"),
])
def test_pad002_three_way_outcomes(fixture, outcome):
    source = (FIXTURES / fixture).read_text()
    assert extract_pad002_facts(source)["outcome"] == outcome


def test_default_gate_never_emits_finding():
    result = run(FIXTURES / "pad002_unsafe.c", enabled=False)
    assert result == {"schema_version": "1.0", "enabled": False, "findings": [], "gate": "no_fp_default"}


def test_comments_and_strings_do_not_create_events():
    result = extract_pad002_facts('// cbc_decrypt(x); remove_padding(x);\nchar*s="validate_padding(x)";')
    assert result["outcome"] == "unknown"


def test_validation_success_branch_with_failing_else_dominates_release():
    source = '''
int f(unsigned char *buf) {
    cbc_decrypt(buf);
    if (validate_padding(buf) == PADDING_VALID) { return_plaintext(buf); }
    else { return -1; }
    return 0;
}
'''
    result = extract_pad002_facts(source)
    assert result["outcome"] == "satisfied"
    assert result["reason"] == "validation_guard_dominates_all_removal_and_release_paths"


def test_conditional_unsafe_release_is_unknown_not_confirmed():
    source = '''
int f(unsigned char *buf, int debug) {
    cbc_decrypt(buf);
    if (debug) return_plaintext(buf);
    return 0;
}
'''
    assert extract_pad002_facts(source)["outcome"] == "unknown"


@pytest.mark.parametrize("source", [
    "#define CHECK(x) validate_padding(x)\nint f(char*x){cbc_decrypt(x);CHECK(x);return_plaintext(x);}",
    "int helper(char*x){return validate_padding(x);}\nint f(char*x){cbc_decrypt(x);if(!helper(x))return -1;return_plaintext(x);}",
    "class X { int f(char*x){ cbc_decrypt(x); return_plaintext(x); } };",
])
def test_macro_interprocedural_and_cpp_remain_unknown(source):
    result = extract_pad002_facts(source)
    assert result["outcome"] == "unknown"
    assert result["enforcement"] == "none"


def test_loop_or_switch_with_relevant_events_remains_unknown():
    source = '''
int f(unsigned char *buf, int n) {
    cbc_decrypt(buf);
    while (n--) { if (validate_padding(buf)) return_plaintext(buf); }
    return 0;
}
'''
    assert extract_pad002_facts(source)["outcome"] == "unknown"


def test_unknown_helper_between_decrypt_and_release_blocks_unsafe_claim():
    source = '''
int f(unsigned char *buf) {
    cbc_decrypt(buf);
    custom_check_and_maybe_unpad(buf);
    return_plaintext(buf);
    return 0;
}
'''
    result = extract_pad002_facts(source)
    assert result["outcome"] == "unknown"
    assert result["reason"] == "unsupported_control_flow_or_interprocedural_event"


@pytest.mark.parametrize("condition", [
    "validate_padding(buf)",
    "!validate_padding(buf)",
    "validate_padding(buf) == 0",
    "validate_padding(buf) != 0",
    "validate_padding(buf) == 1",
])
def test_validator_name_or_numeric_return_polarity_never_proves_satisfied(condition):
    source = f'''
int f(unsigned char *buf) {{
    cbc_decrypt(buf);
    if ({condition}) return_plaintext(buf);
    return 0;
}}
'''
    result = extract_pad002_facts(source)
    assert result["outcome"] == "unknown"
    assert result["enforcement"] == "none"


@pytest.mark.parametrize("control", [
    "do { return_plaintext(buf); } while (retry);",
    "retry ? return_plaintext(buf) : remove_padding(buf);",
    "goto release; release: return_plaintext(buf);",
])
def test_do_while_ternary_and_goto_are_unknown(control):
    source = f"int f(char*buf,int retry){{cbc_decrypt(buf);{control}return 0;}}"
    assert extract_pad002_facts(source)["outcome"] == "unknown"


def test_multiple_sinks_require_guard_dominance_for_every_sink():
    satisfied = '''
int f(char *buf, int send) {
  cbc_decrypt(buf);
  if (validate_padding(buf) != PADDING_VALID) return -1;
  remove_padding(buf);
  if (send) return_plaintext(buf);
  return 0;
}'''
    assert extract_pad002_facts(satisfied)["outcome"] == "satisfied"
    unsafe = '''
int f(char *buf) {
  cbc_decrypt(buf); return_plaintext(buf);
  if (validate_padding(buf) == PADDING_VALID) remove_padding(buf);
  return 0;
}'''
    assert extract_pad002_facts(unsafe)["outcome"] != "satisfied"


def test_alias_and_release_wrapper_calls_are_unknown():
    source = '''
int f(char *buf, void (*release)(char*)) {
  cbc_decrypt(buf);
  if (validate_padding(buf) != PADDING_VALID) return -1;
  release(buf);
  return 0;
}'''
    assert extract_pad002_facts(source)["outcome"] == "unknown"
