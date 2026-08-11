"""KCMVP CMAC tag-length profile and HIGHT exception regressions."""

from pathlib import Path

import pytest

from app.services.rule_engine_service import _apply_rule_to_file, load_ruleset

RULE_ROOT = Path(__file__).resolve().parents[2] / "rules"


def _findings(tmp_path: Path, source: str, filename: str = "cmac_impl.c"):
    rule = next(r for r in load_ruleset(RULE_ROOT, "mode", "cmac") if r["id"] == "CMAC-004")
    path = tmp_path / filename
    path.write_text(source, encoding="utf-8")
    return _apply_rule_to_file(path, source, rule, tmp_path)


@pytest.mark.parametrize("algorithm", ["aria", "seed", "lea"])
@pytest.mark.parametrize("value", [112, 120, 128])
def test_128_bit_ciphers_accept_kcmvp_bit_range(tmp_path, algorithm, value):
    assert not _findings(tmp_path, f"int {algorithm}_cmac_tag_bits = {value};")


@pytest.mark.parametrize("value", [64, 96, 111, 129])
def test_128_bit_ciphers_reject_non_profile_bits(tmp_path, value):
    assert len(_findings(tmp_path, f"int lea_cmac_tag_bits = {value};")) == 1


def test_hight_explicit_64_bit_exception(tmp_path):
    assert not _findings(tmp_path, "int hight_cmac_tag_bits = 64;")
    assert not _findings(tmp_path, "int hight_cmac_tag_len_bytes = 8;")
    assert len(_findings(tmp_path, "int hight_cmac_tag_bits = 112;")) == 1
    assert len(_findings(tmp_path, "int hight_cmac_tag_len_bytes = 16;")) == 1


def test_unit_algorithm_context_and_mixed_module_boundary(tmp_path):
    assert not _findings(tmp_path, "void lea_cmac(void){}\nint cmac_tag_len_bytes = 14;")
    assert len(_findings(tmp_path, "void hight_cmac(void){}\nint cmac_tag_len_bytes = 14;")) == 1
    mixed = "void lea_cmac(void){} void hight_cmac(void){} int cmac_tag_bits = 96;"
    assert not _findings(tmp_path, mixed)


def test_comments_strings_and_unrelated_constants_are_ignored(tmp_path):
    source = '''
// int hight_cmac_tag_bits = 112;
const char *s = "lea_cmac_tag_bits = 64";
int block_bits = 64;
'''
    assert not _findings(tmp_path, source)


@pytest.mark.parametrize("name", ["lea_cmac_tag_len", "lea_cmac_mac_len", "cmac_tag_len"])
def test_unitless_length_is_unknown_and_abstains(tmp_path, name):
    assert not _findings(tmp_path, f"int {name} = 120;")


def test_literal_macro_and_enum_are_checked_but_runtime_values_abstain(tmp_path):
    assert len(_findings(tmp_path, "#define LEA_CMAC_TAG_BITS 64\n")) == 1
    assert len(_findings(tmp_path, "enum { SEED_CMAC_MAC_LEN_BYTES = 8 };")) == 1
    assert not _findings(tmp_path, "int lea_cmac_tag_bits = configured_tag_bits;")
    assert not _findings(tmp_path, "#define LEA_CMAC_TAG_BITS CONFIGURED_BITS\n")


def test_mixed_module_checks_explicit_algorithm_but_abstains_unqualified(tmp_path):
    source = "int lea_cmac_tag_bits = 64; int hight_cmac_tag_bits = 112;"
    findings = _findings(tmp_path, source)
    assert len(findings) == 2
    assert [finding["line"] for finding in findings] == [1, 1]
    assert not _findings(
        tmp_path,
        "void lea_cmac(void){} void hight_cmac(void){} int cmac_tag_bits = 96;",
    )


@pytest.mark.parametrize("filename", ["violations_cmac.c", "hight_cmac.c", "safe.c"])
def test_filename_does_not_change_an_explicit_lea_decision(tmp_path, filename):
    assert len(_findings(tmp_path, "int lea_cmac_tag_bits = 64;", filename)) == 1


def test_multiline_match_preserves_exact_source_span(tmp_path):
    findings = _findings(tmp_path, "int lea_cmac_tag_bits\n    = 64;\n")
    assert len(findings) == 1
    assert findings[0]["line"] == 1
    assert findings[0]["end_line"] == 2


def test_identifier_substrings_and_preprocessor_diagnostics_do_not_match(tmp_path):
    source = '''
int mylea_cmac_tag_bits = 64;
int lea_cmac_tag_bits_backup = 64;
#define MESSAGE "hight_cmac_tag_bits = 112"
'''
    assert not _findings(tmp_path, source)
