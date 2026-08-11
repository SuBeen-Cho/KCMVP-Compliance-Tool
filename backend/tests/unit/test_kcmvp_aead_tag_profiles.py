"""KCMVP GVI Part 2 AEAD tag-length profile regressions."""

from pathlib import Path

import pytest

from app.services.rule_engine_service import _apply_rule_to_file, load_ruleset


RULE_ROOT = Path(__file__).resolve().parents[2] / "rules"
FIXTURE_ROOT = Path(__file__).resolve().parents[1] / "fixtures"


def _rule(mode: str, rule_id: str) -> dict:
    rules = load_ruleset(RULE_ROOT, "mode", mode)
    return next(item for item in rules if item["id"] == rule_id)


def _findings(tmp_path: Path, mode: str, rule_id: str, source: str):
    path = tmp_path / f"{mode}.c"
    path.write_text(source, encoding="utf-8")
    return _apply_rule_to_file(path, source, _rule(mode, rule_id), tmp_path)


@pytest.mark.parametrize("value", [14, 15, 16])
def test_gcm_kcmvp_byte_boundaries_are_accepted(tmp_path: Path, value: int):
    assert not _findings(tmp_path, "gcm", "GCM-002", f"int gcm_tag_len_bytes = {value};")


@pytest.mark.parametrize("value", [13, 17, 4, 12])
def test_gcm_generic_or_out_of_range_byte_lengths_are_rejected(tmp_path: Path, value: int):
    findings = _findings(tmp_path, "gcm", "GCM-002", f"int gcm_tag_len_bytes = {value};")
    assert len(findings) == 1
    assert findings[0]["pattern_type"] == "regex"


@pytest.mark.parametrize("value", [112, 113, 127, 128])
def test_gcm_bit_boundaries_are_accepted(tmp_path: Path, value: int):
    assert not _findings(tmp_path, "gcm", "GCM-002", f"int gcm_tag_bits = {value};")


@pytest.mark.parametrize("value", [111, 129, 96])
def test_gcm_short_general_nist_tags_are_not_kcmvp_compliant(tmp_path: Path, value: int):
    assert len(_findings(tmp_path, "gcm", "GCM-002", f"int gcm_tag_bits = {value};")) == 1


@pytest.mark.parametrize("value", [14, 16])
def test_ccm_kcmvp_byte_set_is_accepted(tmp_path: Path, value: int):
    assert not _findings(tmp_path, "ccm", "CCM-003", f"int ccm_tag_len_bytes = {value};")


@pytest.mark.parametrize("value", [4, 6, 8, 10, 12, 15])
def test_ccm_general_standard_lengths_are_rejected_by_kcmvp_profile(tmp_path: Path, value: int):
    assert len(_findings(tmp_path, "ccm", "CCM-003", f"int ccm_tag_len_bytes = {value};")) == 1


@pytest.mark.parametrize("value", [112, 128])
def test_ccm_kcmvp_bit_set_is_accepted(tmp_path: Path, value: int):
    assert not _findings(tmp_path, "ccm", "CCM-003", f"int ccm_tag_bits = {value};")


@pytest.mark.parametrize("value", [96, 120, 127])
def test_ccm_non_profile_bit_lengths_are_rejected(tmp_path: Path, value: int):
    assert len(_findings(tmp_path, "ccm", "CCM-003", f"int ccm_tag_bits = {value};")) == 1


def test_unitless_lea_api_length_is_bytes(tmp_path: Path):
    assert not _findings(tmp_path, "gcm", "GCM-002", "int tag_len = 14;")
    assert len(_findings(tmp_path, "ccm", "CCM-003", "int t_len = 12;")) == 1


def test_normal_implementation_fixture_has_no_tag_profile_findings(tmp_path: Path):
    source = (FIXTURE_ROOT / "aead_kcmvp_tag_lengths_compliant.c").read_text(encoding="utf-8")
    for mode, rule_id in (("gcm", "GCM-002"), ("ccm", "CCM-003")):
        assert not _findings(tmp_path, mode, rule_id, source)


def test_unrelated_numeric_constants_are_not_guessed_as_tag_lengths(tmp_path: Path):
    source = "int rounds = 12; int buffer_len = 8; int auth_size = 4;"
    assert not _findings(tmp_path, "gcm", "GCM-002", source)
    assert not _findings(tmp_path, "ccm", "CCM-003", source)


def test_comments_and_string_literals_are_not_treated_as_configuration(tmp_path: Path):
    source = '''
// int gcm_tag_len_bytes = 12;
/* int ccm_tag_bits = 96; */
const char *diagnostic = "ccm_tag_len_bytes = 8";
'''
    assert not _findings(tmp_path, "gcm", "GCM-002", source)
    assert not _findings(tmp_path, "ccm", "CCM-003", source)
