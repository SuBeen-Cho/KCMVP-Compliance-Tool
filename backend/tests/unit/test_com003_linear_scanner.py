"""Linear COM-003 initializer scanner and finding-path regressions."""

import re
import time
from pathlib import Path

from app.services.rule_engine_service import (
    _apply_rule_to_file,
    _iter_com003_initializer_matches,
    load_ruleset,
)


def _spans(content: str):
    return [(m.start(), m.end()) for m in _iter_com003_initializer_matches(content)]


def _rule() -> dict:
    rules = load_ruleset(Path(__file__).resolve().parents[2] / "rules", "common")
    return next(rule for rule in rules if rule["id"] == "COM-003")


def test_seven_hex_literals_do_not_match_but_eight_do():
    seven = "unsigned char secret_key[7] = {0x1,0x2,0x3,0x4,0x5,0x6,0x7};"
    eight = "unsigned char secret_key[8] = {0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8};"
    assert _spans(seven) == []
    assert len(_spans(eight)) == 1


def test_nested_multiline_initializer_preserves_span_lines():
    content = """int before;
unsigned char secret_key[2][4] = {
  {0x1, 0x2, 0x3, 0x4},
  {0x5, 0x6, 0x7, 0x8}
};
"""
    match = list(_iter_com003_initializer_matches(content))[0]
    assert content.count("\n", 0, match.start()) + 1 == 2
    assert content.count("\n", 0, match.end()) + 1 == 5


def test_comments_strings_and_character_braces_do_not_change_depth():
    content = r'''const char *fake = "unsigned char key[8] = {0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8}";
/* unsigned char comment_key[8] = {0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8}; */
unsigned char secret_key[8] = {0x1,0x2,0x3,0x4, '}', 0x5,0x6,0x7,0x8};
'''
    assert len(_spans(content)) == 1


def test_small_input_spans_match_previous_regex_semantics():
    content = """static const uint32_t delta[2][4] = {
 {0x1,0x2,0x3,0x4}, {0x5,0x6,0x7,0x8}
};
"""
    old_spans = [(m.start(), m.end()) for m in re.compile(_rule()["pattern"]).finditer(content)]
    assert _spans(content) == old_spans


def test_sha_public_tables_are_filtered_and_hardcoded_key_is_reported(tmp_path: Path):
    content = """static const uint32_t SHA256_K[8] = {
0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8};



static const unsigned char secret_key[8] = {
0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18};
"""
    source = tmp_path / "crypto.c"
    source.write_text(content, encoding="utf-8")
    findings = _apply_rule_to_file(source, content, _rule(), tmp_path)
    assert len(findings) == 1
    assert findings[0]["line"] == 6
    assert findings[0]["end_line"] == 7


def test_large_sha_like_input_completes_under_upper_bound():
    row = ",".join(f"0x{i:08x}" for i in range(256))
    content = "\n".join(
        f"static const uint32_t SHA256_K_{n}[256] = {{{row}}};" for n in range(80)
    )
    started = time.perf_counter()
    matches = list(_iter_com003_initializer_matches(content))
    elapsed = time.perf_counter() - started
    assert len(matches) == 80
    assert elapsed < 1.0
