"""COM-003 immutable declaration fact-index regression tests."""

from pathlib import Path

from app.services import ast_checker_service as ast_service
from app.services import rule_engine_service


def test_com003_index_preserves_tp_and_fp_verdicts():
    content = """
void use(const unsigned char *external_key) { (void)external_key; }
static const unsigned char public_table[8] = {1,2,3,4,5,6,7,8};
static const unsigned char secret_key[8] = {1,2,3,4,5,6,7,8};
"""
    facts = ast_service.build_com003_decl_fact_index(content, "sample.c")
    assert facts
    cases = (
        (2, "external_key", True),
        (3, "public_table", True),
        (4, "secret_key", False),
    )
    for line, name, expected in cases:
        uncached = ast_service.com003_libclang_is_fp(content, "sample.c", line, name)
        indexed = ast_service.com003_libclang_is_fp(
            content, "sample.c", line, name, fact_index=facts
        )
        assert uncached == indexed == expected


def test_com003_rule_builds_and_traverses_fact_index_once(monkeypatch, tmp_path: Path):
    content = """unsigned char secret_key[8] = {1,2,3,4,5,6,7,8};
unsigned char master_key[8] = {8,7,6,5,4,3,2,1};
"""
    source = tmp_path / "keys.c"
    source.write_text(content, encoding="utf-8")
    calls = {"build": 0, "query": 0}
    facts = (
        ("var", 1, "secret_key", True, 8, True),
        ("var", 2, "master_key", True, 8, True),
    )

    def fake_build(*_args, **_kwargs):
        calls["build"] += 1
        return facts

    original_query = ast_service.com003_libclang_is_fp

    def counted_query(*args, **kwargs):
        calls["query"] += 1
        return original_query(*args, **kwargs)

    monkeypatch.setattr(ast_service, "build_com003_decl_fact_index", fake_build)
    monkeypatch.setattr(ast_service, "com003_libclang_is_fp", counted_query)
    rule = {
        "id": "COM-003",
        "name": "hard-coded key",
        "pattern_type": "regex",
        "pattern": r"(?m)^unsigned char\s+\w+\[8\]\s*=\s*\{[^}]+\};",
        "severity": "high",
    }
    findings = rule_engine_service._apply_rule_to_file(
        source, content, rule, tmp_path, stripped_content=content
    )
    assert len(findings) == 2
    assert calls == {"build": 1, "query": 2}


def test_com003_empty_fact_index_is_cached_for_all_matches(monkeypatch, tmp_path: Path):
    content = """unsigned char secret_key[8] = {1,2,3,4,5,6,7,8};
unsigned char master_key[8] = {8,7,6,5,4,3,2,1};
"""
    source = tmp_path / "keys.c"
    source.write_text(content, encoding="utf-8")
    builds = 0

    def empty_build(*_args, **_kwargs):
        nonlocal builds
        builds += 1
        return ()

    monkeypatch.setattr(ast_service, "build_com003_decl_fact_index", empty_build)
    rule = {
        "id": "COM-003", "name": "hard-coded key", "pattern_type": "regex",
        "pattern": r"(?m)^unsigned char\s+\w+\[8\]\s*=\s*\{[^}]+\};",
    }
    findings = rule_engine_service._apply_rule_to_file(
        source, content, rule, tmp_path, stripped_content=content
    )
    assert len(findings) == 2
    assert builds == 1
