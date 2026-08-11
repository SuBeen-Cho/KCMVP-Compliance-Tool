from pathlib import Path

from experiments.blind_equivalence import (
    identifier_semantic_risks, run_equivalence_gate, token_equivalence,
)
from experiments.l1_snapshot import build_snapshot


PROVENANCE = {
    "git_commit": "a" * 40, "workspace_sha256": "b" * 64,
    "rules_sha256": "c" * 64, "prompts_sha256": "d" * 64,
}


def _snapshot(tmp_path: Path):
    root = tmp_path / "sources"
    path = root / "set-1" / "wrong_sample.c"
    path.parent.mkdir(parents=True)
    path.write_text("static int wrong_value(void) { return 1; }\n", encoding="utf-8")
    return build_snapshot(root, [{
        "file": "set-1/wrong_sample.c", "rule_id": "T-001", "line": 1,
    }], set_id="test", provenance=PROVENANCE)


def test_token_equivalence_allows_only_declared_identifier_renaming():
    assert token_equivalence("int bad = 1;", "int id_123 = 1;", {"bad": "id_123"})
    assert not token_equivalence("int bad = 1;", "int id_123 = 2;", {"bad": "id_123"})


def test_identifier_risk_catches_preprocessor_dynamic_symbol_and_external_abi():
    source = '#define S(x) #x\nvoid *p = dlsym(h, "bad");\nint bad(void) { return 1; }\n'
    risks = identifier_semantic_risks(source, {"bad": "id_1"})
    reasons = {row["reason"] for row in risks}
    assert {"dynamic_symbol_string", "external_function_abi"} <= reasons


def test_answer_comment_removal_keeps_token_separator():
    from experiments.blind_corpus import strip_answer_comments
    cleaned = strip_answer_comments("int/* [V1] judgement */value;\n")
    assert token_equivalence("int value;\n", cleaned, {})


def test_gate_passes_for_semantics_preserving_neutralization(tmp_path):
    snapshot = _snapshot(tmp_path)

    def engine(**kwargs):
        entry = kwargs["preprocess_result"]["files"][0]
        return [{"file": entry["display"], "rule_id": "T-001", "line": 1}]

    report = run_equivalence_gate(
        snapshot, salt=b"0123456789abcdef", rules_dir=tmp_path,
        engine=engine, compiler="clang",
    )
    assert report["passed"]


def test_gate_blocks_changed_l1_occurrence(tmp_path):
    snapshot = _snapshot(tmp_path)
    report = run_equivalence_gate(
        snapshot, salt=b"0123456789abcdef", rules_dir=tmp_path,
        engine=lambda **kwargs: [], compiler="clang",
    )
    assert not report["passed"]
    assert report["l1_occurrence_equivalence"]["missing"][0]["rule_id"] == "T-001"
