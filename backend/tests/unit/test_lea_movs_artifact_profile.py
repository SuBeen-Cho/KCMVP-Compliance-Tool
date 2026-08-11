"""LEA-048 MOVS artifact naming and applicability attack regressions."""

from pathlib import Path

from app.services.rule_engine_service import _apply_project_missing_rule, load_ruleset


RULE_ROOT = Path(__file__).resolve().parents[2] / "rules"


def _rule():
    return next(
        row for row in load_ruleset(RULE_ROOT, "algorithm", "lea")
        if row["id"] == "LEA-048"
    )


def _findings(tmp_path: Path, *names: str):
    files = [
        {"display": f"tests/vectors/{name}", "content": "KEY = 00\nPT = 00\n", "file_type": "test"}
        for name in names
    ]
    return _apply_project_missing_rule(_rule(), files, tmp_path, search_files=files)


def test_valid_kat_mmt_mct_req_rsp_fax_names_pass(tmp_path):
    names = ["LEA128ECBKAT.req", "LEA192CFB8MMT.rsp", "LEA256CFB128MCT.fax", "lea128ctrkat.REQ"]
    assert not _findings(tmp_path, *names)


def test_invalid_key_mode_test_type_and_suffix_are_candidates(tmp_path):
    names = ["LEA64ECBKAT.req", "LEA128GCMKAT.req", "LEA128ECBSAT.req", "LEA128ECBKAT.reqx"]
    findings = _findings(tmp_path, *names)
    assert [Path(row["file"]).name for row in findings] == names[:3]
    assert all(row["pattern_type"] == "artifact_filename" for row in findings)
    assert all(row["scope"] == "submission-package" for row in findings)


def test_absence_and_non_lea_exchange_artifacts_do_not_fire(tmp_path):
    assert not _findings(tmp_path)
    assert not _findings(tmp_path, "AES128ECBKAT.req", "notes.rsp", "LEA128ECBKAT.txt")


def test_file_content_comments_and_strings_cannot_change_filename_decision(tmp_path):
    files = [{
        "display": "tests/vectors/LEA999BADKAT.req",
        "content": '// LEA128ECBKAT.req\nconst char *s = "LEA128ECBKAT.req";\n',
        "file_type": "test",
    }]
    findings = _apply_project_missing_rule(_rule(), files, tmp_path, search_files=files)
    assert len(findings) == 1
    assert findings[0]["line"] is None
    assert findings[0]["snippet"] == "LEA999BADKAT.req"
