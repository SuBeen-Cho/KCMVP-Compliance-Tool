import importlib.util
import zipfile
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "evaluate_real_sets.py"
SPEC = importlib.util.spec_from_file_location("evaluate_real_sets", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def test_ground_truth_annotations_are_removed_without_changing_lines():
    source = "int x; // [위반: LEA-010]\nint y; /* [위반: CBC-LEA-002] */\n"
    sanitized = MODULE.sanitize_gt_annotations(source)
    assert "LEA-010" not in sanitized
    assert "CBC-LEA-002" not in sanitized
    assert sanitized.count("\n") == source.count("\n")
    assert "위반" not in sanitized
    assert "int x;" in sanitized


def test_archive_relative_ids_do_not_merge_duplicate_basenames(tmp_path):
    archive = tmp_path / "sample.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("src/a/same.c", "// [위반: LEA-010]\n")
        zf.writestr("src/b/same.c", "// [위반: LEA-011]\n")

    gt = MODULE.extract_code_gt_from_zip(archive)

    assert set(gt) == {"a/same.c", "b/same.c"}


def test_evaluator_physically_sanitizes_input_and_counts_gt_free_file_as_fp(tmp_path, monkeypatch):
    archive = tmp_path / "sample.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("src/a.c", "int a; // [위반: LEA-010]\n")
        zf.writestr("src/sub/b.c", "int b;\n")

    observed = {"l2": False}

    def fake_l1(*, preprocess_result, **_kwargs):
        contents = [Path(item["path"]).read_text(encoding="utf-8") for item in preprocess_result["files"]]
        assert all("[위반:" not in content for content in contents)
        assert any(item["display"] == "sub/b.c" for item in preprocess_result["files"])
        # The production rule engine commonly emits paths relative to job root.
        return [{"file": "src/sub/b.c", "rule_id": "LEA-099", "line": 1}]

    def fake_l2(items):
        observed["l2"] = True
        return items

    monkeypatch.setattr(MODULE, "run_rule_engine", fake_l1)
    monkeypatch.setattr(MODULE, "run_l2_rag_context", fake_l2)
    monkeypatch.setattr(MODULE, "USE_L3", False)

    result = MODULE.evaluate_code_set(archive, "test")

    assert observed["l2"] is True
    assert result["FN"] == 1
    assert result["FP_extra"] == 1
    assert result["fp_list"][0]["candidate_id"] == "sub/b.c::LEA-099"


def test_cli_set_selection_and_output_parsing(tmp_path):
    args = MODULE.parse_args(["--no-l3", "--no-rag", "--code-only", "--sets", "1,3-4", "--output", str(tmp_path / "r.json")])
    assert MODULE.parse_set_selection(args.sets) == [1, 3, 4]
    assert args.no_l3 and args.no_rag
    assert args.code_only
    assert args.output == tmp_path / "r.json"
