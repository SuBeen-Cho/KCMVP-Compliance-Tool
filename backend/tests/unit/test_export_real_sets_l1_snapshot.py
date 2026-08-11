import importlib.util
import json
from pathlib import Path
import zipfile

import pytest

from experiments.l1_snapshot import SnapshotError, validate_snapshot


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "export_real_sets_l1_snapshot.py"
SPEC = importlib.util.spec_from_file_location("export_real_sets_l1_snapshot", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def _set_zip(root: Path, number: int, member: str = "src/a.c") -> Path:
    archive = root / f"세트 {number}" / "kcmvp_combined.zip"
    archive.parent.mkdir(parents=True)
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr(
            member,
            "/* 이 패턴은 위반 정답임 */\nint a(void) { return 0; } // [위반: AES-001]\n",
        )
    return archive


def test_export_sanitizes_labels_and_freezes_combined_sets(tmp_path, monkeypatch):
    base = tmp_path / "sets"
    _set_zip(base, 1)
    _set_zip(base, 2)
    observed = []

    def fake_engine(*, preprocess_result, **kwargs):
        item = preprocess_result["files"][0]
        observed.append(item["content"])
        return [{
            "file": item["path"], "rule_id": "AES-001", "line": 2,
            "confidence": 70, "message": "unsafe AES use", "ai_context": "위반 정답",
        }]

    monkeypatch.setattr(MODULE, "build_manifest", lambda *args, **kwargs: {
        "code": {"commit": "a" * 40, "workspace_sha256": "b" * 64},
        "artifacts": {"rules_tree_sha256": "c" * 64, "prompts_sha256": "d" * 64},
    })
    output = tmp_path / "snapshot.json"
    report = MODULE.export_snapshot(base, [1, 2], output, engine=fake_engine)
    snapshot = json.loads(output.read_text(encoding="utf-8"))
    assert report["candidate_count"] == 2
    assert all("위반" not in content for content in observed)
    assert all("ai_context" not in item["payload"] for item in snapshot["candidates"])
    assert [item["source_id"] for item in snapshot["sources"]] == [
        "set-1/src/a.c", "set-2/src/a.c",
    ]
    validate_snapshot(snapshot)


def test_export_rejects_archive_traversal_before_engine(tmp_path):
    base = tmp_path / "sets"
    _set_zip(base, 1, "../escape.c")
    called = []
    with pytest.raises(SnapshotError, match="unsafe"):
        MODULE.export_snapshot(base, [1], tmp_path / "snapshot.json", engine=lambda **kw: called.append(kw))
    assert called == []


def test_comment_sanitizer_removes_all_comments_and_preserves_lines():
    raw = (
        "/* ordinary implementation note */\n"
        "int a = 1; // [위반: AES-001]\n"
        "/* expected verdict: false positive\nsecond answer line */\n"
        "int b = 2; // keep this rationale\n"
        "int c = 3; // 정답 패턴\n"
    )
    cleaned = MODULE._strip_answer_comments_preserve_lines(raw)
    assert "ordinary implementation note" not in cleaned
    assert "keep this rationale" not in cleaned
    assert "위반" not in cleaned and "expected verdict" not in cleaned and "정답" not in cleaned
    assert cleaned.count("\n") == raw.count("\n")


def test_export_decodes_cp949_without_loss(tmp_path, monkeypatch):
    base = tmp_path / "sets"
    archive = base / "세트 1" / "kcmvp_combined.zip"
    archive.parent.mkdir(parents=True)
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("src/a.h", "/* 일반 구현 설명 */\nint a;\n".encode("cp949"))
    observed = []

    def engine(*, preprocess_result, **kwargs):
        observed.append(preprocess_result["files"][0]["content"])
        return []

    monkeypatch.setattr(MODULE, "build_manifest", lambda *args, **kwargs: {
        "code": {"commit": "a" * 40, "workspace_sha256": "b" * 64},
        "artifacts": {"rules_tree_sha256": "c" * 64, "prompts_sha256": "d" * 64},
    })
    MODULE.export_snapshot(base, [1], tmp_path / "snapshot.json", engine=engine)
    assert "일반 구현 설명" not in observed[0]
    assert "int a;" in observed[0]
