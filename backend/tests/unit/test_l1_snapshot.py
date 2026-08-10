import copy
import json
from pathlib import Path
import subprocess
import sys

import pytest

from experiments.l1_snapshot import (
    SnapshotError,
    atomic_write_snapshot,
    build_snapshot,
    validate_snapshot,
)


def test_source_label_guard_does_not_confuse_c_pointer_named_fp(tmp_path):
    root = tmp_path / "sources"
    root.mkdir()
    (root / "a.c").write_text("int read(FILE *fp);\n", encoding="utf-8")
    snapshot = build_snapshot(root, [], set_id="set-1", provenance=PROVENANCE)
    assert snapshot["sources"][0]["source_id"] == "a.c"


PROVENANCE = {
    "git_commit": "a" * 40,
    "workspace_sha256": "b" * 64,
    "rules_sha256": "c" * 64,
    "prompts_sha256": "d" * 64,
}


def _sources(tmp_path: Path) -> Path:
    root = tmp_path / "sanitized"
    (root / "src").mkdir(parents=True)
    (root / "src" / "a.c").write_text("int a(void) { return 0; }\n", encoding="utf-8")
    return root


def test_snapshot_is_deterministic_and_uses_stable_occurrence_ids(tmp_path):
    root = _sources(tmp_path)
    candidates = [
        {"file": "src/a.c", "rule_id": "LEA-001", "line": 1, "message": "z"},
        {"file": "src/a.c", "rule_id": "LEA-001", "line": 1, "message": "a"},
    ]
    first = build_snapshot(root, candidates, set_id="set-1", provenance=PROVENANCE)
    second = build_snapshot(root, reversed(candidates), set_id="set-1", provenance=PROVENANCE)
    assert first == second
    assert first["l3_candidate_ids"] == [
        f"set-1::src/a.c::LEA-001::1::1::{first['candidates'][0]['payload_sha256']}",
        f"set-1::src/a.c::LEA-001::1::2::{first['candidates'][1]['payload_sha256']}",
    ]
    assert validate_snapshot(first)["candidate_count"] == 2
    assert "ground_truth" not in json.dumps(first)


@pytest.mark.parametrize(
    "content",
    ["int x; // [위반: LEA-001]\n", "int x; // [TP]\n", "// ground_truth\n"],
)
def test_source_label_markers_fail_before_write(tmp_path, content):
    root = tmp_path / "sanitized"
    root.mkdir()
    (root / "a.c").write_text(content, encoding="utf-8")
    output = tmp_path / "snapshot.json"
    with pytest.raises(SnapshotError, match="label marker"):
        snapshot = build_snapshot(root, [], set_id="set-1", provenance=PROVENANCE)
        atomic_write_snapshot(output, snapshot)
    assert not output.exists()


def test_candidate_ground_truth_and_absolute_path_fail_fast(tmp_path):
    root = _sources(tmp_path)
    with pytest.raises(SnapshotError, match="ground-truth"):
        build_snapshot(
            root,
            [{"file": "src/a.c", "rule_id": "X-1", "ground_truth": True}],
            set_id="set-1",
            provenance=PROVENANCE,
        )
    with pytest.raises(SnapshotError, match="workstation path"):
        build_snapshot(
            root,
            [{"file": "src/a.c", "rule_id": "X-1", "snippet": "/Users/alice/a.c"}],
            set_id="set-1",
            provenance=PROVENANCE,
        )


def test_validator_rejects_source_payload_and_candidate_id_tampering(tmp_path):
    root = _sources(tmp_path)
    snapshot = build_snapshot(
        root,
        [{"file": "src/a.c", "rule_id": "LEA-001", "line": 1}],
        set_id="set-1",
        provenance=PROVENANCE,
    )
    source_tamper = copy.deepcopy(snapshot)
    source_tamper["sources"][0]["content"] = "changed\n"
    with pytest.raises(SnapshotError, match="source hash"):
        validate_snapshot(source_tamper)
    id_tamper = copy.deepcopy(snapshot)
    id_tamper["candidates"][0]["candidate_id"] = "forged"
    with pytest.raises(SnapshotError, match="stable identity"):
        validate_snapshot(id_tamper)


def test_atomic_write_and_cli_validation(tmp_path):
    root = _sources(tmp_path)
    snapshot = build_snapshot(root, [], set_id="set-1", provenance=PROVENANCE)
    output = tmp_path / "snapshot.json"
    atomic_write_snapshot(output, snapshot)
    script = Path(__file__).resolve().parents[2] / "scripts" / "l1_snapshot.py"
    result = subprocess.run(
        [sys.executable, str(script), "validate", str(output)],
        check=False,
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0
    report = json.loads(result.stdout)
    assert report == {
        "candidate_count": 0,
        "snapshot_id": snapshot["snapshot_id"],
        "source_count": 1,
    }
    serialized = output.read_text(encoding="utf-8")
    assert str(tmp_path) not in serialized
    assert not list(tmp_path.glob(".snapshot.json.*.tmp"))


def test_export_cli_builds_and_validates_snapshot(tmp_path):
    root = _sources(tmp_path)
    candidates = tmp_path / "candidates.json"
    candidates.write_text(
        json.dumps([{"file": "src/a.c", "rule_id": "LEA-001", "line": 1}]),
        encoding="utf-8",
    )
    output = tmp_path / "exported.json"
    script = Path(__file__).resolve().parents[2] / "scripts" / "l1_snapshot.py"
    repo = Path(__file__).resolve().parents[3]
    result = subprocess.run(
        [
            sys.executable, str(script), "export", "--set-id", "set-1",
            "--source-root", str(root), "--candidates", str(candidates),
            "--output", str(output), "--repo", str(repo),
        ],
        check=False,
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["source_count"] == 1
    assert report["candidate_count"] == 1
    assert validate_snapshot(json.loads(output.read_text(encoding="utf-8"))) == report


def test_candidate_path_traversal_and_arbitrary_prefix_are_rejected(tmp_path):
    root = _sources(tmp_path)
    for unsafe in ("../../evil/src/a.c", "unrelated/src/a.c"):
        with pytest.raises(SnapshotError, match="candidate file"):
            build_snapshot(
                root, [{"file": unsafe, "rule_id": "X-1"}],
                set_id="set-1", provenance=PROVENANCE,
            )


def test_candidate_identity_is_bound_to_payload_hash(tmp_path):
    root = _sources(tmp_path)
    one = build_snapshot(
        root, [{"file": "src/a.c", "rule_id": "X-1", "message": "one"}],
        set_id="set-1", provenance=PROVENANCE,
    )
    two = build_snapshot(
        root, [{"file": "src/a.c", "rule_id": "X-1", "message": "two"}],
        set_id="set-1", provenance=PROVENANCE,
    )
    assert one["l3_candidate_ids"] != two["l3_candidate_ids"]


@pytest.mark.parametrize("level", ["top", "source", "candidate"])
def test_validator_rejects_unknown_fields(tmp_path, level):
    root = _sources(tmp_path)
    snapshot = build_snapshot(root, [], set_id="set-1", provenance=PROVENANCE)
    if level == "top":
        snapshot["unknown"] = "secret"
    elif level == "source":
        snapshot["sources"][0]["unknown"] = "secret"
    else:
        snapshot = build_snapshot(
            root, [{"file": "src/a.c", "rule_id": "X-1"}],
            set_id="set-1", provenance=PROVENANCE,
        )
        snapshot["candidates"][0]["unknown"] = "secret"
    with pytest.raises(SnapshotError, match="unsupported fields"):
        validate_snapshot(snapshot)


@pytest.mark.parametrize("key", ["groundTruth", "expected-label", "verdict", "answer"])
def test_normalized_label_keys_are_rejected(tmp_path, key):
    with pytest.raises(SnapshotError, match="ground-truth"):
        build_snapshot(
            _sources(tmp_path),
            [{"file": "src/a.c", "rule_id": "X-1", "ai_context": {key: "TP"}}],
            set_id="set-1", provenance=PROVENANCE,
        )


def test_source_identifier_named_ground_truth_is_not_a_label(tmp_path):
    root = tmp_path / "sanitized"
    root.mkdir()
    (root / "a.c").write_text("int ground_truth = 0;\n", encoding="utf-8")
    assert build_snapshot(root, [], set_id="set-1", provenance=PROVENANCE)["sources"]


def test_noncanonical_json_and_malformed_items_are_rejected(tmp_path):
    root = _sources(tmp_path)
    with pytest.raises(SnapshotError, match="canonical JSON"):
        build_snapshot(
            root, [{"file": "src/a.c", "rule_id": "X-1", "confidence": float("nan")}],
            set_id="set-1", provenance=PROVENANCE,
        )
    snapshot = build_snapshot(root, [], set_id="set-1", provenance=PROVENANCE)
    snapshot["sources"] = [None]
    with pytest.raises(SnapshotError, match="source contains"):
        validate_snapshot(snapshot)


def test_symlink_source_and_root_are_rejected_before_export(tmp_path):
    outside = tmp_path / "outside.c"
    outside.write_text("int external_secret;\n", encoding="utf-8")
    root = tmp_path / "sanitized"
    root.mkdir()
    (root / "linked.c").symlink_to(outside)
    with pytest.raises(SnapshotError, match="symlink sources"):
        build_snapshot(root, [], set_id="set-1", provenance=PROVENANCE)

    real_root = tmp_path / "real"
    real_root.mkdir()
    (real_root / "a.c").write_text("int a;\n", encoding="utf-8")
    linked_root = tmp_path / "linked-root"
    linked_root.symlink_to(real_root, target_is_directory=True)
    with pytest.raises(SnapshotError, match="symlink source roots"):
        build_snapshot(linked_root, [], set_id="set-1", provenance=PROVENANCE)


def test_validator_requires_canonical_source_order(tmp_path):
    root = _sources(tmp_path)
    (root / "src" / "b.c").write_text("int b;\n", encoding="utf-8")
    snapshot = build_snapshot(root, [], set_id="set-1", provenance=PROVENANCE)
    snapshot["sources"].reverse()
    with pytest.raises(SnapshotError, match="canonical order"):
        validate_snapshot(snapshot)


def test_git_commit_accepts_only_sha1_or_sha256_length(tmp_path):
    provenance = {**PROVENANCE, "git_commit": "a" * 41}
    with pytest.raises(SnapshotError, match="hashes are malformed"):
        build_snapshot(_sources(tmp_path), [], set_id="set-1", provenance=provenance)


@pytest.mark.parametrize(
    "marker", ["// FP: known issue\n", "// expected_label: violation\n", "// verdict: TP\n"],
)
def test_expanded_source_label_markers_are_rejected(tmp_path, marker):
    root = tmp_path / "sanitized"
    root.mkdir()
    (root / "a.c").write_text(marker, encoding="utf-8")
    with pytest.raises(SnapshotError, match="label marker"):
        build_snapshot(root, [], set_id="set-1", provenance=PROVENANCE)
