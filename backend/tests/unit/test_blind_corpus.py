import copy
import json
from pathlib import Path
import zipfile

import pytest

from experiments.blind_corpus import (
    build_packets, extract_legacy_gt, neutralize_identifiers, scan_public_cues,
    write_packets,
)
from experiments.l1_snapshot import SnapshotError, build_snapshot
from experiments.labeling import validate_packet


PROVENANCE = {
    "git_commit": "a" * 40, "workspace_sha256": "b" * 64,
    "rules_sha256": "c" * 64, "prompts_sha256": "d" * 64,
}


def _snapshot(tmp_path: Path):
    root = tmp_path / "source"
    path = root / "set-1" / "violations_lea.c"
    path.parent.mkdir(parents=True)
    path.write_text(
        "int wrong_key_size(void) {\n"
        "  const char *s = \"ordinary\"; // [위반: AES-001]\n"
        "  return 7;\n}\n", encoding="utf-8",
    )
    # build_snapshot correctly rejects the annotated source, mirroring production:
    path.write_text("int wrong_key_size(void) {\n  return 7;\n}\n", encoding="utf-8")
    return build_snapshot(root, [{
        "file": "set-1/violations_lea.c", "rule_id": "AES-001", "line": 2,
        "detection_semantics": "prohibited_presence",
    }], set_id="real-sets-1", provenance=PROVENANCE)


def test_packet_neutralizes_path_and_identifier_and_separates_identity(tmp_path):
    snapshot = _snapshot(tmp_path)
    public, private = build_packets(snapshot, {
        "AES-001": {"description": "AES block size requirement", "kcmvp_ref": "FIPS 197"}
    }, salt=b"0123456789abcdef", legacy_gt={("set-1/violations_lea.c", "AES-001")})
    encoded = json.dumps(public, ensure_ascii=False)
    assert "violations" not in encoded and "wrong_key_size" not in encoded
    assert "frozen_candidate_id" not in encoded
    assert validate_packet(public)["candidate_count"] == 1
    assert set(public) == {"schema_version", "packet_id", "snapshot_id", "blinding", "randomization_sha256", "items"}
    assert private["occurrences"][0]["legacy_file_rule_label"] is True
    assert private["packet_id"] == public["packet_id"]


def test_identifier_renaming_does_not_change_string_or_comment_semantics():
    source = 'int bad_value = 1; const char *s = "bad_value"; /* bad_value */\n'
    neutral, mapping = neutralize_identifiers(source, b"0123456789abcdef")
    assert mapping["bad_value"] in neutral
    assert '"bad_value"' in neutral and "/* bad_value */" in neutral
    with pytest.raises(SnapshotError, match="cue remains"):
        scan_public_cues("src.c", neutral)


def test_zeroization_judgment_identifiers_are_neutralized():
    source = (
        "void com001_weak_zeroize(void) {}\n"
        "void no_zeroise(void) {}\n"
        "void unsafe_zeroize(void) {}\n"
    )
    neutral, mapping = neutralize_identifiers(source, b"0123456789abcdef")
    assert set(mapping) == {"com001_weak_zeroize", "no_zeroise", "unsafe_zeroize"}
    for original in mapping:
        assert original not in neutral
    scan_public_cues("src.c", neutral)


def test_v_marker_and_rule_heading_comments_are_removed_but_lines_remain():
    from experiments.blind_corpus import strip_answer_comments
    source = "/* [V1] 판정 근거 AES-001 */\nint a;\n"
    cleaned = strip_answer_comments(source)
    assert cleaned.count("\n") == source.count("\n")
    assert "V1" not in cleaned and "AES-001" not in cleaned


def test_packet_is_deterministic_and_occurrences_are_distinct(tmp_path):
    snapshot = _snapshot(tmp_path)
    second = copy.deepcopy(snapshot["candidates"][0])
    second["candidate_id"] += "-second"
    second["payload_sha256"] = snapshot["candidates"][0]["payload_sha256"]
    snapshot["candidates"].append(second)
    snapshot["l3_candidate_ids"].append(second["candidate_id"])
    # Hand modification invalidates the snapshot; use distinct payloads in a fresh build.
    source_root = tmp_path / "source2"
    path = source_root / "set-1" / "a.c"
    path.parent.mkdir(parents=True)
    path.write_text("int a;\n", encoding="utf-8")
    valid = build_snapshot(source_root, [
        {"file": "set-1/a.c", "rule_id": "AES-001", "line": 1, "message": "a"},
        {"file": "set-1/a.c", "rule_id": "AES-001", "line": 1, "message": "b"},
    ], set_id="x", provenance=PROVENANCE)
    one, _ = build_packets(valid, {}, salt=b"0123456789abcdef")
    two, _ = build_packets(valid, {}, salt=b"0123456789abcdef")
    ids = [row["candidate_id"] for row in one["items"]]
    assert one == two and len(set(ids)) == 2
    assert len({row["group_id"] for row in one["items"]}) == 1


def test_private_sidecar_cannot_be_written_in_repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    with pytest.raises(SnapshotError, match="outside"):
        write_packets(repo / "public.json", repo / "private.json", {}, {}, repo)


def test_safe_legacy_gt_zip_and_traversal_rejection(tmp_path):
    archive = tmp_path / "one.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("src/a.c", "int a; // [위반: AES-001]\n")
    assert extract_legacy_gt([archive]) == {("set-1/src/a.c", "AES-001")}
    unsafe = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(unsafe, "w") as handle:
        handle.writestr("../a.c", "int a;\n")
    with pytest.raises(SnapshotError, match="unsafe"):
        extract_legacy_gt([unsafe])
