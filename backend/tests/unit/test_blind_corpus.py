import copy
import hashlib
import json
from pathlib import Path
import re
import zipfile

import pytest

from experiments.blind_corpus import (
    build_packets, extract_legacy_gt, neutralize_identifiers, scan_public_cues,
    write_packets,
)
from experiments.l1_snapshot import SnapshotError, build_snapshot, canonical_bytes
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


def _equivalence(snapshot):
    core = {
        "schema_version": "1.0", "snapshot_id": snapshot["snapshot_id"],
        "source_count": len(snapshot["sources"]),
        "frozen_candidate_count": len(snapshot["candidates"]),
        "candidate_count_expected": len(snapshot["candidates"]),
        "candidate_count_observed": len(snapshot["candidates"]),
        "token_equivalence": {"passed": True, "failures": []},
        "identifier_semantics": {"passed": True, "renamed_in_analysis": 0, "risks": []},
        "display_blinding": {"passed": True, "semantic_equivalence_claimed": False,
                             "unsafe_contexts_excluded": 0, "risks": []},
        "detector_blindness": {"passed": True, "semantic_equivalence_claimed": False,
                               "missing_under_opaque_view": 0, "added_under_opaque_view": 0,
                               "affected_rules": [], "unexcluded_affected_rules": []},
        "preregistered_exclusions": {},
        "preprocess_equivalence": {"passed": True, "failures": [], "both_failed_inconclusive": 0},
        "compile_preservation": {"passed": True, "regressions": [], "other_transitions": [], "both_failed_inconclusive": 0},
        "l1_occurrence_equivalence": {"passed": True, "missing": [], "added": []},
        "passed": True,
    }
    return {"report_id": hashlib.sha256(canonical_bytes(core)).hexdigest(), **core}


def test_packet_neutralizes_path_and_identifier_and_separates_identity(tmp_path):
    snapshot = _snapshot(tmp_path)
    public, private = build_packets(snapshot, {
        "AES-001": {"description": "AES block size requirement", "kcmvp_ref": "FIPS 197"}
    }, salt=b"0123456789abcdef", equivalence_report=_equivalence(snapshot),
       legacy_gt={("set-1/violations_lea.c", "AES-001")})
    encoded = json.dumps(public, ensure_ascii=False)
    assert "violations" not in encoded and "wrong_key_size" not in encoded
    assert "frozen_candidate_id" not in encoded
    assert validate_packet(public)["candidate_count"] == 1
    assert set(public) == {"schema_version", "packet_id", "snapshot_id", "view", "purpose",
                           "claim_limit", "blinding", "randomization_sha256", "items"}
    assert private["legacy_file_rule_labels"] == [{
        "original_source_id": "set-1/violations_lea.c", "rule_id": "AES-001",
        "label_precision": "file_rule_only; independent occurrence review required",
    }]
    assert "legacy_file_rule_label" not in private["occurrences"][0]
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


def test_spliced_line_comment_is_removed_through_next_physical_line():
    from experiments.blind_corpus import strip_answer_comments
    source = "int a; // answer \\\ncontinued cue\nint b;\n"
    cleaned = strip_answer_comments(source)
    assert "answer" not in cleaned and "continued cue" not in cleaned
    assert "int a;" in cleaned and "int b;" in cleaned
    assert cleaned.count("\n") == source.count("\n")


def test_all_comments_are_removed_but_strings_and_line_count_are_preserved():
    from experiments.blind_corpus import strip_answer_comments
    source = 'int/* harmless note */x; // TODO missing cleanup\nchar *s = "// literal";\n'
    cleaned = strip_answer_comments(source)
    assert "harmless note" not in cleaned and "TODO" not in cleaned
    assert '"// literal"' in cleaned
    assert cleaned.count("\n") == source.count("\n")
    assert re.search(r"int\s+x", cleaned)


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
    one, _ = build_packets(valid, {}, salt=b"0123456789abcdef", equivalence_report=_equivalence(valid))
    two, _ = build_packets(valid, {}, salt=b"0123456789abcdef", equivalence_report=_equivalence(valid))
    ids = [row["candidate_id"] for row in one["items"]]
    assert one == two and len(set(ids)) == 2
    assert len({row["group_id"] for row in one["items"]}) == 1


def test_required_absence_gets_bounded_neutral_cross_file_evidence(tmp_path):
    root = tmp_path / "source"
    (root / "set-1" / "src").mkdir(parents=True)
    (root / "set-1" / "src" / "module.c").write_text(
        "int use_key(unsigned char *key) { return key[0]; }\n", encoding="utf-8",
    )
    (root / "set-1" / "src" / "helper.c").write_text(
        "#include <string.h>\nvoid clear_key(unsigned char *key) { memset(key, 0, 16); }\n",
        encoding="utf-8",
    )
    snapshot = build_snapshot(root, [{
        "file": "set-1/src/module.c", "rule_id": "COM-001", "line": None,
        "message": "detector prose must not drive retrieval", "scope": "project",
        "pattern_type": "missing", "detection_semantics": "required_absence",
    }], set_id="expanded", provenance=PROVENANCE)
    catalog = {"COM-001": {"description": "비밀키 메모리 제거", "kcmvp_ref": "7.1"}}
    public, private = build_packets(snapshot, catalog, salt=b"0123456789abcdef", equivalence_report=_equivalence(snapshot))
    source = public["items"][0]["source"]
    encoded = json.dumps(public, ensure_ascii=False)
    assert source["context"].startswith("Requirement-keyed neutral evidence bundle")
    assert "memset" in source["code"] and "evidence_" in source["code"]
    assert "module.c" not in encoded and "helper.c" not in encoded
    assert "detector prose" not in encoded
    assert len(source["code"].splitlines()) <= 240
    evidence = private["occurrences"][0]["evidence_line_mappings"]
    assert len(evidence) == len(source["code"].splitlines())
    assert any(row["original_source_id"].endswith("helper.c") for row in evidence)
    assert "evidence_line_mappings" not in encoded
    validate_packet(public)


def test_expanded_retrieval_is_deterministic_and_ignores_detector_message(tmp_path):
    root = tmp_path / "source"
    (root / "set-1").mkdir(parents=True)
    (root / "set-1" / "a.c").write_text("void clear_key(char *key) { key[0] = 0; }\n", encoding="utf-8")
    base = {"file": "set-1/a.c", "rule_id": "COM-001", "scope": "project",
            "pattern_type": "missing", "detection_semantics": "required_absence"}
    first = build_snapshot(root, [{**base, "message": "first"}], set_id="one", provenance=PROVENANCE)
    second = build_snapshot(root, [{**base, "message": "entirely different"}], set_id="two", provenance=PROVENANCE)
    catalog = {"COM-001": {"description": "비밀키 메모리 제거", "kcmvp_ref": "7.1"}}
    packet_a, _ = build_packets(first, catalog, salt=b"0123456789abcdef", equivalence_report=_equivalence(first))
    packet_b, _ = build_packets(second, catalog, salt=b"0123456789abcdef", equivalence_report=_equivalence(second))
    assert packet_a["items"][0]["source"] == packet_b["items"][0]["source"]
    again, _ = build_packets(first, catalog, salt=b"0123456789abcdef", equivalence_report=_equivalence(first))
    assert packet_a == again


def test_groups_are_decimal_cue_free_and_cross_rule_context_is_grouped(tmp_path):
    root = tmp_path / "source"
    (root / "set-1").mkdir(parents=True)
    (root / "set-1" / "a.c").write_text("int value = 1;\n", encoding="utf-8")
    candidates = [
        {"file": "set-1/a.c", "rule_id": rule, "line": 1,
         "detection_semantics": "prohibited_presence"}
        for rule in ("AES-001", "AES-002")
    ]
    snapshot = build_snapshot(root, candidates, set_id="groups", provenance=PROVENANCE)
    public, _ = build_packets(snapshot, {
        "AES-001": {"description": "same", "kcmvp_ref": "one"},
        "AES-002": {"description": "same", "kcmvp_ref": "two"},
    }, salt=b"0123456789abcdef", equivalence_report=_equivalence(snapshot))
    groups = [item["group_id"] for item in public["items"]]
    assert len(set(groups)) == 1
    assert all(group.startswith("cluster_") and group[8:].isdigit() for group in groups)


def test_detector_specific_requirement_identifier_is_neutralized(tmp_path):
    snapshot = _snapshot(tmp_path)
    public, private = build_packets(snapshot, {
        "AES-001": {"description": "Reject wrong_key_size helper", "kcmvp_ref": "FIPS 197"}
    }, salt=b"0123456789abcdef", equivalence_report=_equivalence(snapshot))
    encoded = json.dumps(public, ensure_ascii=False)
    assert "wrong_key_size" not in encoded
    assert private["occurrences"][0]["requirement_identifiers"]


def test_requirement_outcome_wording_is_rewritten_to_normative_form(tmp_path):
    snapshot = _snapshot(tmp_path)
    public, _ = build_packets(snapshot, {
        "AES-001": {"description": "이 조건 위반을 검사한다.", "kcmvp_ref": "FIPS 197"}
    }, salt=b"0123456789abcdef", equivalence_report=_equivalence(snapshot))
    text = public["items"][0]["requirement"]["text"]
    assert "위반" not in text and "비준수 조건" in text


def test_dual_layer_packet_makes_no_display_compile_equivalence_claim(tmp_path):
    snapshot = _snapshot(tmp_path)
    report = _equivalence(snapshot)
    public, private = build_packets(
        snapshot, {}, salt=b"0123456789abcdef", equivalence_report=report,
    )
    assert public["blinding"]["display_alias_compile_equivalence_claimed"] is False
    assert private["equivalence_report_sha256"] == hashlib.sha256(canonical_bytes(report)).hexdigest()
    assert validate_packet(public)["candidate_count"] == 1


def test_semantically_risky_display_context_is_withheld(tmp_path):
    root = tmp_path / "source"
    (root / "set-1").mkdir(parents=True)
    (root / "set-1" / "a.c").write_text(
        'void wrong_api(void) { puts(__func__); }\n', encoding="utf-8",
    )
    snapshot = build_snapshot(root, [{
        "file": "set-1/a.c", "rule_id": "AES-001", "line": 1,
        "detection_semantics": "prohibited_presence",
    }], set_id="risky-display", provenance=PROVENANCE)
    public, private = build_packets(
        snapshot, {}, salt=b"0123456789abcdef", equivalence_report=_equivalence(snapshot),
    )
    source = public["items"][0]["source"]
    assert source["context"].startswith("Insufficient context")
    assert "wrong_api" not in source["code"] and "__func__" not in source["code"]
    assert private["occurrences"][0]["display_context_withheld"] is True


def test_private_sidecar_cannot_be_written_in_repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    with pytest.raises(SnapshotError, match="outside"):
        write_packets(repo / "public.json", repo / "private.json", {}, {}, repo)


def test_packet_rejects_tampered_or_failed_equivalence_report(tmp_path):
    snapshot = _snapshot(tmp_path)
    report = _equivalence(snapshot)
    report["candidate_count_observed"] = 0
    with pytest.raises(SnapshotError, match="hash"):
        build_packets(snapshot, {}, salt=b"0123456789abcdef", equivalence_report=report)
    report = _equivalence(snapshot)
    report["passed"] = False
    core = {key: value for key, value in report.items() if key != "report_id"}
    report["report_id"] = hashlib.sha256(canonical_bytes(core)).hexdigest()
    with pytest.raises(SnapshotError, match="did not pass"):
        build_packets(snapshot, {}, salt=b"0123456789abcdef", equivalence_report=report)


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
