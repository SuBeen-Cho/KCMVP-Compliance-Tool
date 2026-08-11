from experiments.blind_views import (
    VIEWS, build_three_view_packets, minimal_source_id, strip_provenance_answer_comments,
)
from experiments.labeling import LabelingError, cross_view_report, validate_packet
import pytest
import hashlib
import json
import subprocess
import sys
from pathlib import Path


MANIFEST = {"schema_version": "1.0", "generator_id": "fixture-generator",
            "source_tree_sha256": "placeholder", "provenance_evidence": ["fixture declaration"],
            "comment_patterns": [r"\[\s*V\d+\s*\]", r"\[\s*위반\s*[:\]]"],
            "path_prefixes": ["violations_"], "identifier_patterns": [
                r"^wrong_", r"(?:^|_)weak_(?:rng|nonce|iv)(?:_|$)",
                r"(?:^|_)unseeded_rand(?:_|$)", r"(?:^|_)time_seeded(?:_|$)",
                r"(?:^|_)partial_(?:zeroize|cleanup)(?:_|$)",
            ],
            "name_evidence_rules": ["LEA-048"]}


def _equivalence(snapshot):
    import hashlib
    from experiments.l1_snapshot import canonical_bytes
    core = {"schema_version": "1.0", "snapshot_id": snapshot["snapshot_id"],
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
            "compile_preservation": {"passed": True, "regressions": [], "other_transitions": [],
                                     "both_failed_inconclusive": 0},
            "l1_occurrence_equivalence": {"passed": True, "missing": [], "added": []},
            "passed": True}
    return {"report_id": hashlib.sha256(canonical_bytes(core)).hexdigest(), **core}


def _build(snapshot, catalog):
    manifest = {**MANIFEST, "source_tree_sha256": snapshot["source_tree_sha256"]}
    return build_three_view_packets(snapshot, catalog, salt=b"0123456789abcdef",
                                    equivalence_report=_equivalence(snapshot),
                                    generator_manifest=manifest, excluded_rules=frozenset())


def _snapshot(tmp_path):
    # Import the canonical builder so this fixture always tracks the snapshot schema.
    from experiments.l1_snapshot import build_snapshot
    root = tmp_path / "source"
    (root / "set-1/src").mkdir(parents=True)
    (root / "set-1/src/violations_crypto.c").write_text(
        "// ordinary API comment\nvoid wrong_zeroize(void) { int weak_rng_key = 0; }\n")
    (root / "set-1/src/violations_LEA128ECBKAT.req.c").write_text(
        "// expected filename evidence\nint kat(void) { return 0; }\n")
    # The production snapshot contract rejects answer markers. Build the
    # immutable fixture with safe text, then restore raw artifacts to exercise
    # view rendering while retaining a valid snapshot identity.
    first = root / "set-1/src/violations_crypto.c"
    first.write_text("// ordinary API comment\nvoid wrong_zeroize(void) { int weak_rng_key = 0; }\n")
    second = root / "set-1/src/violations_LEA128ECBKAT.req.c"
    second.write_text("// filename evidence\nint kat(void) { return 0; }\n")
    provenance = {"git_commit": "a" * 40, "workspace_sha256": "b" * 64,
                  "rules_sha256": "c" * 64, "prompts_sha256": "d" * 64}
    return build_snapshot(root, [
        {"file": "set-1/src/violations_crypto.c", "rule_id": "COM-001", "line": 2,
         "detection_semantics": "prohibited_presence"},
        {"file": "set-1/src/violations_LEA128ECBKAT.req.c", "rule_id": "LEA-048", "line": 2,
         "detection_semantics": "prohibited_presence"},
    ], set_id="fixture", provenance=provenance)


def test_three_views_are_deterministic_and_join_the_same_occurrences(tmp_path):
    snapshot = _snapshot(tmp_path)
    catalog = {rule: {"description": f"requirement {rule}", "kcmvp_ref": "primary:1"}
               for rule in ("COM-001", "LEA-048")}
    first, sidecar = _build(snapshot, catalog)
    second, second_sidecar = _build(snapshot, catalog)
    assert first == second and sidecar == second_sidecar
    assert tuple(first) == VIEWS
    joined = [{item["candidate_id"] for item in first[view]["items"]} for view in VIEWS]
    assert joined[0] == joined[1] == joined[2]
    assert len({first[view]["randomization_sha256"] for view in VIEWS}) == len(VIEWS)
    assert "must be preregistered externally" in sidecar["order_strategy"]
    assert {row["occurrence_id"] for row in sidecar["occurrences"]} == joined[0]
    for view in VIEWS:
        assert validate_packet(first[view])["candidate_count"] == 2
        assert first[view]["view"] == view
        assert first[view]["purpose"] and first[view]["claim_limit"]


def test_minimal_view_preserves_normal_names_and_name_rule_filename(tmp_path):
    snapshot = _snapshot(tmp_path)
    packets, _ = _build(snapshot, {
            "COM-001": {"description": "zeroization", "kcmvp_ref": "p1"},
            "LEA-048": {"description": "filename", "kcmvp_ref": "p2"},
        })
    rows = {row["rule_id"]: row for row in packets["minimal_cue_controlled"]["items"]}
    assert "wrong_zeroize" not in rows["COM-001"]["source"]["code"]
    assert "weak_rng_key" not in rows["COM-001"]["source"]["code"]
    assert "ordinary API comment" in rows["COM-001"]["source"]["code"]
    assert "violations_LEA128ECBKAT.req.c" in rows["LEA-048"]["source"]["source_id"]
    assert "violations_crypto.c" not in rows["COM-001"]["source"]["source_id"]


def test_provenance_comment_removal_preserves_layout_and_ordinary_comments():
    source = ('const char *s = "// [V9]";\n// ordinary\\\n continued\n'
              '/* [V2]\n * 위반: COM-001 */\nint f(void);\n')
    rendered, hashes = strip_provenance_answer_comments(source)
    assert "ordinary" in rendered and '"// [V9]"' in rendered
    assert "[V2]" not in rendered and len(hashes) == 1
    assert rendered.count("\n") == source.count("\n")
    assert minimal_source_id("set/src/violations_x.c", "COM-001")[0].endswith("/x.c")
    assert minimal_source_id("set/src/violations_x.c", "LEA-048")[0].endswith("violations_x.c")


def test_line_comment_continues_when_any_backslash_precedes_newline():
    source = "// [V2] two backslashes \\\\\ncontinued answer marker\nint f(void);\n"
    rendered, hashes = strip_provenance_answer_comments(source)
    assert "continued answer marker" not in rendered
    assert len(hashes) == 1
    assert rendered.count("\n") == source.count("\n")


def test_exact_content_clones_share_a_group_across_set_paths(tmp_path):
    from experiments.l1_snapshot import build_snapshot
    root = tmp_path / "clones"
    for set_id in ("set-5", "set-6"):
        path = root / set_id / "src/lea.c"; path.parent.mkdir(parents=True)
        path.write_text("int lea(void) { return 0; }\n")
    provenance = {"git_commit": "a" * 40, "workspace_sha256": "b" * 64,
                  "rules_sha256": "c" * 64, "prompts_sha256": "d" * 64}
    snapshot = build_snapshot(root, [
        {"file": f"{set_id}/src/lea.c", "rule_id": "LEA-001", "line": 1,
         "detection_semantics": "prohibited_presence"}
        for set_id in ("set-5", "set-6")
    ], set_id="clone-fixture", provenance=provenance)
    packets, _ = _build(snapshot, {"LEA-001": {"description": "r", "kcmvp_ref": "p"}})
    for view in VIEWS:
        assert len({row["group_id"] for row in packets[view]["items"]}) == 1


def test_three_view_issuance_rejects_unbound_equivalence_or_manifest(tmp_path):
    from experiments.l1_snapshot import SnapshotError
    snapshot = _snapshot(tmp_path)
    catalog = {"COM-001": {"description": "r", "kcmvp_ref": "p"},
               "LEA-048": {"description": "r", "kcmvp_ref": "p"}}
    manifest = {**MANIFEST, "source_tree_sha256": snapshot["source_tree_sha256"]}
    report = _equivalence(snapshot); report["snapshot_id"] = "different"
    with pytest.raises(SnapshotError, match="frozen snapshot|hash"):
        build_three_view_packets(snapshot, catalog, salt=b"0123456789abcdef",
                                 equivalence_report=report, generator_manifest=manifest)
    manifest["source_tree_sha256"] = "0" * 64
    with pytest.raises(SnapshotError, match="source tree"):
        build_three_view_packets(snapshot, catalog, salt=b"0123456789abcdef",
                                 equivalence_report=_equivalence(snapshot),
                                 generator_manifest=manifest)


def test_cross_view_cli_joins_different_packet_ids_with_fake_labels(tmp_path):
    snapshot = _snapshot(tmp_path)
    packets, sidecar = _build(snapshot, {
        "COM-001": {"description": "r", "kcmvp_ref": "p"},
        "LEA-048": {"description": "r", "kcmvp_ref": "p"},
    })
    labels = {}
    for view, packet in packets.items():
        annotations = []
        for index, item in enumerate(packet["items"]):
            label = "violation" if view != "fully_opaque" or index else "insufficient_context"
            annotations.append({"candidate_id": item["candidate_id"], "label": label,
                                "confidence": 80, "requirement_applicability": "applicable",
                                "evidence": "disclosed code", "rationale": "fixture judgment",
                                "source_citations": [{"source_id": item["source"]["source_id"],
                                                      "line_start": item["source"]["line_start"],
                                                      "line_end": item["source"]["line_start"]}]})
        core = {"schema_version": "1.1", "packet_id": packet["packet_id"],
                "annotator": {"annotator_id": f"fixture-{view}", "annotator_type": "ai",
                              "model": {"provider": "test", "name": "fixed", "version": "1"}},
                "created_at": "2026-08-11T12:00:00+09:00", "annotations": annotations}
        labels[view] = {"label_batch_id": hashlib.sha256(json.dumps(
            core, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest(), **core}
    paths = {}
    for view in VIEWS:
        packet_path, label_path = tmp_path / f"{view}.packet.json", tmp_path / f"{view}.labels.json"
        packet_path.write_text(json.dumps(packets[view])); label_path.write_text(json.dumps(labels[view]))
        paths[view] = packet_path, label_path
    sidecar_path = tmp_path / "sidecar.json"; sidecar_path.write_text(json.dumps(sidecar))
    report_path = tmp_path / "cross.json"
    script = Path(__file__).resolve().parents[2] / "scripts/blind_labeling.py"
    command = [sys.executable, str(script), "cross-view"]
    for view in VIEWS: command.extend(["--packet", f"{view}={paths[view][0]}"])
    for view in VIEWS: command.extend(["--labels", f"{view}={paths[view][1]}"])
    command.extend(["--sidecar", str(sidecar_path), "--report", str(report_path)])
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    assert result.returncode == 0, result.stderr
    report = json.loads(report_path.read_text())
    assert report["occurrence_count"] == 2 and len(report["paired_table"]) == 2
    assert report["all_view_exact_count"] == 1
    assert any(row["labels"]["fully_opaque"] == "insufficient_context"
               for row in report["paired_table"])
    tampered = json.loads(json.dumps(sidecar))
    tampered["occurrences"].reverse()
    with pytest.raises(LabelingError, match="sidecar identity"):
        cross_view_report(packets, labels, tampered)


def test_three_view_builder_cli_rejects_input_output_collision(tmp_path):
    protected = tmp_path / "input.json"; protected.write_text("{}")
    script = Path(__file__).resolve().parents[2] / "scripts/build_blind_label_packet.py"
    result = subprocess.run([
        sys.executable, str(script), "--analysis-snapshot", str(protected),
        "--equivalence-report", str(protected), "--generator-manifest", str(protected),
        "--private-output", str(protected), "--three-view-output-dir", str(tmp_path / "views"),
    ], text=True, capture_output=True, check=False)
    assert result.returncode == 2
    assert "must all be distinct" in result.stderr
