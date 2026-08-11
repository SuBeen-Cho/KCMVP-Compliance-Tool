import copy
import hashlib
import json

import pytest

from experiments.calibration import calibrate, grouped_dev_heldout_split, validate_calibration_dataset
from experiments.score_only_evaluation import (
    EvaluationJoinError, build_calibration_proxy, build_test_retest_proxy_gt,
    migrate_v15_sidecar_group_ids, paired_binary_report, score_artifact_from_l3_result,
    score_artifact_from_l3_results,
)
from experiments.labeling import build_packet


def _hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _fixtures():
    occurrences = []
    for i in range(8):
        occurrences.append({"occurrence_id": f"o{i}", "frozen_candidate_id": f"f{i}",
                            "group_id": f"clone-{i // 2}", "x": i})
    side_core = {"schema_version": "1.1", "snapshot_id": "snap",
                 "equivalence_report_sha256": "a" * 64, "generator_manifest_sha256": "b" * 64,
                 "order_strategy": "sealed", "packet_ids": {}, "occurrences": occurrences}
    sidecar = {"sidecar_id": _hash(side_core), **side_core}
    gt_core = {"schema_version": "1.0", "scope": "ai_adjudicated_proxy_gt",
               "ground_truth_basis": "same_model_temperature0_test_retest_proxy_not_external_expert_gt",
               "claim_limit": "Same-model test-retest proxy; not independent annotators",
               "source_label_batch_ids": ["a", "b"],
               "rows": [{"occurrence_id": f"o{i}",
                         "label": ("insufficient_context" if i == 6 else
                                   "not_applicable" if i == 7 else
                                   "violation" if i % 2 else "non_violation"),
                         "adjudication": "majority"} for i in range(8)]}
    gt = {"gt_id": _hash(gt_core), **gt_core}
    scores = []
    for condition, delta in (("rag", 5), ("no_rag", -5)):
        rows = [{"frozen_candidate_id": f"f{i}", "repeat": 0,
                 "initial": (80 if i % 2 else 20) + delta, "rejudge": None,
                 "score_provenance": "prompt_contract_confidence_proxy_not_calibrated_probability"}
                for i in range(8)]
        coverage = {"universe_ids": [f"f{i}" for i in range(8)],
                    "selected_ids": [f"f{i}" for i in range(8)],
                    "repeat_dispositions": [{"repeat": 0,
                        "scored_ids": [f"f{i}" for i in range(8)], "unresolved_ids": []}]}
        core = {"schema_version": "1.2", "scope": "score_only_system_output",
                "snapshot_id": "snap", "condition": condition,
                "score_semantics": "violation_probability", "coverage": coverage, "rows": rows}
        scores.append({"artifact_id": _hash(core), **core})
    return sidecar, gt, scores


def test_posthoc_join_builds_proxy_and_clone_groups_never_cross_split():
    dataset = build_calibration_proxy(*_fixtures())
    rows = validate_calibration_dataset(dataset)
    dev, heldout = grouped_dev_heldout_split(rows, heldout_fraction=.5)
    assert {r["group_id"] for r in dev}.isdisjoint({r["group_id"] for r in heldout})
    assert dataset["ground_truth_basis"].startswith("same_model")
    assert dataset["eligibility"]["sealed_total"] == 8
    assert dataset["eligibility"]["binary_eligible"] == 6
    assert dataset["eligibility"]["common_scored_binary"]["count"] == 6
    assert dataset["eligibility"]["excluded_by_label"] == {
        "insufficient_context": 1, "not_applicable": 1}
    report = paired_binary_report(dataset)
    assert report["paired_n"] == 6


def test_score_artifact_rejects_ground_truth_and_bad_provenance():
    sidecar, gt, scores = _fixtures()
    bad = copy.deepcopy(scores[0])
    bad["ground_truth"] = True
    with pytest.raises(EvaluationJoinError, match="closed schema"):
        build_calibration_proxy(sidecar, gt, [bad])
    bad = copy.deepcopy(scores[0])
    bad["rows"][0]["score_provenance"] = "calibrated_probability"
    core = {k: v for k, v in bad.items() if k != "artifact_id"}
    bad["artifact_id"] = _hash(core)
    with pytest.raises(EvaluationJoinError, match="provenance"):
        build_calibration_proxy(sidecar, gt, [bad])

    bad = copy.deepcopy(scores[0])
    bad["snapshot_id"] = "other"
    core = {k: v for k, v in bad.items() if k != "artifact_id"}
    bad["artifact_id"] = _hash(core)
    with pytest.raises(EvaluationJoinError, match="different snapshot"):
        build_calibration_proxy(sidecar, gt, [bad])


def test_ai_proxy_limit_survives_calibration_report():
    dataset = build_calibration_proxy(*_fixtures())
    report = calibrate(dataset, thresholds=[50], windows=[None], minimum_recall=0,
                       heldout_fraction=.5, bootstrap_iterations=3)
    assert "external-expert" in report["claim_limit"]
    assert report["eligibility"]["binary_eligible"] == 6


def test_legacy_sidecar_without_clone_group_fails_closed():
    sidecar, gt, scores = _fixtures()
    del sidecar["occurrences"][0]["group_id"]
    core = {k: v for k, v in sidecar.items() if k != "sidecar_id"}
    sidecar["sidecar_id"] = _hash(core)
    with pytest.raises(EvaluationJoinError, match="clone group_id"):
        build_calibration_proxy(sidecar, gt, scores)


def test_test_retest_builder_emits_four_class_gt_and_fails_on_disagreement():
    items = [{"candidate_id": f"o{i}", "group_id": "g", "rule_id": "R-1",
              "requirement": {"text": "requirement", "citations": [{"source": "s", "locator": "1"}]},
              "source": {"source_id": "a.c", "line_start": 1, "line_end": 1,
                         "code": "000001: int x;", "context": "context"}} for i in range(4)]
    audit = {"passed": True, "checks": {"ok": True}, "audited_items_sha256": _hash(items)}
    packet = build_packet(snapshot_id="snap", prepared_by="test", randomization_id="r",
                          items=items, blind_audit_report=audit, view="minimal_cue_controlled")
    def labels(annotator):
        rows = [{"candidate_id": item["candidate_id"], "label": label, "confidence": 80,
                 "requirement_applicability": "not_applicable" if label == "not_applicable" else "applicable",
                 "evidence": "e", "rationale": "r", "source_citations": [
                     {"source_id": "a.c", "line_start": 1, "line_end": 1}]}
                for item, label in zip(packet["items"],
                    ["violation", "non_violation", "insufficient_context", "not_applicable"])]
        core = {"schema_version": "1.1", "packet_id": packet["packet_id"],
                "annotator": {"annotator_id": annotator, "annotator_type": "ai",
                              "model": {"provider": "p", "name": "m", "version": "v"}},
                "created_at": "2026-01-01T00:00:00+00:00", "annotations": rows}
        return {"label_batch_id": _hash(core), **core}
    a, b = labels("run-a"), labels("run-b")
    gt = build_test_retest_proxy_gt(packet, a, b)
    assert [row["label"] for row in gt["rows"]] == [row["label"] for row in a["annotations"]]
    b["annotations"][0]["label"] = "non_violation"
    bcore = {k: v for k, v in b.items() if k != "label_batch_id"}
    b["label_batch_id"] = _hash(bcore)
    with pytest.raises(EvaluationJoinError, match="requires separate adjudication"):
        build_test_retest_proxy_gt(packet, a, b)


def test_converter_seals_partial_score_dispositions_and_join_uses_common_subset():
    sidecar, gt, _ = _fixtures()
    def raw(no_rag, scored):
        universe = [f"f{i}" for i in range(8)]
        selected = universe[:6]
        return {"scope": "single_l2_l3_condition_from_frozen_l1", "snapshot_id": "snap",
                "candidate_ids": universe, "selected_candidate_ids": selected,
                "l3_decision_records": [{"candidate_id": cid,
                    "initial_violation_probability": 80, "rejudge_violation_probability": None,
                    "score_provenance": "prompt_contract_confidence_proxy_not_calibrated_probability",
                    "rejudge_applied": False, "decision": "retained"} for cid in scored]}
    rag = score_artifact_from_l3_result(raw(False, ["f0", "f1", "f2", "f3", "f4"]),
                                        condition="rag", repeat=0)
    no_rag = score_artifact_from_l3_result(raw(True, ["f1", "f2", "f3", "f4", "f5"]),
                                           condition="no_rag", repeat=0)
    dataset = build_calibration_proxy(sidecar, gt, [rag, no_rag])
    assert dataset["eligibility"]["common_scored"]["count"] == 4
    assert dataset["eligibility"]["common_scored_binary"]["count"] == 4
    assert dataset["eligibility"]["excluded_by_disposition"]["rag"] == {
        "unselected": _summary({"f6", "f7"}),
        "score_unresolved": _summary({"f5::0"}),
        "condition_only_scored": _summary({"f0::0"}),
    }
    assert "not whole-L1 performance" in dataset["claim_limit"]

    merged = score_artifact_from_l3_results(
        [raw(False, ["f0", "f1"]), raw(False, ["f1", "f2"])], condition="rag")
    assert [row["repeat"] for row in merged["coverage"]["repeat_dispositions"]] == [0, 1]
    assert {row["repeat"] for row in merged["rows"]} == {0, 1}
    changed = raw(False, ["f0"])
    changed["selected_candidate_ids"] = changed["selected_candidate_ids"][:-1]
    with pytest.raises(EvaluationJoinError, match="differ in snapshot"):
        score_artifact_from_l3_results([raw(False, ["f0"]), changed], condition="rag")


def _summary(values):
    return {"count": len(values), "ids_sha256": _hash(sorted(values))}


def test_strict_sidecar_group_migration_preserves_occurrences_and_rejects_view_disagreement():
    items = [{"candidate_id": f"o{i}", "group_id": f"g{i // 2}", "rule_id": "R-1",
              "requirement": {"text": "requirement", "citations": [{"source": "s", "locator": "1"}]},
              "source": {"source_id": "a.c", "line_start": 1, "line_end": 1,
                         "code": "000001: int x;", "context": "context"}} for i in range(4)]
    audit = {"passed": True, "checks": {"ok": True}, "audited_items_sha256": _hash(items)}
    packets = {view: build_packet(snapshot_id="snap", prepared_by="test",
                randomization_id=f"r-{view}", items=copy.deepcopy(items),
                blind_audit_report=audit, view=view)
               for view in ("analysis_artifact_aware", "minimal_cue_controlled", "fully_opaque")}
    occurrences = [{"occurrence_id": f"o{i}", "frozen_candidate_id": f"f{i}", "x": i}
                   for i in range(4)]
    core = {"schema_version": "1.1", "snapshot_id": "snap",
            "equivalence_report_sha256": "a" * 64, "generator_manifest_sha256": "b" * 64,
            "order_strategy": "sealed", "packet_ids": {v: p["packet_id"] for v, p in packets.items()},
            "occurrences": occurrences}
    legacy = {"sidecar_id": _hash(core), **core}
    migrated = migrate_v15_sidecar_group_ids(legacy, packets)
    assert [row["occurrence_id"] for row in migrated["occurrences"]] == [f"o{i}" for i in range(4)]
    assert [row["group_id"] for row in migrated["occurrences"]] == [f"g{i // 2}" for i in range(4)]
    assert migrated["sidecar_id"] != legacy["sidecar_id"]

    bad_items = copy.deepcopy(items)
    bad_items[0]["group_id"] = "different"
    bad_audit = {"passed": True, "checks": {"ok": True}, "audited_items_sha256": _hash(bad_items)}
    packets["fully_opaque"] = build_packet(
        snapshot_id="snap", prepared_by="test", randomization_id="bad",
        items=bad_items, blind_audit_report=bad_audit, view="fully_opaque")
    core["packet_ids"] = {v: p["packet_id"] for v, p in packets.items()}
    legacy = {"sidecar_id": _hash(core), **core}
    with pytest.raises(EvaluationJoinError, match="disagree"):
        migrate_v15_sidecar_group_ids(legacy, packets)
