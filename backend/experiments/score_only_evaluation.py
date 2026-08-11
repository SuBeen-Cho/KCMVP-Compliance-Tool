"""Leakage-resistant post-hoc joining of system scores and adjudicated labels.

System execution artifacts deliberately contain no ground truth.  This module is
the only bridge: it validates a sealed three-view sidecar, an occurrence-level
adjudication artifact, and score-only system outputs before producing metrics or
a calibration dataset.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from typing import Any

from experiments.calibration import SCORE_SEMANTICS
from experiments.labeling import validate_label_document, validate_packet


class EvaluationJoinError(ValueError):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def _hash(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _exact(value: Any, keys: set[str], name: str) -> None:
    if not isinstance(value, dict) or set(value) != keys:
        raise EvaluationJoinError(f"{name} does not match the closed schema")


def build_test_retest_proxy_gt(packet: Any, first: Any, second: Any) -> dict[str, Any]:
    """Build four-class proxy GT from two same-model deterministic repeat runs.

    This strict builder refuses disagreements.  A future adjudication workflow
    must use a separate explicit schema rather than silently applying majority
    voting to only two observations.
    """
    validate_packet(packet)
    validate_label_document(packet, first)
    validate_label_document(packet, second)
    left, right = first["annotator"], second["annotator"]
    if left["annotator_type"] != "ai" or right["annotator_type"] != "ai":
        raise EvaluationJoinError("test-retest proxy requires two AI label documents")
    if left["annotator_id"] == right["annotator_id"]:
        raise EvaluationJoinError("test-retest runs must use distinct run annotator IDs")
    if left["model"] != right["model"]:
        raise EvaluationJoinError("test-retest proxy requires the exact same model configuration")
    rows = []
    disagreements = []
    for a, b in zip(first["annotations"], second["annotations"]):
        if a["candidate_id"] != b["candidate_id"]:
            raise EvaluationJoinError("validated label documents have different occurrence order")
        if a["label"] != b["label"]:
            disagreements.append(a["candidate_id"])
            continue
        rows.append({"occurrence_id": a["candidate_id"], "label": a["label"],
                     "adjudication": "unanimous"})
    if disagreements:
        raise EvaluationJoinError(
            f"test-retest disagreement requires separate adjudication input ({len(disagreements)} unresolved)"
        )
    core = {
        "schema_version": "1.0", "scope": "ai_adjudicated_proxy_gt",
        "ground_truth_basis": "same_model_temperature0_test_retest_proxy_not_external_expert_gt",
        "claim_limit": ("Same-model temperature-0 test-retest proxy; not independent annotators "
                        "and not external-expert ground truth"),
        "source_label_batch_ids": [first["label_batch_id"], second["label_batch_id"]],
        "rows": rows,
    }
    document = {"gt_id": _hash(core), **core}
    validate_adjudicated_gt(document, {item["candidate_id"] for item in packet["items"]})
    return document


def validate_sidecar(sidecar: Any) -> dict[str, dict[str, str]]:
    required = {"schema_version", "snapshot_id", "equivalence_report_sha256",
                "generator_manifest_sha256", "order_strategy", "packet_ids",
                "occurrences", "sidecar_id"}
    _exact(sidecar, required, "sealed sidecar")
    core = {key: value for key, value in sidecar.items() if key != "sidecar_id"}
    if sidecar["sidecar_id"] != _hash(core):
        raise EvaluationJoinError("sealed sidecar identity does not match its contents")
    if not isinstance(sidecar["occurrences"], list) or not sidecar["occurrences"]:
        raise EvaluationJoinError("sealed sidecar occurrences must be non-empty")
    output: dict[str, dict[str, str]] = {}
    frozen: set[str] = set()
    for row in sidecar["occurrences"]:
        occurrence_id, frozen_id = row.get("occurrence_id"), row.get("frozen_candidate_id")
        if not all(isinstance(value, str) and value for value in (occurrence_id, frozen_id)):
            raise EvaluationJoinError("sidecar occurrence identities are invalid")
        if occurrence_id in output or frozen_id in frozen:
            raise EvaluationJoinError("sidecar occurrence join must be one-to-one")
        group_id = row.get("group_id")
        # Older sidecars derive the group only into packet items. They cannot
        # safely support clone-separated calibration and therefore fail closed.
        if not isinstance(group_id, str) or not group_id:
            raise EvaluationJoinError("sidecar must carry clone group_id for safe splitting")
        output[occurrence_id] = {"frozen_candidate_id": frozen_id, "group_id": group_id}
        frozen.add(frozen_id)
    return output


def validate_adjudicated_gt(document: Any, occurrence_ids: set[str]) -> dict[str, str]:
    _exact(document, {"schema_version", "scope", "ground_truth_basis", "claim_limit",
                      "source_label_batch_ids", "rows", "gt_id"}, "adjudicated GT")
    if document["schema_version"] != "1.0" or document["scope"] != "ai_adjudicated_proxy_gt":
        raise EvaluationJoinError("only explicitly identified AI proxy GT is supported")
    if document["ground_truth_basis"] != "same_model_temperature0_test_retest_proxy_not_external_expert_gt":
        raise EvaluationJoinError("AI proxy GT basis must not claim expert ground truth")
    claim = document["claim_limit"].lower() if isinstance(document["claim_limit"], str) else ""
    if not all(term in claim for term in ("proxy", "test-retest", "not independent")):
        raise EvaluationJoinError("AI proxy GT must disclose same-model test-retest non-independence")
    core = {key: value for key, value in document.items() if key != "gt_id"}
    if document["gt_id"] != _hash(core):
        raise EvaluationJoinError("adjudicated GT identity does not match its contents")
    labels: dict[str, str] = {}
    for row in document["rows"]:
        _exact(row, {"occurrence_id", "label", "adjudication"}, "GT row")
        oid, label = row["occurrence_id"], row["label"]
        if oid in labels or label not in {
            "violation", "non_violation", "insufficient_context", "not_applicable",
        }:
            raise EvaluationJoinError("GT rows must be unique closed four-class labels")
        if row["adjudication"] not in {"unanimous", "majority", "tie_break"}:
            raise EvaluationJoinError("GT adjudication provenance is invalid")
        labels[oid] = label
    if set(labels) != occurrence_ids:
        raise EvaluationJoinError("GT must resolve exactly the sealed occurrence set")
    return labels


def validate_score_artifact(document: Any, frozen_ids: set[str]) -> list[dict[str, Any]]:
    _exact(document, {"schema_version", "scope", "snapshot_id", "condition",
                      "score_semantics", "rows", "artifact_id"}, "score artifact")
    if document["schema_version"] != "1.0" or document["scope"] != "score_only_system_output":
        raise EvaluationJoinError("unsupported score-only artifact")
    if document["score_semantics"] != SCORE_SEMANTICS:
        raise EvaluationJoinError("system score must use violation_probability semantics")
    encoded = _canonical({key: value for key, value in document.items() if key != "artifact_id"})
    if document["artifact_id"] != hashlib.sha256(encoded).hexdigest():
        raise EvaluationJoinError("score artifact identity does not match its contents")
    forbidden = (b"ground_truth", b"expected", b"correct", b"expert", b"adjudicat")
    if any(token in encoded.lower() for token in forbidden):
        raise EvaluationJoinError("ground-truth-bearing content is forbidden in system scores")
    rows, seen = [], set()
    for row in document["rows"]:
        _exact(row, {"frozen_candidate_id", "repeat", "initial", "rejudge",
                     "score_provenance"}, "score row")
        cid = row["frozen_candidate_id"]
        if cid not in frozen_ids or (cid, row["repeat"]) in seen:
            raise EvaluationJoinError("score rows contain unknown or duplicate occurrences")
        if type(row["repeat"]) is not int or row["repeat"] < 0:
            raise EvaluationJoinError("score repeat must be a non-negative integer")
        if row["score_provenance"] != "prompt_contract_confidence_proxy_not_calibrated_probability":
            raise EvaluationJoinError("score provenance must disclose the uncalibrated proxy")
        for key in ("initial", "rejudge"):
            value = row[key]
            if value is None and key == "rejudge":
                continue
            if type(value) is not int or not 0 <= value <= 100:
                raise EvaluationJoinError("scores must be integer probabilities from 0 to 100")
        seen.add((cid, row["repeat"]))
        rows.append(row)
    return rows


def build_calibration_proxy(sidecar: Any, gt: Any, score_documents: list[Any]) -> dict[str, Any]:
    """Join after inference; output remains explicitly non-expert/proxy evidence."""
    join = validate_sidecar(sidecar)
    labels = validate_adjudicated_gt(gt, set(join))
    reverse = {row["frozen_candidate_id"]: (oid, row["group_id"]) for oid, row in join.items()}
    rows = []
    conditions: set[str] = set()
    for document in score_documents:
        if document.get("snapshot_id") != sidecar["snapshot_id"]:
            raise EvaluationJoinError("score artifact is bound to a different snapshot")
        condition = document.get("condition")
        if not isinstance(condition, str) or not condition or condition in conditions:
            raise EvaluationJoinError("score conditions must be unique non-empty strings")
        conditions.add(condition)
        score_rows = validate_score_artifact(document, set(reverse))
        covered = {row["frozen_candidate_id"] for row in score_rows}
        if covered != set(reverse):
            raise EvaluationJoinError("each score condition must cover every frozen occurrence")
        for score in score_rows:
            oid, group_id = reverse[score["frozen_candidate_id"]]
            initial, rejudge = score["initial"], score["rejudge"]
            if labels[oid] not in {"violation", "non_violation"}:
                continue
            rows.append({
                "observation_id": _hash({"artifact": document["artifact_id"], "id": oid,
                                         "repeat": score["repeat"]}),
                "candidate_id": oid, "group_id": group_id, "condition": condition,
                "repeat": score["repeat"],
                "ground_truth_violation": labels[oid] == "violation",
                "initial": {"verdict": "violation" if initial >= 50 else "not_violation",
                            "violation_probability": initial},
                "rejudge": None if rejudge is None else {
                    "verdict": "violation" if rejudge >= 50 else "not_violation",
                    "violation_probability": rejudge,
                },
            })
    if not rows:
        raise EvaluationJoinError("at least one score row is required")
    label_counts = Counter(labels.values())
    return {
        "schema_version": "1.1", "score_semantics": SCORE_SEMANTICS,
        "ground_truth_basis": "same_model_temperature0_test_retest_proxy_not_external_expert_gt",
        "claim_limit": ("Calibration proxy from same-model temperature-0 test-retest labels; "
                        "not independent annotators and not an external-expert performance estimate"),
        "eligibility": {"sealed_total": len(labels),
                        "binary_eligible": label_counts["violation"] + label_counts["non_violation"],
                        "excluded_by_label": {
                            "insufficient_context": label_counts["insufficient_context"],
                            "not_applicable": label_counts["not_applicable"],
                        }},
        "rows": rows,
    }


def paired_binary_report(dataset: dict[str, Any], *, threshold: int = 50) -> dict[str, Any]:
    """Report paired condition deltas and exact McNemar discordance counts."""
    if dataset.get("schema_version") != "1.1":
        raise EvaluationJoinError("paired report requires a joined proxy dataset")
    by_condition: dict[str, dict[tuple[str, int], dict[str, Any]]] = {}
    for row in dataset["rows"]:
        by_condition.setdefault(row["condition"], {})[(row["candidate_id"], row["repeat"])] = row
    if len(by_condition) != 2:
        raise EvaluationJoinError("paired binary report requires exactly two conditions")
    left, right = sorted(by_condition)
    if set(by_condition[left]) != set(by_condition[right]):
        raise EvaluationJoinError("paired conditions must contain identical occurrences and repeats")
    discordant = Counter(left_only_correct=0, right_only_correct=0)
    for key in by_condition[left]:
        l, r = by_condition[left][key], by_condition[right][key]
        truth = l["ground_truth_violation"]
        lc = (l["initial"]["violation_probability"] >= threshold) == truth
        rc = (r["initial"]["violation_probability"] >= threshold) == truth
        if lc and not rc:
            discordant["left_only_correct"] += 1
        elif rc and not lc:
            discordant["right_only_correct"] += 1
    return {"conditions": [left, right], "paired_n": len(by_condition[left]),
            "threshold": threshold, "mcnemar_discordance_counts": dict(discordant),
            "claim_limit": dataset["claim_limit"]}
