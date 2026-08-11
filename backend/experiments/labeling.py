"""Closed-schema, occurrence-level blind-labeling protocol."""
from __future__ import annotations

from collections import Counter
from datetime import datetime
import hashlib
import json
import re
from typing import Any, Iterable


SCHEMA_VERSION = "1.0"
LABELS = ("violation", "non_violation", "insufficient_context", "not_applicable")
APPLICABILITY = ("applicable", "not_applicable", "uncertain")
FORBIDDEN_PACKET_KEYS = {
    "label", "labels", "verdict", "groundtruth", "ground_truth", "expected",
    "is_violation", "l3", "l3_result", "rejudge", "decision", "disposition",
    "accepted", "rejected", "confidence",
    "message", "file", "path", "raw_source_path", "system_output",
}
SECRET_RE = re.compile(r"(?:AIza[0-9A-Za-z_-]{20,}|(?i:api[_-]?key)\s*[:=])")


class LabelingError(ValueError):
    """A packet or annotation violates the blind-labeling contract."""


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                          allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise LabelingError("document must be canonical JSON") from exc


def _hash(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _exact(value: Any, fields: set[str], name: str) -> None:
    if not isinstance(value, dict) or set(value) != fields:
        raise LabelingError(f"{name} does not match the closed schema")


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise LabelingError(f"{name} must be non-empty text")
    if SECRET_RE.search(value):
        raise LabelingError(f"credential-like value found in {name}")
    return value


def _walk_packet(value: Any) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key.lower() in FORBIDDEN_PACKET_KEYS:
                raise LabelingError(f"outcome-bearing field is forbidden in packet: {key}")
            _walk_packet(item)
    elif isinstance(value, list):
        for item in value:
            _walk_packet(item)
    elif isinstance(value, str) and SECRET_RE.search(value):
        raise LabelingError("credential-like value found in packet")


def validate_packet(packet: dict[str, Any]) -> dict[str, Any]:
    """Validate a label-free packet and return its stable identity summary."""
    _exact(packet, {"schema_version", "packet_id", "snapshot_id", "blinding",
                    "randomization_sha256", "items"}, "packet")
    if packet["schema_version"] != SCHEMA_VERSION:
        raise LabelingError("unsupported packet schema")
    _text(packet["snapshot_id"], "snapshot_id")
    _exact(packet["blinding"], {"outcome_fields_removed", "identifiers_neutralized",
                                "order_randomized", "duplicate_families_grouped",
                                "blind_audit_passed", "prepared_by"},
           "blinding")
    if packet["blinding"]["outcome_fields_removed"] is not True:
        raise LabelingError("packet must attest that outcome fields were removed")
    if packet["blinding"]["identifiers_neutralized"] is not True:
        raise LabelingError("packet must attest that identifiers were neutralized")
    if any(packet["blinding"][key] is not True for key in (
        "order_randomized", "duplicate_families_grouped", "blind_audit_passed",
    )):
        raise LabelingError("packet blind-audit attestations must all pass")
    _text(packet["blinding"]["prepared_by"], "prepared_by")
    if not re.fullmatch(r"[0-9a-f]{64}", str(packet["randomization_sha256"]), re.I):
        raise LabelingError("randomization_sha256 must be a SHA-256 value")
    if not isinstance(packet["items"], list) or not packet["items"]:
        raise LabelingError("packet items must be a non-empty list")
    seen: set[str] = set()
    for item in packet["items"]:
        _exact(item, {"candidate_id", "group_id", "rule_id", "requirement", "source"}, "packet item")
        candidate_id = _text(item["candidate_id"], "candidate_id")
        if candidate_id in seen:
            raise LabelingError("candidate IDs must be unique")
        seen.add(candidate_id)
        _text(item["group_id"], "group_id")
        _text(item["rule_id"], "rule_id")
        _exact(item["requirement"], {"text", "citations"}, "requirement")
        _text(item["requirement"]["text"], "requirement text")
        citations = item["requirement"]["citations"]
        if not isinstance(citations, list) or not citations:
            raise LabelingError("each requirement needs at least one citation")
        for citation in citations:
            _exact(citation, {"source", "locator"}, "requirement citation")
            _text(citation["source"], "citation source")
            _text(citation["locator"], "citation locator")
        _exact(item["source"], {"source_id", "line_start", "line_end", "code", "context"}, "source")
        _text(item["source"]["source_id"], "source_id")
        start, end = item["source"]["line_start"], item["source"]["line_end"]
        if isinstance(start, bool) or not isinstance(start, int) or start < 1:
            raise LabelingError("line_start must be a positive integer")
        if isinstance(end, bool) or not isinstance(end, int) or end < start:
            raise LabelingError("line_end must be at least line_start")
        _text(item["source"]["code"], "source code")
        if not isinstance(item["source"]["context"], str):
            raise LabelingError("source context must be text")
    # Exact and near duplicates remain in one contiguous family, while family
    # order is reproducibly shuffled. This prevents candidate-level leakage and
    # enables cluster-level splitting/bootstrap downstream.
    groups = [item["group_id"] for item in packet["items"]]
    closed: set[str] = set()
    previous = None
    for group in groups:
        if group != previous:
            if group in closed:
                raise LabelingError("duplicate-family group must be contiguous")
            if previous is not None:
                closed.add(previous)
            previous = group
    ordered_groups = list(dict.fromkeys(groups))
    expected_groups = sorted(
        ordered_groups,
        key=lambda group: hashlib.sha256(
            f"{packet['randomization_sha256']}::{group}".encode("utf-8")
        ).hexdigest(),
    )
    if ordered_groups != expected_groups:
        raise LabelingError("packet group order does not match recorded randomization")
    _walk_packet(packet)
    core = {key: value for key, value in packet.items() if key != "packet_id"}
    expected = _hash(core)
    if packet["packet_id"] != expected:
        raise LabelingError("packet_id does not match packet contents")
    return {"packet_id": expected, "candidate_count": len(seen)}


def build_packet(*, snapshot_id: str, prepared_by: str, randomization_id: str,
                 items: list[dict[str, Any]]) -> dict[str, Any]:
    randomization_sha256 = hashlib.sha256(_text(randomization_id, "randomization_id").encode()).hexdigest()
    grouped: dict[str, list[dict[str, Any]]] = {}
    for item in items:
        grouped.setdefault(str(item.get("group_id", "")), []).append(item)
    group_order = sorted(
        grouped,
        key=lambda group: hashlib.sha256(f"{randomization_sha256}::{group}".encode()).hexdigest(),
    )
    randomized_items = [item for group in group_order for item in grouped[group]]
    core = {
        "schema_version": SCHEMA_VERSION, "snapshot_id": snapshot_id,
        "blinding": {"outcome_fields_removed": True, "identifiers_neutralized": True,
                     "order_randomized": True, "duplicate_families_grouped": True,
                     "blind_audit_passed": True, "prepared_by": prepared_by},
        "randomization_sha256": randomization_sha256, "items": randomized_items,
    }
    packet = {"packet_id": _hash(core), **core}
    validate_packet(packet)
    return packet


def _validate_timestamp(value: Any) -> None:
    _text(value, "created_at")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise LabelingError("created_at must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise LabelingError("created_at must include a timezone")


def validate_label_document(packet: dict[str, Any], document: dict[str, Any]) -> dict[str, Any]:
    validate_packet(packet)
    _exact(document, {"schema_version", "label_batch_id", "packet_id", "annotator", "created_at",
                      "annotations"}, "label document")
    if document["schema_version"] != SCHEMA_VERSION or document["packet_id"] != packet["packet_id"]:
        raise LabelingError("label document schema or packet identity mismatch")
    _exact(document["annotator"], {"annotator_id", "annotator_type", "model"}, "annotator")
    _text(document["annotator"]["annotator_id"], "annotator_id")
    if document["annotator"]["annotator_type"] not in {"human", "ai"}:
        raise LabelingError("annotator_type must be human or ai")
    _exact(document["annotator"]["model"], {"provider", "name", "version"}, "model")
    for key, value in document["annotator"]["model"].items():
        _text(value, f"model {key}")
    _validate_timestamp(document["created_at"])
    expected_ids = [item["candidate_id"] for item in packet["items"]]
    packet_sources = {item["candidate_id"]: item["source"] for item in packet["items"]}
    annotations = document["annotations"]
    if not isinstance(annotations, list) or [row.get("candidate_id") for row in annotations] != expected_ids:
        raise LabelingError("annotations must be complete and in packet order")
    for row in annotations:
        _exact(row, {"candidate_id", "label", "confidence", "requirement_applicability",
                     "evidence", "rationale", "source_citations"}, "annotation")
        if row["label"] not in LABELS:
            raise LabelingError("unsupported annotation label")
        if row["requirement_applicability"] not in APPLICABILITY:
            raise LabelingError("unsupported requirement applicability")
        if (row["label"] == "not_applicable") != (row["requirement_applicability"] == "not_applicable"):
            raise LabelingError("not_applicable label and applicability must agree")
        confidence = row["confidence"]
        if isinstance(confidence, bool) or not isinstance(confidence, int) or not 0 <= confidence <= 100:
            raise LabelingError("confidence must be an integer from 0 through 100")
        _text(row["evidence"], "evidence")
        _text(row["rationale"], "rationale")
        if not isinstance(row["source_citations"], list) or not row["source_citations"]:
            raise LabelingError("annotation requires concrete source citations")
        for cite in row["source_citations"]:
            _exact(cite, {"source_id", "line_start", "line_end"}, "source citation")
            if not isinstance(cite["line_start"], int) or not isinstance(cite["line_end"], int):
                raise LabelingError("source citation lines must be integers")
            if cite["line_start"] < 1 or cite["line_end"] < cite["line_start"]:
                raise LabelingError("source citation line range is invalid")
            source = packet_sources[row["candidate_id"]]
            if cite["source_id"] != source["source_id"]:
                raise LabelingError("source citation must reference the candidate source")
    core = {key: value for key, value in document.items() if key != "label_batch_id"}
    if document["label_batch_id"] != _hash(core):
        raise LabelingError("label_batch_id does not match immutable label contents")
    return {"label_batch_id": document["label_batch_id"], "annotation_count": len(annotations)}


def cohens_kappa(labels_a: Iterable[str], labels_b: Iterable[str]) -> float:
    a, b = list(labels_a), list(labels_b)
    if not a or len(a) != len(b):
        raise ValueError("two equally sized non-empty label lists are required")
    categories = sorted(set(a) | set(b))
    observed = sum(x == y for x, y in zip(a, b)) / len(a)
    ca, cb = Counter(a), Counter(b)
    expected = sum(ca[c] / len(a) * cb[c] / len(b) for c in categories)
    return 1.0 if expected == 1.0 and observed == 1.0 else (observed - expected) / (1 - expected)


def disagreements(rows: Iterable[dict]) -> list[dict]:
    """Backward-compatible helper for legacy two-column rows."""
    return [row for row in rows if row.get("annotator_a") != row.get("annotator_b")]


def agreement_report(packet: dict[str, Any], a: dict[str, Any], b: dict[str, Any]) -> tuple[dict, dict]:
    validate_label_document(packet, a)
    validate_label_document(packet, b)
    if a["annotator"]["annotator_id"] == b["annotator"]["annotator_id"]:
        raise LabelingError("agreement requires distinct annotator IDs")
    labels_a = [row["label"] for row in a["annotations"]]
    labels_b = [row["label"] for row in b["annotations"]]
    per_class = {}
    for label in LABELS:
        per_class[label] = cohens_kappa([x == label for x in labels_a], [x == label for x in labels_b])
    conflict_rows = []
    for left, right in zip(a["annotations"], b["annotations"]):
        if left["label"] != right["label"] or left["requirement_applicability"] != right["requirement_applicability"]:
            conflict_rows.append({"candidate_id": left["candidate_id"], "annotation_a": left,
                                  "annotation_b": right})
    report = {
        "schema_version": SCHEMA_VERSION, "packet_id": packet["packet_id"],
        "annotator_ids": [a["annotator"]["annotator_id"], b["annotator"]["annotator_id"]],
        "n": len(labels_a), "exact_agreement": sum(x == y for x, y in zip(labels_a, labels_b)) / len(labels_a),
        "cohens_kappa_multiclass": cohens_kappa(labels_a, labels_b),
        "cohens_kappa_one_vs_rest": per_class, "disagreement_count": len(conflict_rows),
    }
    queue_core = {
        "schema_version": SCHEMA_VERSION, "packet_id": packet["packet_id"],
        "source_label_batch_ids": [a["label_batch_id"], b["label_batch_id"]],
        "items": conflict_rows,
    }
    queue = {"adjudication_queue_id": _hash(queue_core), **queue_core}
    return report, queue
