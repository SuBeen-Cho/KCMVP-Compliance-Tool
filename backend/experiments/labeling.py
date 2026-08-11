"""Closed-schema, occurrence-level blind-labeling protocol."""
from __future__ import annotations

from collections import Counter
from datetime import datetime
import hashlib
import json
import re
from typing import Any, Iterable


SCHEMA_VERSION = "1.1"
PACKET_VIEWS = {
    "analysis_artifact_aware": {
        "purpose": "Primary analysis-artifact review with ordinary names and non-outcome comments preserved",
        "claim_limit": "Uses the sanitized analysis artifact, not an untouched original; does not establish independent ground truth",
        "identifiers_neutralized": False,
    },
    "minimal_cue_controlled": {
        "purpose": "Primary cue-controlled review removing only provenance-confirmed synthetic answer markers",
        "claim_limit": "Supports a primary robustness comparison; ordinary names remain admissible evidence",
        "identifiers_neutralized": False,
    },
    "fully_opaque": {
        "purpose": "Secondary selected-cue stress test of dependence on paths, comments and cue-bearing identifiers",
        "claim_limit": "Selected-cue ablation only, not complete lexical opacity or representative product accuracy",
        "identifiers_neutralized": True,
    },
}
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
    if packet.get("schema_version") == "1.0" and "view" not in packet:
        _exact(packet, {"schema_version", "packet_id", "snapshot_id", "blinding",
                        "randomization_sha256", "items"}, "legacy packet")
        expected = _hash({key: value for key, value in packet.items() if key != "packet_id"})
        if packet["packet_id"] != expected:
            raise LabelingError("legacy packet_id does not match packet contents")
        _walk_packet(packet)
        migrated = migrate_packet(packet)
        summary = validate_packet(migrated)
        return {"packet_id": packet["packet_id"], "candidate_count": summary["candidate_count"],
                "legacy_schema": True, "migrated_packet_id": migrated["packet_id"]}
    _exact(packet, {"schema_version", "packet_id", "snapshot_id", "view", "purpose",
                    "claim_limit", "blinding",
                    "randomization_sha256", "items"}, "packet")
    if packet["schema_version"] != SCHEMA_VERSION:
        raise LabelingError("unsupported packet schema")
    _text(packet["snapshot_id"], "snapshot_id")
    view = packet["view"]
    if view not in PACKET_VIEWS:
        raise LabelingError("unsupported packet view")
    specification = PACKET_VIEWS[view]
    if packet["purpose"] != specification["purpose"] or packet["claim_limit"] != specification["claim_limit"]:
        raise LabelingError("packet purpose or claim limit does not match its registered view")
    _exact(packet["blinding"], {"outcome_fields_removed", "identifiers_neutralized",
                                "order_randomized", "duplicate_families_grouped",
                                "blind_audit_passed", "blind_audit_sha256",
                                "display_alias_compile_equivalence_claimed", "prepared_by"},
           "blinding")
    if packet["blinding"]["outcome_fields_removed"] is not True:
        raise LabelingError("packet must attest that outcome fields were removed")
    if packet["blinding"]["identifiers_neutralized"] is not specification["identifiers_neutralized"]:
        raise LabelingError("identifier-neutralization attestation does not match packet view")
    if packet["blinding"]["display_alias_compile_equivalence_claimed"] is not False:
        raise LabelingError("display aliases must not claim compile equivalence")
    if any(packet["blinding"][key] is not True for key in (
        "order_randomized", "duplicate_families_grouped", "blind_audit_passed",
    )):
        raise LabelingError("packet blind-audit attestations must all pass")
    _text(packet["blinding"]["prepared_by"], "prepared_by")
    if not re.fullmatch(r"[0-9a-f]{64}", str(packet["blinding"]["blind_audit_sha256"]), re.I):
        raise LabelingError("blind_audit_sha256 must be a SHA-256 value")
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


def migrate_packet(packet: dict[str, Any]) -> dict[str, Any]:
    """Migrate a validated legacy 1.0 packet to the explicit selected-cue view."""
    if packet.get("schema_version") != "1.0" or "view" in packet:
        raise LabelingError("only legacy 1.0 packets can be migrated")
    expected = _hash({key: value for key, value in packet.items() if key != "packet_id"})
    if packet.get("packet_id") != expected:
        raise LabelingError("legacy packet_id does not match packet contents")
    core = {key: value for key, value in packet.items() if key != "packet_id"}
    core["schema_version"] = SCHEMA_VERSION
    core["view"] = "fully_opaque"
    core["purpose"] = PACKET_VIEWS["fully_opaque"]["purpose"]
    core["claim_limit"] = PACKET_VIEWS["fully_opaque"]["claim_limit"]
    migrated = {"packet_id": _hash(core), **core}
    return migrated


def build_packet(*, snapshot_id: str, prepared_by: str, randomization_id: str,
                 items: list[dict[str, Any]], blind_audit_report: dict[str, Any],
                 view: str = "fully_opaque") -> dict[str, Any]:
    if view not in PACKET_VIEWS:
        raise LabelingError("unsupported packet view")
    _exact(blind_audit_report, {"passed", "checks", "audited_items_sha256"}, "blind audit report")
    checks = blind_audit_report["checks"]
    if (blind_audit_report["passed"] is not True or not isinstance(checks, dict)
            or not checks or any(value is not True for value in checks.values())):
        raise LabelingError("a completed passing blind audit is required before packet issuance")
    if blind_audit_report["audited_items_sha256"] != _hash(items):
        raise LabelingError("blind audit report does not bind to packet items")
    audit_sha256 = _hash(blind_audit_report)
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
        "view": view, "purpose": PACKET_VIEWS[view]["purpose"],
        "claim_limit": PACKET_VIEWS[view]["claim_limit"],
        "blinding": {"outcome_fields_removed": True,
                     "identifiers_neutralized": PACKET_VIEWS[view]["identifiers_neutralized"],
                     "order_randomized": True, "duplicate_families_grouped": True,
                     "blind_audit_passed": True, "blind_audit_sha256": audit_sha256,
                     "display_alias_compile_equivalence_claimed": False,
                     "prepared_by": prepared_by},
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
    if (packet.get("schema_version") == "1.0" and "view" not in packet
            and document.get("schema_version") == "1.0"):
        validate_packet(packet)
        _exact(document, {"schema_version", "label_batch_id", "packet_id", "annotator",
                          "created_at", "annotations"}, "legacy label document")
        if document["packet_id"] != packet["packet_id"]:
            raise LabelingError("legacy label document packet identity mismatch")
        core = {key: value for key, value in document.items() if key != "label_batch_id"}
        if document["label_batch_id"] != _hash(core):
            raise LabelingError("legacy label_batch_id does not match immutable label contents")
        migrated_packet = migrate_packet(packet)
        migrated_document = migrate_label_document(packet, document)
        summary = validate_label_document(migrated_packet, migrated_document)
        return {"label_batch_id": document["label_batch_id"],
                "annotation_count": summary["annotation_count"], "legacy_schema": True,
                "migrated_label_batch_id": migrated_document["label_batch_id"],
                "migrated_packet_id": migrated_packet["packet_id"]}
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
            if (cite["line_start"] < source["line_start"]
                    or cite["line_end"] > source["line_end"]):
                raise LabelingError("source citation must stay within the disclosed source window")
    core = {key: value for key, value in document.items() if key != "label_batch_id"}
    if document["label_batch_id"] != _hash(core):
        raise LabelingError("label_batch_id does not match immutable label contents")
    return {"label_batch_id": document["label_batch_id"], "annotation_count": len(annotations)}


def migrate_label_document(packet: dict[str, Any], document: dict[str, Any]) -> dict[str, Any]:
    """Bind an immutable legacy 1.0 annotation batch to the migrated packet."""
    if (packet.get("schema_version") != "1.0" or "view" in packet
            or document.get("schema_version") != "1.0"):
        raise LabelingError("label migration requires a legacy 1.0 packet and document")
    packet_core = {key: value for key, value in packet.items() if key != "packet_id"}
    document_core = {key: value for key, value in document.items() if key != "label_batch_id"}
    if packet.get("packet_id") != _hash(packet_core):
        raise LabelingError("legacy packet_id does not match packet contents")
    if (document.get("packet_id") != packet["packet_id"]
            or document.get("label_batch_id") != _hash(document_core)):
        raise LabelingError("legacy label document identity does not match its contents")
    migrated_packet = migrate_packet(packet)
    document_core["schema_version"] = SCHEMA_VERSION
    document_core["packet_id"] = migrated_packet["packet_id"]
    return {"label_batch_id": _hash(document_core), **document_core}


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


def cross_view_report(
    packets: dict[str, dict[str, Any]], documents: dict[str, dict[str, Any]],
    sidecar: dict[str, Any],
) -> dict[str, Any]:
    """Compare paired occurrence labels across different packet identities."""
    if set(packets) != set(documents) or len(packets) < 2:
        raise LabelingError("cross-view comparison requires matching packet and label views")
    if set(packets) - set(PACKET_VIEWS):
        raise LabelingError("cross-view comparison contains an unsupported view")
    packet_ids = sidecar.get("packet_ids") if isinstance(sidecar, dict) else None
    occurrences = sidecar.get("occurrences") if isinstance(sidecar, dict) else None
    if not isinstance(packet_ids, dict) or not isinstance(occurrences, list):
        raise LabelingError("sealed sidecar occurrence join is required")
    sidecar_id = sidecar.get("sidecar_id")
    sidecar_core = {key: value for key, value in sidecar.items() if key != "sidecar_id"}
    if not isinstance(sidecar_id, str) or sidecar_id != _hash(sidecar_core):
        raise LabelingError("sealed sidecar identity does not match its contents")
    ordered_views = [view for view in PACKET_VIEWS if view in packets]
    labels_by_view: dict[str, dict[str, dict[str, Any]]] = {}
    expected_ids: set[str] | None = None
    for view in ordered_views:
        packet = packets[view]
        if packet.get("view") != view or packet_ids.get(view) != packet.get("packet_id"):
            raise LabelingError("sidecar packet identity does not match cross-view input")
        validate_label_document(packet, documents[view])
        rows = {row["candidate_id"]: row for row in documents[view]["annotations"]}
        expected_ids = set(rows) if expected_ids is None else expected_ids
        if set(rows) != expected_ids:
            raise LabelingError("cross-view occurrence sets differ")
        labels_by_view[view] = rows
    joined_ids = [str(row.get("occurrence_id", "")) for row in occurrences]
    if not joined_ids or len(joined_ids) != len(set(joined_ids)) or set(joined_ids) != expected_ids:
        raise LabelingError("sidecar occurrence join does not match label documents")
    paired_table = [{
        "occurrence_id": occurrence_id,
        "labels": {view: labels_by_view[view][occurrence_id]["label"] for view in ordered_views},
        "confidence": {view: labels_by_view[view][occurrence_id]["confidence"] for view in ordered_views},
    } for occurrence_id in joined_ids]
    counts = {view: dict(sorted(Counter(row["label"] for row in labels_by_view[view].values()).items()))
              for view in ordered_views}
    baseline = ordered_views[0]
    deltas = {view: {label: counts[view].get(label, 0) - counts[baseline].get(label, 0)
                     for label in LABELS} for view in ordered_views[1:]}
    pairs = {}
    for left_index, left in enumerate(ordered_views):
        for right in ordered_views[left_index + 1:]:
            transitions = Counter(
                f"{labels_by_view[left][oid]['label']}->{labels_by_view[right][oid]['label']}"
                for oid in joined_ids
            )
            exact = sum(labels_by_view[left][oid]["label"] == labels_by_view[right][oid]["label"]
                        for oid in joined_ids)
            pairs[f"{left}::{right}"] = {
                "exact_count": exact, "exact_rate": exact / len(joined_ids),
                "transitions": dict(sorted(transitions.items())),
            }
    all_exact = sum(len({labels_by_view[view][oid]["label"] for view in ordered_views}) == 1
                    for oid in joined_ids)
    core = {"schema_version": SCHEMA_VERSION, "views": ordered_views,
            "occurrence_count": len(joined_ids), "counts": counts, "deltas_from_first_view": deltas,
            "pairwise": pairs, "all_view_exact_count": all_exact,
            "all_view_exact_rate": all_exact / len(joined_ids), "paired_table": paired_table}
    return {"report_id": _hash(core), **core}


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
        "cohens_kappa_one_vs_rest": per_class,
        "label_disagreement_count": sum(x != y for x, y in zip(labels_a, labels_b)),
        "applicability_disagreement_count": sum(
            left["requirement_applicability"] != right["requirement_applicability"]
            for left, right in zip(a["annotations"], b["annotations"])
        ),
        # The adjudication queue is the union of label and applicability conflicts.
        "adjudication_count": len(conflict_rows),
        "disagreement_count": len(conflict_rows),
    }
    queue_core = {
        "schema_version": SCHEMA_VERSION, "packet_id": packet["packet_id"],
        "source_label_batch_ids": [a["label_batch_id"], b["label_batch_id"]],
        "items": conflict_rows,
    }
    queue = {"adjudication_queue_id": _hash(queue_core), **queue_core}
    return report, queue
