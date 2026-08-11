import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

from experiments.labeling import (
    LabelingError, agreement_report, build_packet, migrate_label_document, migrate_packet,
    validate_label_document, validate_packet,
)


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "blind_labeling.py"


def digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()


def packet():
    item = {
        "candidate_id": "case-001", "group_id": "family-001", "rule_id": "LEA-001",
        "requirement": {"text": "키 길이를 검사한다.",
                        "citations": [{"source": "KCMVP guide", "locator": "section 1"}]},
        "source": {"source_id": "module_001.c", "line_start": 10, "line_end": 11,
                   "code": "if (n == 16) return 0;", "context": "함수 본문"},
    }
    audit = {"passed": True, "checks": {"leak_scan": True},
             "audited_items_sha256": hashlib.sha256(json.dumps(
                 [item], ensure_ascii=False, sort_keys=True, separators=(",", ":"),
             ).encode()).hexdigest()}
    return build_packet(snapshot_id="snapshot-1", prepared_by="blind-preparer",
                        randomization_id="test-randomization", items=[item],
                        blind_audit_report=audit)


def test_packet_builder_requires_explicit_completed_blind_audit():
    with pytest.raises(LabelingError, match="completed.*blind audit"):
        build_packet(snapshot_id="snapshot-1", prepared_by="blind-preparer",
                     randomization_id="test-randomization", items=[],
                     blind_audit_report={"passed": False, "checks": {"leak_scan": False},
                                         "audited_items_sha256": "0" * 64})


def labels(identity="reviewer-a", label="violation"):
    annotation = {
        "candidate_id": "case-001", "label": label, "confidence": 90,
        "requirement_applicability": "applicable" if label != "not_applicable" else "not_applicable",
        "evidence": "10행의 조건을 확인하였다.", "rationale": "요구 길이와 비교한다.",
        "source_citations": [{"source_id": "module_001.c", "line_start": 10, "line_end": 10}],
    }
    core = {
        "schema_version": "1.1", "packet_id": packet()["packet_id"],
        "annotator": {"annotator_id": identity, "annotator_type": "ai",
                      "model": {"provider": "test", "name": "fixed", "version": "1"}},
        "created_at": "2026-08-11T12:00:00+09:00", "annotations": [annotation],
    }
    return {"label_batch_id": digest(core), **core}


def test_packet_rejects_outcome_leakage_and_tampering():
    value = packet()
    assert validate_packet(value)["candidate_count"] == 1
    value["items"][0]["source"]["confidence"] = 99
    with pytest.raises(LabelingError, match="closed schema|outcome-bearing"):
        validate_packet(value)
    value = packet(); value["items"][0]["source"]["code"] += " "
    with pytest.raises(LabelingError, match="packet_id"):
        validate_packet(value)


def test_legacy_1_0_packet_validates_and_migrates_explicitly():
    import hashlib
    value = packet()
    legacy_core = {key: item for key, item in value.items()
                   if key not in {"packet_id", "view", "purpose", "claim_limit"}}
    legacy_core["schema_version"] = "1.0"
    encoded = json.dumps(legacy_core, ensure_ascii=False, sort_keys=True,
                         separators=(",", ":")).encode()
    legacy = {"packet_id": hashlib.sha256(encoded).hexdigest(), **legacy_core}
    summary = validate_packet(legacy)
    assert summary["legacy_schema"] is True
    migrated = migrate_packet(legacy)
    assert migrated["schema_version"] == "1.1"
    assert migrated["view"] == "fully_opaque"
    assert validate_packet(migrated)["candidate_count"] == 1

    current_labels = labels()
    legacy_label_core = {key: item for key, item in current_labels.items()
                         if key != "label_batch_id"}
    legacy_label_core["schema_version"] = "1.0"
    legacy_label_core["packet_id"] = legacy["packet_id"]
    legacy_labels = {"label_batch_id": digest(legacy_label_core), **legacy_label_core}
    label_summary = validate_label_document(legacy, legacy_labels)
    assert label_summary["legacy_schema"] is True
    migrated_labels = migrate_label_document(legacy, legacy_labels)
    assert migrated_labels["packet_id"] == migrated["packet_id"]
    assert validate_label_document(migrated, migrated_labels)["annotation_count"] == 1

def test_label_document_is_complete_closed_and_immutable():
    assert validate_label_document(packet(), labels())["annotation_count"] == 1
    value = labels(); value["annotations"] = []
    with pytest.raises(LabelingError, match="complete"):
        validate_label_document(packet(), value)
    value = labels(); value["annotations"][0]["rationale"] = "changed"
    with pytest.raises(LabelingError, match="label_batch_id"):
        validate_label_document(packet(), value)
    value = labels(); value["annotator"]["api_key"] = "secret"
    with pytest.raises(LabelingError, match="closed schema"):
        validate_label_document(packet(), value)


def test_not_applicable_and_applicability_must_agree():
    value = labels(label="not_applicable")
    value["annotations"][0]["requirement_applicability"] = "applicable"
    core = {key: item for key, item in value.items() if key != "label_batch_id"}
    value["label_batch_id"] = digest(core)
    with pytest.raises(LabelingError, match="must agree"):
        validate_label_document(packet(), value)


def test_source_citation_must_stay_inside_disclosed_window():
    value = labels()
    value["annotations"][0]["source_citations"][0]["line_end"] = 999
    core = {key: item for key, item in value.items() if key != "label_batch_id"}
    value["label_batch_id"] = digest(core)
    with pytest.raises(LabelingError, match="disclosed source window"):
        validate_label_document(packet(), value)


def test_agreement_reports_multiclass_per_class_and_disagreement_queue():
    report, queue = agreement_report(packet(), labels(), labels("reviewer-b", "non_violation"))
    assert report["exact_agreement"] == 0
    assert report["disagreement_count"] == 1
    assert report["label_disagreement_count"] == 1
    assert report["adjudication_count"] == 1
    assert set(report["cohens_kappa_one_vs_rest"]) == {
        "violation", "non_violation", "insufficient_context", "not_applicable",
    }
    assert queue["items"][0]["candidate_id"] == "case-001"


def test_cli_does_not_overwrite_inputs(tmp_path):
    p, a, b = tmp_path / "p.json", tmp_path / "a.json", tmp_path / "b.json"
    p.write_text(json.dumps(packet()), encoding="utf-8")
    a.write_text(json.dumps(labels()), encoding="utf-8")
    b.write_text(json.dumps(labels("reviewer-b")), encoding="utf-8")
    completed = subprocess.run([
        sys.executable, str(SCRIPT), "agreement", str(p), str(a), str(b),
        "--report", str(a), "--disagreements", str(tmp_path / "queue.json"),
    ], text=True, capture_output=True, check=False)
    assert completed.returncode == 2
    assert "overwrite immutable inputs" in completed.stderr
