import json

import pytest

from app.services import evidence_mapping_validator as validator


def test_active_rules_have_explicit_fail_closed_audit_state():
    result = validator.validate_evidence_mapping_registry()

    assert result["active_rule_count"] == 165
    assert result["verified_count"] == 3
    assert result["review_required_count"] == 162


def test_validator_rejects_unverified_exposed_evidence_unit(tmp_path, monkeypatch):
    source = json.loads(validator._AUDIT.read_text(encoding="utf-8"))
    source["rules"]["CTR-001"]["evidence_unit_ids"] = ["fabricated-unit"]
    broken = tmp_path / "audit.json"
    broken.write_text(json.dumps(source), encoding="utf-8")
    monkeypatch.setattr(validator, "_AUDIT", broken)

    with pytest.raises(validator.EvidenceMappingValidationError, match="must not expose"):
        validator.validate_evidence_mapping_registry()


def test_known_bad_legacy_mappings_are_not_presented_as_verified():
    payload = json.loads(validator._AUDIT.read_text(encoding="utf-8"))
    for rule_id in (
        "CTR-001", "CBC-LEA-005", "LEA-001", "COM-002", "COM-003", "COM-005"
    ):
        row = payload["rules"][rule_id]
        assert row["status"] == "review_required"
        assert row["authority_class"] == "unverified"
        assert row["evidence_unit_ids"] == []
        assert "incorrect or overgeneralized" in row["audit_note"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_sha256", "not-a-sha256"),
        ("applicability", "LEA"),
        ("source_locator", {"page": 1}),
        ("evidence_unit_ids", ["OTHER:p0001:b001"]),
    ],
)
def test_validator_rejects_forged_verified_metadata(tmp_path, monkeypatch, field, value):
    source = json.loads(validator._AUDIT.read_text(encoding="utf-8"))
    source["rules"]["GCM-002"][field] = value
    broken = tmp_path / "audit.json"
    broken.write_text(json.dumps(source), encoding="utf-8")
    monkeypatch.setattr(validator, "_AUDIT", broken)

    with pytest.raises(validator.EvidenceMappingValidationError):
        validator.validate_evidence_mapping_registry()
