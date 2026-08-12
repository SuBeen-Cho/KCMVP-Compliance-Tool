import json

import pytest

from app.services import evidence_mapping_validator as validator


def test_active_rules_have_explicit_fail_closed_audit_state():
    result = validator.validate_evidence_mapping_registry()

    assert result["active_rule_count"] == 166
    assert result["verified_count"] == 58
    assert result["review_required_count"] == 108


def test_submission_guide_promotions_are_source_bound_and_fail_closed():
    payload = json.loads(validator._AUDIT.read_text(encoding="utf-8"))
    promoted = [
        row for row in payload["rules"].values()
        if row["status"] == "verified"
        and row["source_locator"]["source_id"] == "KCMVP_SUBMISSION_GUIDE_2025_09"
    ]
    assert len(promoted) == 38
    assert all(row["source_sha256"] == "30e4adf58c2b8b3c00422352a6ac276a321717e5b12f2394bdd3443fcefa1c89" for row in promoted)
    assert all(row["applicability"]["scope"] == ["submission_artifacts"] for row in promoted)

    # The guide extraction does not contain an AS09.27 section and the
    # AS02.22 text does not directly establish the rule's stronger claim.
    for rule_id in (
        "CM-003", "CM-004", "DOC-003", "DOC-009", "DOC-012",
        "DOC-014", "DOC-015", "DOC-025", "DOC-027", "DOC-028",
        "DOC-030", "DOC-031", "DOC-035", "DOC-036", "DOC-037",
        "DOC-039", "DOC-040", "DOC-044", "DOC-045", "DOC-046",
        "DOC-049", "DOC-051", "DOC-052", "DOC-053", "DOC-054",
        "DOC-055",
    ):
        assert payload["rules"][rule_id]["status"] == "review_required"
        assert payload["rules"][rule_id]["evidence_unit_ids"] == []


def test_validator_rejects_unverified_exposed_evidence_unit(tmp_path, monkeypatch):
    source = json.loads(validator._AUDIT.read_text(encoding="utf-8"))
    source["rules"]["COM-003"]["evidence_unit_ids"] = ["fabricated-unit"]
    broken = tmp_path / "audit.json"
    broken.write_text(json.dumps(source), encoding="utf-8")
    monkeypatch.setattr(validator, "_AUDIT", broken)

    with pytest.raises(validator.EvidenceMappingValidationError, match="must not expose"):
        validator.validate_evidence_mapping_registry()


def test_known_bad_legacy_mappings_are_not_presented_as_verified():
    payload = json.loads(validator._AUDIT.read_text(encoding="utf-8"))
    for rule_id in (
        "CBC-LEA-005", "COM-002", "COM-003", "COM-005"
    ):
        row = payload["rules"][rule_id]
        assert row["status"] == "review_required"
        assert row["authority_class"] == "unverified"
        assert row["evidence_unit_ids"] == []
        assert "incorrect or overgeneralized" in row["audit_note"]


def test_lea_cbc_ctr_promotions_are_exact_and_algorithm_scoped():
    rows = json.loads(validator._AUDIT.read_text(encoding="utf-8"))["rules"]
    expected = {
        "CBC-001": (
            "LEA_VALIDATION_SYSTEM", [8], [3, 4, 5, 6],
            "normative_test_interface",
        ),
        "CTR-001": (
            "LEA_VALIDATION_SYSTEM", [11], [3, 4, 5, 6, 7],
            "normative_test_interface",
        ),
        "CTR-002": (
            "KCMVP_GVI_PART2_2024_03", [23], [3, 5, 6],
            "normative_guidance",
        ),
    }
    for rule_id, (source_id, pages, blocks, authority) in expected.items():
        row = rows[rule_id]
        assert row["status"] == "verified"
        assert row["authority_class"] == authority
        assert row["applicability"]["algorithm"] == ["LEA"]
        assert row["source_locator"]["source_id"] == source_id
        assert row["source_locator"]["pages"] == pages
        assert row["source_locator"]["blocks"] == blocks
        assert all(unit_id.startswith(f"{source_id}:") for unit_id in row["evidence_unit_ids"])


def test_lea001_is_bound_to_self_contained_normative_standard_units():
    payload = json.loads(validator._AUDIT.read_text(encoding="utf-8"))
    row = payload["rules"]["LEA-001"]
    assert row["status"] == "verified"
    assert row["source_locator"]["source_id"] == "LEA_DATASHEET_KO"
    assert row["evidence_unit_ids"] == [
        f"LEA_DATASHEET_KO:p0011:b{block:03d}" for block in range(3, 9)
    ]


def test_lea_round_graph_promotions_bind_complete_equations_not_keyword_fragments():
    rows = json.loads(validator._AUDIT.read_text(encoding="utf-8"))["rules"]
    expected = {
        "LEA-027": [7, 8, 6],
        "LEA-028": [10, 11, 9],
        "LEA-029": [13, 14, 12],
        "LEA-030": [15],
        "LEA-031": [7, 8, 6, 10, 11, 9, 13, 14, 12],
    }
    for rule_id, blocks in expected.items():
        row = rows[rule_id]
        assert row["status"] == "verified"
        assert row["authority_class"] == "normative_standard"
        assert row["source_sha256"] == (
            "b0c065c527be33984c779b16f9bd26024b92254bf8bf374a13b95d599fb3b795"
        )
        assert row["source_locator"]["pages"] == [13]
        assert row["source_locator"]["blocks"] == blocks
        assert row["evidence_unit_ids"] == [
            f"LEA_DATASHEET_KO:p0013:b{block:03d}" for block in blocks
        ]


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
