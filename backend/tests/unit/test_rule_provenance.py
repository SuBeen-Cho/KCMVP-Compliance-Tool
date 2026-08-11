from app.services import mapping_service
from app.services.rule_engine_service import _apply_project_missing_rule
import json
from pathlib import Path

import yaml


def test_lea_048_is_normative_only_for_movs_artifacts():
    provenance = mapping_service.get_provenance("LEA-048")

    assert mapping_service.is_audited_active_normative_rule("LEA-048")
    assert provenance["authority_class"] == "normative_test_interface"
    assert provenance["applies_to"] == ["LEA MOVS 시험 교환 산출물"]
    assert "일반 LEA 소스코드 파일명 규칙" in provenance["does_not_establish"]


def test_reference_distribution_names_are_not_universal_requirements():
    for rule_id in ("LEA-051", "LEA-052"):
        provenance = mapping_service.get_provenance(rule_id)
        assert provenance["status"] == "retired"
        assert provenance["authority_class"] == "reference_implementation_manual"
        assert provenance["evidence_role"] == "implementation_example"
        assert not mapping_service.is_audited_active_normative_rule(rule_id)
        assert any("KCMVP 보안 위반" in limit for limit in provenance["does_not_establish"])


def test_lea_053_does_not_generalize_online_init_return_contract():
    provenance = mapping_service.get_provenance("LEA-053")

    assert provenance["status"] == "retired"
    assert provenance["source_locator"] == "§4.3.12 lea_online_init"
    assert not mapping_service.is_audited_active_normative_rule("LEA-053")
    assert "모든 LEA API의 음수 에러 반환 의무" in provenance["does_not_establish"]


def test_get_provenance_returns_copy_and_handles_legacy_mapping():
    first = mapping_service.get_provenance("LEA-048")
    first["status"] = "tampered"

    assert mapping_service.get_provenance("LEA-048")["status"] == "active"
    assert mapping_service.get_provenance("LEA-001") == {}


def test_provenance_guideline_resolves_from_repository_ruleset():
    path = mapping_service.get_guideline_path("LEA-048")

    assert path is not None
    assert path.name == "VER_001_KAT_파일_규격.md"
    assert "ruleset/LEA" in path.as_posix()


def test_retired_guideline_requires_explicit_opt_in():
    assert mapping_service.get_guideline_path("LEA-053") is None
    path = mapping_service.get_guideline_path("LEA-053", include_retired=True)
    assert path is not None
    assert path.name == "API_004_에러_반환_규격.md"


def test_lea_048_checks_only_discovered_movs_exchange_names(tmp_path):
    rule = {
        "id": "LEA-048",
        "name": "MOVS 시험 교환 파일 명명 적합성",
        "pattern": r"(?i)^LEA(128|192|256)(ECB|CBC|CTR|OFB|CFB(?:1|8|128))(KAT|MMT|MCT)\.(req|rsp|fax)$",
    }
    valid = {"display": "test/LEA128CBCKAT.req", "content": ""}
    malformed = {"display": "test/LEA999CBCKAT.req", "content": ""}

    assert _apply_project_missing_rule(rule, [], tmp_path, search_files=[]) == []
    assert _apply_project_missing_rule(rule, [valid], tmp_path) == []
    findings = _apply_project_missing_rule(rule, [malformed], tmp_path)
    assert len(findings) == 1
    assert findings[0]["pattern_type"] == "artifact_filename"
    assert findings[0]["file"] == "test/LEA999CBCKAT.req"


def test_lea_048_regex_is_anchored_against_disguised_source_name(tmp_path):
    rule = {
        "id": "LEA-048",
        "pattern": r"(?i)^LEA(128|192|256)(ECB|CBC|CTR|OFB|CFB(?:1|8|128))(KAT|MMT|MCT)\.(req|rsp|fax)$",
    }
    disguised = {"display": "test/violations_LEA128CBCKAT.req.c", "content": ""}
    assert _apply_project_missing_rule(rule, [disguised], tmp_path) == []


def test_mapping_status_matches_active_rules_and_rules_only_allowlist():
    backend = Path(__file__).resolve().parents[2]
    active = set()
    for path in (backend / "rules").rglob("*.yaml"):
        payload = yaml.safe_load(path.read_text(encoding="utf-8")) or []
        rows = payload.get("rules", []) if isinstance(payload, dict) else payload
        active.update(row["id"] for row in rows if isinstance(row, dict) and row.get("id"))
    mapping = json.loads((backend / "mapping/rule_to_guideline.json").read_text(encoding="utf-8"))
    mapped = {rule_id for rule_id in mapping if not rule_id.startswith("_")}
    retired = {
        rule_id for rule_id, row in mapping.items()
        if isinstance(row, dict) and (row.get("provenance") or {}).get("status") == "retired"
    }

    assert not (active & retired)
    assert active - mapped == {
        "CFB-001", "CFB-002", "DOC-KEYBIZ-SELFTEST", "ECB-002",
        "OFB-001", "OFB-002", "TRC-004",
    }
    assert {"LEA-051", "LEA-052", "LEA-053"} <= retired - active
