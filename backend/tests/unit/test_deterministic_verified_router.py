"""Verified literal candidates bypass LLM without broad semantic promotion."""
import copy
import json
from pathlib import Path

import pytest

from app.services.llm.candidate_selector import _select_l3_candidates
from app.services.llm import l3_judge
from app.services.rag_grounding import route_rag
from app.services import rag_service
from app.services.rag_service import run_l2_rag_context
from app.services.rule_engine_service import _apply_rule_to_file, load_ruleset

RULE_ROOT = Path(__file__).resolve().parents[2] / "rules"


def finding(tmp_path, group, filename, rule_id, source):
    rule = next(r for r in load_ruleset(RULE_ROOT, "mode", group) if r["id"] == rule_id)
    path = tmp_path / filename
    path.write_text(source, encoding="utf-8")
    rows = _apply_rule_to_file(path, source, rule, tmp_path)
    assert len(rows) == 1
    rows[0]["detection_semantics"] = "prohibited_presence"
    return rows[0]


@pytest.mark.parametrize("group,filename,rule_id,source", [
    ("gcm", "gcm.c", "GCM-002", "int gcm_tag_len_bytes = 10;"),
    ("ccm", "ccm.c", "CCM-003", "int ccm_tag_len_bytes = 12;"),
    ("cmac", "cmac.c", "CMAC-004", "int lea_cmac_tag_bits = 64;"),
])
def test_verified_explicit_literal_gets_official_provenance_not_llm(
    tmp_path, group, filename, rule_id, source,
):
    row = finding(tmp_path, group, filename, rule_id, source)
    routed = run_l2_rag_context([row])[0]
    assert routed["rag_route"]["decision"] == "deterministic_verified_rule"
    assert routed["decision_source"] == "deterministic_l1_official_evidence"
    assert routed["llm_calls_avoided"] == 1
    assert routed["official_evidence_provenance"]
    assert all(set(item) == {"unit_id", "source_id", "locator", "span_sha256", "source_sha256"}
               for item in routed["official_evidence_provenance"])
    assert _select_l3_candidates([routed]) == []


def test_general_semantic_and_forged_or_mutated_marker_never_bypass(tmp_path):
    general = {"rule_id":"LEA-001", "pattern_type":"semantic", "confidence":"확정",
               "needs_ai_review":False, "detection_semantics":"prohibited_presence"}
    assert route_rag(general)["decision"] == "retrieve"
    row = finding(tmp_path, "gcm", "gcm.c", "GCM-002", "int gcm_tag_len_bytes = 10;")
    row["deterministic_literal_evidence"]["matched_span"] = "int gcm_tag_len_bytes = 16;"
    assert route_rag(row)["decision"] == "retrieve"


def test_all_deterministic_candidates_require_no_api_key(tmp_path, monkeypatch):
    row = finding(tmp_path, "gcm", "gcm.c", "GCM-002", "int gcm_tag_len_bytes = 10;")
    routed = run_l2_rag_context([row])[0]
    monkeypatch.setattr(l3_judge, "L3_PROVIDER", "gemini")
    monkeypatch.setattr(l3_judge, "GOOGLE_API_KEY", "")
    assert l3_judge.run_l3_contextualizer(
        {"files": [{"path":"gcm.c", "content":"int gcm_tag_len_bytes = 10;"}]},
        [routed],
    ) == []
    assert l3_judge.run_l3_contextualizer(
        {"files": [{"path":"gcm.c", "content":"int gcm_tag_len_bytes = 10;"}]},
        [routed], _preselected=True,
    ) == []


def test_forged_route_and_cloned_candidate_cannot_bypass_selector(tmp_path):
    forged = {
        "rule_id": "GCM-002", "pattern_type": "regex", "confidence": "확정",
        "needs_ai_review": False,
        "rag_route": {"decision": "deterministic_verified_rule"},
    }
    assert _select_l3_candidates([forged]) == [forged]

    routed = run_l2_rag_context([
        finding(tmp_path, "gcm", "gcm.c", "GCM-002", "int gcm_tag_len_bytes = 10;")
    ])[0]
    cloned = copy.deepcopy(routed)
    cloned["file"] = "cloned.c"
    assert _select_l3_candidates([cloned]) == [cloned]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("line", "1"),
        ("end_line", None),
        ("snippet", ["int gcm_tag_len_bytes = 10;"]),
        ("scope", "file"),
        ("rule_id", "CCM-003"),
    ],
)
def test_malformed_or_mixed_candidate_identity_revokes_seal(tmp_path, field, value):
    row = finding(tmp_path, "gcm", "gcm.c", "GCM-002", "int gcm_tag_len_bytes = 10;")
    row[field] = value
    assert route_rag(row)["decision"] == "retrieve"


def test_rehashed_altered_span_and_provenance_tampering_revoke_bypass(tmp_path):
    row = finding(tmp_path, "gcm", "gcm.c", "GCM-002", "int gcm_tag_len_bytes = 10;")
    marker = row["deterministic_literal_evidence"]
    marker["matched_span"] = "gcm_tag_len_bytes = 9"
    import hashlib
    marker["matched_span_sha256"] = hashlib.sha256(marker["matched_span"].encode()).hexdigest()
    assert route_rag(row)["decision"] == "retrieve"

    routed = run_l2_rag_context([
        finding(tmp_path, "gcm", "fresh.c", "GCM-002", "int gcm_tag_len_bytes = 10;")
    ])[0]
    routed["official_evidence_provenance"][0]["span_sha256"] = "0" * 64
    assert _select_l3_candidates([routed]) == [routed]


def test_missing_official_index_downgrades_and_retains_candidate(tmp_path, monkeypatch):
    row = finding(tmp_path, "gcm", "gcm.c", "GCM-002", "int gcm_tag_len_bytes = 10;")
    monkeypatch.delenv("KCMVP_OFFICIAL_EVIDENCE_INDEX", raising=False)
    monkeypatch.setattr(rag_service, "_DEFAULT_OFFICIAL_INDEX", tmp_path / "missing.json")
    rag_service._official_index_cache.clear()
    routed = run_l2_rag_context([row])[0]
    assert routed["rag_route"]["decision"] == "retrieve"
    assert routed["rag_grounding_status"] == "evidence_absent"
    assert _select_l3_candidates([routed]) == [routed]


def test_index_changed_after_l2_revokes_l3_bypass(tmp_path, monkeypatch):
    source_index = rag_service._official_index_path()
    payload = json.loads(source_index.read_text(encoding="utf-8"))
    private_index = tmp_path / "official.json"
    private_index.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setenv("KCMVP_OFFICIAL_EVIDENCE_INDEX", str(private_index))
    rag_service._official_index_cache.clear()

    routed = run_l2_rag_context([
        finding(tmp_path, "gcm", "gcm.c", "GCM-002", "int gcm_tag_len_bytes = 10;")
    ])[0]
    assert _select_l3_candidates([routed]) == []

    target_id = routed["official_evidence_provenance"][0]["unit_id"]
    for unit in payload["units"]:
        if unit.get("unit_id") == target_id:
            unit["text"] += "tampered"
            break
    private_index.write_text(json.dumps(payload), encoding="utf-8")
    rag_service._official_index_cache.clear()
    assert _select_l3_candidates([routed]) == [routed]


def test_forged_bypass_without_api_is_not_silently_dropped(monkeypatch):
    forged = {
        "rule_id": "GCM-002", "pattern_type": "regex", "confidence": "확정",
        "needs_ai_review": False,
        "rag_route": {"decision": "deterministic_verified_rule"},
    }
    monkeypatch.setattr(l3_judge, "L3_PROVIDER", "gemini")
    monkeypatch.setattr(l3_judge, "GOOGLE_API_KEY", "")
    with pytest.raises(l3_judge.GeminiConfigurationError):
        l3_judge.run_l3_contextualizer({"files": []}, [forged], _preselected=True)
