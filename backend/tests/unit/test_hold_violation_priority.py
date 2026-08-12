import pytest

from experiments.hold_violation_priority import HoldTriageInputError, summarize


def _gap():
    return {"failclosed_rule_count": 3, "rules": [
        {"rule_id": "AES-001", "primary_gap": "exact_locator_gap"},
        {"rule_id": "CBC-001", "primary_gap": "detector_scope"},
        {"rule_id": "CBC-002", "primary_gap": "authority_gap"},
    ]}


def test_closed_priority_counts_clones_and_separates_mapping_potential():
    rows = [
        {"rule_id": "AES-001", "family": "AES", "group_id": "g1", "stage": "hold", "label": "violation"},
        {"rule_id": "AES-001", "family": "AES", "group_id": "g1", "stage": "hold", "label": "violation"},
        {"rule_id": "CBC-001", "family": "CBC", "group_id": "g2", "stage": "hold", "label": "violation"},
        {"rule_id": "CBC-002", "family": "CBC", "group_id": "g3", "stage": "ai_ready", "label": "violation"},
    ]
    result = summarize(rows, _gap(), input_sha256={"x": "a" * 64})
    assert result["target"]["proxy_violation_occurrences"] == 3
    assert result["target"]["unique_clone_groups"] == 2
    assert result["rule_priority"][0]["rule_id"] == "AES-001"
    assert result["rule_priority"][0]["unique_clone_groups"] == 1
    assert result["rule_priority"][0]["cumulative_population_ratio"] == pytest.approx(2 / 3)
    assert result["coverage_potential_upper_bound"]["evidence_or_contract_work_occurrences"] == 2
    assert [row["rule_id"] for row in result["evidence_mapping_priority"]] == ["AES-001"]


def test_missing_gap_rule_fails_closed():
    rows = [{"rule_id": "NEW-001", "family": "NEW", "group_id": "g", "stage": "hold", "label": "violation"}]
    with pytest.raises(HoldTriageInputError, match="missing"):
        summarize(rows, _gap(), input_sha256={})


def test_verified_but_held_rule_is_routing_gap_not_mapping_gap():
    rows = [{"rule_id": "LEA-011", "family": "LEA", "group_id": "g", "stage": "hold", "label": "violation"}]
    audit = {"rules": {"LEA-011": {"status": "verified"}}}
    result = summarize(rows, _gap(), evidence_audit=audit, input_sha256={})
    assert result["rule_priority"][0]["audit_status"] == "verified"
    assert result["rule_priority"][0]["primary_gap"] == "routing_or_selector_gap"


def test_current_verified_status_overrides_stale_failclosed_gap_row():
    rows = [{"rule_id": "AES-001", "family": "AES", "group_id": "g", "stage": "hold", "label": "violation"}]
    audit = {"rules": {"AES-001": {"status": "verified"}}}
    result = summarize(rows, _gap(), evidence_audit=audit, input_sha256={})
    assert result["gap_distribution"] == {"routing_or_selector_gap": 1}
    assert result["coverage_potential_upper_bound"]["evidence_or_contract_work_occurrences"] == 0


def test_open_fields_are_rejected_to_prevent_content_disclosure():
    rows = [{"rule_id": "AES-001", "family": "AES", "group_id": "g", "stage": "hold",
             "label": "violation", "snippet": "secret"}]
    with pytest.raises(HoldTriageInputError, match="closed"):
        summarize(rows, _gap(), input_sha256={})
