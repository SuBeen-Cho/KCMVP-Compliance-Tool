import json
from pathlib import Path

from experiments.failclosed_gap_audit import build, validate

BACKEND = Path(__file__).resolve().parents[2]


def test_failclosed_taxonomy_is_exhaustive_and_closed():
    payload = build(BACKEND / "rules", BACKEND / "mapping/rule_evidence_audit.json")
    validate(payload)
    audit = json.loads((BACKEND / "mapping/rule_evidence_audit.json").read_text())["rules"]
    expected = {rule_id for rule_id, row in audit.items() if row["status"] != "verified"}
    assert payload["failclosed_rule_count"] == 113
    assert {row["rule_id"] for row in payload["rules"]} == expected
    assert sum(payload["gap_counts"].values()) == 113


def test_no_failclosed_row_is_accidentally_promoted():
    payload = build(BACKEND / "rules", BACKEND / "mapping/rule_evidence_audit.json")
    assert all(row["decision"] == "remain_fail_closed" for row in payload["rules"])
    assert all(sum(bool(row[key]) for key in payload["gap_counts"]) == 1 for row in payload["rules"])


def test_mode_common_entailment_review_covers_every_failclosed_rule():
    review = json.loads((BACKEND / "mapping/mode_common_entailment_review.json").read_text())
    audit = json.loads((BACKEND / "mapping/rule_evidence_audit.json").read_text())["rules"]
    rules = {}
    for path in (BACKEND / "rules").rglob("*.yaml"):
        data = __import__("yaml").safe_load(path.read_text()) or {}
        for row in data.get("rules", []):
            rules[row["id"]] = row
    expected = {rid for rid, state in audit.items() if state["status"] != "verified" and rules[rid].get("category") in {"mode", "common"}}
    grouped = [rid for group in review["groups"] for rid in group["rule_ids"]]
    assert review["decision"] == "three_exact_lea_scoped_promotions"
    assert review["new_verified_rule_ids"] == ["CBC-001", "CTR-001", "CTR-002"]
    assert review["reviewed_rule_count"] == 36
    assert len(grouped) == len(set(grouped))
    assert set(grouped) == expected
