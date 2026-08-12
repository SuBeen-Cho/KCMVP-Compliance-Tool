import json
import re
from collections import defaultdict
from pathlib import Path

import yaml


BACKEND = Path(__file__).resolve().parents[2]


def test_lea_claim_audit_is_exhaustive_and_disjoint():
    source = json.loads((BACKEND / "mapping/lea_rule_claim_audit.json").read_text())
    rules = yaml.safe_load((BACKEND / "rules/algorithm/lea.yaml").read_text())["rules"]
    active = {row["id"] for row in rules if row["id"].startswith("LEA-")}
    grouped = [rule_id for group in source["dispositions"] for rule_id in group["rule_ids"]]
    assert source["audited_rule_count"] == 53
    assert len(grouped) == len(set(grouped))
    assert set(grouped) == active


def test_only_exact_entailment_group_is_verified():
    claims = json.loads((BACKEND / "mapping/lea_rule_claim_audit.json").read_text())
    audit = json.loads((BACKEND / "mapping/rule_evidence_audit.json").read_text())["rules"]
    exact = next(group for group in claims["dispositions"] if group["decision"] == "verified_exact_entailment")
    assert all(audit[rule_id]["status"] == "verified" for rule_id in exact["rule_ids"])
    for group in claims["dispositions"]:
        if group["decision"] != "verified_exact_entailment":
            assert all(audit[rule_id]["status"] == "review_required" for rule_id in group["rule_ids"])


def test_verified_lea_standard_bindings_are_content_addressed():
    audit = json.loads((BACKEND / "mapping/rule_evidence_audit.json").read_text())["rules"]
    promoted = ["LEA-001", "LEA-002", "LEA-003", "LEA-005", "LEA-011", "LEA-021", "LEA-022", "LEA-023", "LEA-027", "LEA-028", "LEA-029", "LEA-030", "LEA-031"]
    for rule_id in promoted:
        row = audit[rule_id]
        assert row["authority_class"] == "normative_standard"
        assert row["source_locator"]["source_id"] == "LEA_DATASHEET_KO"
        assert row["source_sha256"] == "b0c065c527be33984c779b16f9bd26024b92254bf8bf374a13b95d599fb3b795"
        assert row["evidence_unit_ids"]


def test_verified_lea_bindings_have_occurrence_complete_locators():
    audit = json.loads((BACKEND / "mapping/rule_evidence_audit.json").read_text())["rules"]
    promoted = ["LEA-001", "LEA-002", "LEA-003", "LEA-005", "LEA-011", "LEA-021", "LEA-022", "LEA-023", "LEA-027", "LEA-028", "LEA-029", "LEA-030", "LEA-031"]
    for rule_id in promoted:
        row = audit[rule_id]
        ids = row["evidence_unit_ids"]
        assert all(unit_id.startswith("LEA_DATASHEET_KO:") for unit_id in ids)
        assert row["authority_class"] == "normative_standard"
        assert row["evidence_role"] == "normative_requirement"
        pages = [int(re.search(r":p(\d+):", unit_id).group(1)) for unit_id in ids]
        blocks = [int(re.search(r":b(\d+)$", unit_id).group(1)) for unit_id in ids]
        assert set(row["source_locator"]["pages"]) == set(pages)
        assert all(page in row["source_locator"]["pages"] for page in pages)
        assert row["source_locator"]["blocks"] == blocks


def test_verified_lea_unit_reuse_is_only_the_shared_specification_table():
    audit = json.loads((BACKEND / "mapping/rule_evidence_audit.json").read_text())["rules"]
    promoted = ["LEA-001", "LEA-002", "LEA-003", "LEA-005", "LEA-011", "LEA-021", "LEA-022", "LEA-023", "LEA-027", "LEA-028", "LEA-029", "LEA-030", "LEA-031"]
    consumers = defaultdict(set)
    for rule_id in promoted:
        for unit_id in audit[rule_id]["evidence_unit_ids"]:
            consumers[unit_id].add(rule_id)
    reused = {unit_id: rules for unit_id, rules in consumers.items() if len(rules) > 1}
    assert reused
    allowed = {
        "LEA-001", "LEA-002", "LEA-003", "LEA-027", "LEA-028", "LEA-029", "LEA-031"
    }
    assert all(rules <= allowed for rules in reused.values())
    assert all(
        unit_id.startswith("LEA_DATASHEET_KO:p0011:b")
        or unit_id.startswith("LEA_DATASHEET_KO:p0013:b")
        for unit_id in reused
    )
    assert max(map(len, reused.values())) == 3


def test_exact_entailment_group_does_not_mix_research_or_reference_authority():
    claims = json.loads((BACKEND / "mapping/lea_rule_claim_audit.json").read_text())
    audit = json.loads((BACKEND / "mapping/rule_evidence_audit.json").read_text())["rules"]
    exact = next(group for group in claims["dispositions"] if group["decision"] == "verified_exact_entailment")
    for rule_id in exact["rule_ids"]:
        assert audit[rule_id]["authority_class"] in {"normative_standard", "normative_test_interface"}
