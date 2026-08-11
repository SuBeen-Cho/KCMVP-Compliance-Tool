import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]


def load(name):
    return json.loads((ROOT / "rag" / name).read_text(encoding="utf-8"))


def test_external_registry_is_hash_bound_and_nonverbatim():
    data=load("external_official_sources.json")
    assert data["collection"] == "external_official_source_registry"
    ids={s["source_id"] for s in data["sources"]}
    assert ids == {"NIST_FIPS_197_UPD1_2023","RFC_5794_ARIA_2010","RFC_4269_SEED_2005","ISO_IEC_18033_3_2010"}
    for source in data["sources"]:
        assert source["canonical_url"].startswith("https://")
        if source["storage_policy"] == "remote_hash_bound_no_verbatim_commit":
            assert re.fullmatch(r"[0-9a-f]{64}", source["expected_sha256"])
            assert source["byte_length"] > 0
            assert source["retrieved_at"] == data["fetched_at"]
    iso=next(s for s in data["sources"] if s["source_id"].startswith("ISO_"))
    assert iso["expected_sha256"] is None and iso["storage_policy"] == "metadata_only_no_evidence_units"


def test_rfc_status_is_informational_not_normative_kcmvp():
    sources=load("external_official_sources.json")["sources"]
    for source in sources:
        if source["source_id"].startswith("RFC_"):
            assert source["document_status"].startswith("informational")
            assert source["evidence_role"] == "informational_algorithm_definition"
            assert source["kcmvp_role"] == "cross_check_only_not_normative_kcmvp_requirement"


def test_candidate_units_are_nonverbatim_and_fail_closed_before_review():
    data=load("external_evidence_candidates.json")
    allowed={"AES-001","AES-002","AES-003","ARIA-001","SEED-001"}
    mapped={rule for unit in data["candidates"] for rule in unit["candidate_rules"]}
    assert mapped == allowed
    assert all("text" not in unit and "span" not in unit and unit["claim_summary"] for unit in data["candidates"])
    audit=json.loads((ROOT/"mapping/rule_evidence_audit.json").read_text(encoding="utf-8"))["rules"]
    assert all(audit[rule]["status"] != "verified" for rule in allowed)
