from pathlib import Path


def test_gcm_002_detects_only_explicit_out_of_profile_byte_lengths(tmp_path: Path):
    from app.services.rule_engine_service import run_rule_engine

    rules_dir = Path(__file__).resolve().parents[2] / "rules"
    source = tmp_path / "gcm_profile.c"
    source.write_text(
        """size_t gcm_tag_len_bytes = 12;
size_t gmac_tag_bytes = 17;
size_t accepted_tag_len_bytes = 14;
size_t full_tag_bytes = 16;
size_t tag_len = 12; /* LEA API convention: bytes */
size_t gcm_tag_len_bits = 96;
size_t gcm_tag_len_bits_valid = 112;
""",
        encoding="utf-8",
    )

    findings = run_rule_engine(
        {"files": [{"path": str(source)}]}, rules_dir, tmp_path
    )
    gcm_findings = [item for item in findings if item["rule_id"] == "GCM-002"]

    assert [item["line"] for item in gcm_findings] == [1, 2, 5, 6]
    assert all(item["detection_semantics"] == "prohibited_presence" for item in gcm_findings)


def test_gcm_002_does_not_apply_without_gcm_domain_anchor(tmp_path: Path):
    from app.services.rule_engine_service import run_rule_engine

    rules_dir = Path(__file__).resolve().parents[2] / "rules"
    source = tmp_path / "generic_mac.c"
    source.write_text("size_t tag_len_bytes = 8;\n", encoding="utf-8")

    findings = run_rule_engine(
        {"files": [{"path": str(source)}]}, rules_dir, tmp_path
    )

    assert not [item for item in findings if item["rule_id"] == "GCM-002"]
