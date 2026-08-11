from pathlib import Path

from experiments.inventory import build_rule_inventory
from experiments.manifest import build_manifest


BACKEND = Path(__file__).resolve().parents[2]
REPO = BACKEND.parent


def test_rule_inventory_is_unique_and_current():
    inventory = build_rule_inventory(BACKEND / "rules")
    assert inventory["total_rules"] == 165
    assert inventory["unique_rule_ids"] == 165
    assert inventory["duplicate_rule_ids"] == []


def test_manifest_records_dirty_code_and_artifact_hashes():
    manifest = build_manifest(REPO)
    assert len(manifest["code"]["commit"]) == 40
    assert len(manifest["code"]["workspace_sha256"]) == 64
    assert "status" not in manifest["code"]
    assert manifest["artifacts"]["rules"]["total_rules"] == 165
    assert len(manifest["artifacts"]["prompts_sha256"]) == 64
    assert "api_key_present" not in manifest["models"]


def test_manifest_does_not_disclose_external_input_path(tmp_path):
    secret_named = tmp_path / "confidential-client-name.zip"
    secret_named.write_bytes(b"test")
    manifest = build_manifest(REPO, [secret_named])
    serialized = str(manifest)
    assert "confidential-client-name" not in serialized
    assert str(tmp_path) not in serialized
