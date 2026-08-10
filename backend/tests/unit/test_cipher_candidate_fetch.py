import importlib.util
import json
from pathlib import Path

import pytest


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "fetch_cipher_candidates.py"
SPEC = importlib.util.spec_from_file_location("fetch_cipher_candidates", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


def test_source_lock_is_complete_and_uses_full_commits():
    lock = MODULE.load_lock()
    assert {source["id"] for source in lock["sources"]} == {
        "openssl-3.5.7", "botan-3.12.0", "cryptopp-8.9.0", "mbedtls-3.6.7"
    }
    assert all(len(source["commit"]) == 40 for source in lock["sources"])


def test_cache_inside_repository_is_rejected(tmp_path):
    repository = tmp_path / "repository"
    repository.mkdir()
    with pytest.raises(MODULE.VerificationError, match="outside"):
        MODULE.ensure_external_cache(repository / "vendor", repository)


def test_authoritative_vectors_are_well_formed():
    path = Path(__file__).resolve().parents[2] / "evaluation/candidates/authoritative_vectors.json"
    vectors = json.loads(path.read_text(encoding="utf-8"))["vectors"]
    assert {v["algorithm"] for v in vectors} == {"AES-128", "SEED"}
    for vector in vectors:
        assert len(bytes.fromhex(vector["plaintext"])) == 16
        assert len(bytes.fromhex(vector["ciphertext"])) == 16
        assert len(bytes.fromhex(vector["key"])) in {16, 24, 32}


def test_remote_ref_resolution_handles_annotated_and_lightweight(monkeypatch):
    annotated = {
        "id": "sample", "upstream": "url", "tag": "v1",
        "tag_object": "a" * 40, "commit": "b" * 40,
    }
    monkeypatch.setattr(
        MODULE, "_run", lambda *args, **kwargs: f"{'a' * 40}\trefs/tags/v1\n{'b' * 40}\trefs/tags/v1^{{}}"
    )
    assert MODULE.verify_remote_ref(annotated)["commit"] == "b" * 40


def test_remote_ref_mismatch_fails(monkeypatch):
    source = {"id": "sample", "upstream": "url", "tag": "v1", "commit": "b" * 40}
    monkeypatch.setattr(MODULE, "_run", lambda *args, **kwargs: f"{'c' * 40}\trefs/tags/v1")
    with pytest.raises(MODULE.VerificationError, match="expected"):
        MODULE.verify_remote_ref(source)


def test_authoritative_vectors_pass_with_local_openssl():
    verify_script = SCRIPT.with_name("verify_cipher_vectors.py")
    result = __import__("subprocess").run(
        [__import__("sys").executable, str(verify_script)],
        text=True,
        capture_output=True,
        check=False,
    )
    if "unsupported" in result.stdout.lower() or "unsupported" in result.stderr.lower():
        pytest.skip("local OpenSSL does not expose the SEED legacy provider")
    assert result.returncode == 0, result.stdout + result.stderr
    assert all(item["passed"] for item in json.loads(result.stdout)["results"])
