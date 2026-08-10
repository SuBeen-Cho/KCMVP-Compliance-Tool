import importlib.util
import json
from pathlib import Path

import pytest


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "fetch_cipher_candidates.py"
SPEC = importlib.util.spec_from_file_location("fetch_cipher_candidates", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)

VERIFY_SCRIPT = SCRIPT.with_name("verify_cipher_vectors.py")
VERIFY_SPEC = importlib.util.spec_from_file_location("verify_cipher_vectors", VERIFY_SCRIPT)
VERIFY_MODULE = importlib.util.module_from_spec(VERIFY_SPEC)
assert VERIFY_SPEC.loader
VERIFY_SPEC.loader.exec_module(VERIFY_MODULE)


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
    assert {v["algorithm"] for v in vectors} == {
        "AES-128", "SEED", "ARIA-128", "ARIA-192", "ARIA-256"
    }
    assert len(vectors) == 8
    assert sum(v["algorithm"] == "SEED" for v in vectors) == 4
    assert sum(v["algorithm"].startswith("ARIA-") for v in vectors) == 3
    for vector in vectors:
        assert len(bytes.fromhex(vector["plaintext"])) == 16
        assert len(bytes.fromhex(vector["ciphertext"])) == 16
        assert len(bytes.fromhex(vector["key"])) in {16, 24, 32}


def test_source_lock_records_aria_capable_implementations():
    sources = {source["id"]: source for source in MODULE.load_lock()["sources"]}
    for source_id in (
        "openssl-3.5.7", "botan-3.12.0", "cryptopp-8.9.0", "mbedtls-3.6.7"
    ):
        assert "ARIA" in sources[source_id]["algorithms"]


def test_source_lock_does_not_claim_each_checkout_was_vector_tested():
    policy = MODULE.load_lock()["policy"]
    assert policy["system_reference_vector_validation"] is True
    assert policy["upstream_checkout_vector_validation"] is False


@pytest.mark.parametrize(
    ("algorithm", "expected"),
    [
        ("AES-128", "aes-128-ecb"),
        ("SEED", "seed-ecb"),
        ("ARIA-128", "aria-128-ecb"),
        ("ARIA-192", "aria-192-ecb"),
        ("ARIA-256", "aria-256-ecb"),
    ],
)
def test_vector_algorithm_maps_to_openssl_cipher(algorithm, expected):
    assert VERIFY_MODULE.cipher_name(algorithm) == expected


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


VECTORS = json.loads(
    (Path(__file__).resolve().parents[2] / "evaluation/candidates/authoritative_vectors.json")
    .read_text(encoding="utf-8")
)["vectors"]


@pytest.mark.parametrize(
    "vector", VECTORS, ids=lambda item: item["source"].replace("IETF ", "")
)
def test_authoritative_vector_passes_when_cipher_is_available(vector):
    result = VERIFY_MODULE.verify_vector(vector)
    if result.get("status") == "unavailable":
        pytest.skip(f"local OpenSSL capability unavailable: {vector['algorithm']}")
    assert result["status"] != "error", result.get("error")
    assert result["status"] != "mismatch", result
    assert result["passed"] is True


def test_openssl_report_records_version_and_provider_metadata():
    metadata = VERIFY_MODULE.openssl_metadata()
    assert metadata["version"]
    assert isinstance(metadata["providers"], list)
    assert metadata["provider_details"] is not None or metadata["provider_query_error"]
