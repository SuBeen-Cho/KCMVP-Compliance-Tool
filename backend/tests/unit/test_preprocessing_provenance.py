import hashlib
import hmac
import json

from app.services.preprocessing_provenance import (
    EXTRACTOR_ID, EXTRACTOR_VERSION, extractor_sha256,
    unavailable_preprocessing_provenance, verify_preprocessing_provenance,
)

SECRET = b"test-only-preprocessing-secret-32bytes"
SOURCE = "#include <stdint.h>\n#define D 1\nint f(void) { return D; }\n"


def envelope():
    return unavailable_preprocessing_provenance(
        source=SOURCE, candidate_id="candidate-1", rule_id="LEA-011",
        reason="snapshot_has_no_build_manifest", runtime_secret=SECRET,
    )


def expected():
    return envelope()["provenance"]


def test_unavailable_context_is_authenticated_but_never_usable():
    value = envelope()
    result = verify_preprocessing_provenance(value, SECRET, value["provenance"])
    assert result == {
        "verified": True, "usable": False,
        "reason": "preprocessing_context_unavailable",
    }
    assert value["provenance"]["extractor_id"] == EXTRACTOR_ID
    assert value["provenance"]["extractor_version"] == EXTRACTOR_VERSION
    assert value["provenance"]["extractor_sha256"] == extractor_sha256()
    assert value["provenance"]["source_sha256"] == hashlib.sha256(SOURCE.encode()).hexdigest()
    assert value["missing_context"] == [
        "compile_command", "include_graph", "macro_definitions", "preprocessed_output",
    ]


def test_source_candidate_rule_and_extractor_are_bound():
    value = envelope()
    wrong = dict(value["provenance"], candidate_id="candidate-2")
    assert verify_preprocessing_provenance(value, SECRET, wrong)["reason"] == "preprocessing_provenance_mismatch"
    wrong = dict(value["provenance"], source_sha256="0" * 64)
    assert verify_preprocessing_provenance(value, SECRET, wrong)["reason"] == "preprocessing_provenance_mismatch"


def test_payload_and_mac_tampering_fail_closed():
    value = envelope()
    value["compile_command"]["reason"] = "invented"
    assert verify_preprocessing_provenance(value, SECRET, expected())["usable"] is False
    assert verify_preprocessing_provenance(value, SECRET, expected())["reason"] == "preprocessing_content_hash_mismatch"
    assert verify_preprocessing_provenance(envelope(), b"x" * 32, expected())["reason"] == "preprocessing_seal_mismatch"


def test_unknown_fields_and_partial_availability_fail_closed():
    value = envelope()
    value["unexpected"] = True
    assert verify_preprocessing_provenance(value, SECRET, expected())["reason"] == "preprocessing_envelope_schema_invalid"

    value = envelope()
    value["compile_command"]["status"] = "observed"
    # Merely changing status cannot turn null hashes into observed evidence;
    # even before deeper observed validation, the authenticated body no longer matches.
    assert verify_preprocessing_provenance(value, SECRET, expected())["usable"] is False


def _reseal(value):
    body = {k: v for k, v in value.items() if k not in {"content_sha256", "seal"}}
    canonical = lambda v: json.dumps(v, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False, allow_nan=False).encode()
    value["content_sha256"] = hashlib.sha256(canonical(body)).hexdigest()
    unsigned = {k: v for k, v in value.items() if k != "seal"}
    value["seal"] = {"algorithm": "HMAC-SHA256",
                     "tag": hmac.new(SECRET, canonical(unsigned), hashlib.sha256).hexdigest()}


def test_resealed_hash_shaped_observed_claim_is_never_usable_without_attestor():
    value = envelope()
    sha = "a" * 64
    value["compile_command"] = {
        "status": "observed", "argv_sha256": sha,
        "working_directory_sha256": sha, "compiler_binary_sha256": sha,
        "reason": None,
    }
    value["include_graph"] = {"status": "observed", "graph_sha256": sha,
                              "node_count": 1, "edge_count": 0, "reason": None}
    value["macro_definitions"] = {"status": "observed", "definitions_sha256": sha,
                                  "count": 1, "reason": None}
    value["preprocessed_output"] = {"status": "observed", "sha256": sha,
                                    "bytes": 1, "reason": None}
    value["missing_context"] = []
    # Deliberately leave the manifest inconsistent and recompute the transport
    # hashes/MAC, reproducing a malicious in-process producer.
    _reseal(value)
    result = verify_preprocessing_provenance(value, SECRET, value["provenance"])
    assert result == {"verified": True, "usable": False,
                      "reason": "trusted_preprocessing_capture_unimplemented"}


def test_copied_expected_cannot_bypass_live_extractor_identity():
    value = envelope()
    value["provenance"]["extractor_version"] = "forged"
    _reseal(value)
    result = verify_preprocessing_provenance(value, SECRET, value["provenance"])
    assert result["usable"] is False
    assert result["reason"] == "preprocessing_extractor_identity_mismatch"


def test_short_runtime_secret_is_rejected():
    try:
        unavailable_preprocessing_provenance(
            source=SOURCE, candidate_id="candidate-1", rule_id="LEA-011",
            reason="no_build", runtime_secret=b"short",
        )
    except ValueError as exc:
        assert "32" in str(exc)
    else:
        raise AssertionError("short secret accepted")
