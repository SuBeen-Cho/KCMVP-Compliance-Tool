"""Closed, authenticated provenance contract for C preprocessing inputs.

The contract does not try to reconstruct a build from a source snippet.  A
caller must either bind every compiler input needed to reproduce preprocessing
or record that the context is unavailable.  Both forms are authenticated, but
only a completely observed form can be consumed as preprocessing evidence.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1.0"
EXTRACTOR_ID = "sealed-c-preprocessing-provenance"
EXTRACTOR_VERSION = "1.0.0"

_PROVENANCE_KEYS = {
    "extractor_id", "extractor_version", "extractor_sha256",
    "source_sha256", "input_manifest_sha256", "candidate_id", "rule_id",
}
_ENVELOPE_KEYS = {
    "schema_version", "provenance", "compile_command", "include_graph",
    "macro_definitions", "preprocessed_output", "missing_context",
    "content_sha256", "seal",
}
_COMPONENT_KEYS = {
    "compile_command": {"status", "argv_sha256", "working_directory_sha256",
                        "compiler_binary_sha256", "reason"},
    "include_graph": {"status", "graph_sha256", "node_count", "edge_count", "reason"},
    "macro_definitions": {"status", "definitions_sha256", "count", "reason"},
    "preprocessed_output": {"status", "sha256", "bytes", "reason"},
}


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode()


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _is_sha(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def extractor_sha256() -> str:
    return _sha(Path(__file__).read_bytes())


def unavailable_preprocessing_provenance(*, source: str, candidate_id: str,
                                         rule_id: str, reason: str,
                                         runtime_secret: bytes) -> dict[str, Any]:
    """Record unavailable build context without inventing compiler evidence."""
    if not all(isinstance(item, str) and item for item in (candidate_id, rule_id, reason)):
        raise ValueError("preprocessing provenance identifiers and reason are required")
    source_hash = _sha(source.encode())
    missing = ["compile_command", "include_graph", "macro_definitions",
               "preprocessed_output"]
    provenance = {
        "extractor_id": EXTRACTOR_ID,
        "extractor_version": EXTRACTOR_VERSION,
        "extractor_sha256": extractor_sha256(),
        "source_sha256": source_hash,
        # The manifest explicitly binds the absence assertion to this source
        # and reason.  It is not a hash of guessed build flags.
        "input_manifest_sha256": _sha(_canonical({
            "source_sha256": source_hash, "status": "unavailable",
            "reason": reason, "missing": missing,
        })),
        "candidate_id": candidate_id,
        "rule_id": rule_id,
    }
    envelope: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "provenance": provenance,
        "compile_command": {
            "status": "unavailable", "argv_sha256": None,
            "working_directory_sha256": None, "compiler_binary_sha256": None,
            "reason": reason,
        },
        "include_graph": {
            "status": "unavailable", "graph_sha256": None,
            "node_count": None, "edge_count": None, "reason": reason,
        },
        "macro_definitions": {
            "status": "unavailable", "definitions_sha256": None,
            "count": None, "reason": reason,
        },
        "preprocessed_output": {
            "status": "unavailable", "sha256": None, "bytes": None,
            "reason": reason,
        },
        "missing_context": missing,
    }
    envelope["content_sha256"] = _sha(_canonical(envelope))
    if not isinstance(runtime_secret, bytes) or len(runtime_secret) < 32:
        raise ValueError("preprocessing provenance seal requires at least 32 secret bytes")
    envelope["seal"] = {
        "algorithm": "HMAC-SHA256",
        "tag": hmac.new(runtime_secret, _canonical(envelope), hashlib.sha256).hexdigest(),
    }
    return envelope


def verify_preprocessing_provenance(envelope: dict[str, Any], runtime_secret: bytes,
                                    expected: dict[str, str]) -> dict[str, Any]:
    """Authenticate a closed envelope and fail closed unless all inputs exist."""
    unknown = lambda reason: {"verified": False, "usable": False, "reason": reason}
    if not isinstance(envelope, dict) or set(envelope) != _ENVELOPE_KEYS:
        return unknown("preprocessing_envelope_schema_invalid")
    if envelope.get("schema_version") != SCHEMA_VERSION:
        return unknown("preprocessing_schema_mismatch")
    provenance = envelope.get("provenance")
    if (not isinstance(provenance, dict) or set(provenance) != _PROVENANCE_KEYS
            or any(not isinstance(provenance.get(k), str) or not provenance[k]
                   for k in _PROVENANCE_KEYS)
            or any(not _is_sha(provenance.get(k)) for k in
                   ("extractor_sha256", "source_sha256", "input_manifest_sha256"))):
        return unknown("preprocessing_provenance_invalid")
    if not isinstance(expected, dict) or set(expected) != _PROVENANCE_KEYS or provenance != expected:
        return unknown("preprocessing_provenance_mismatch")
    # Expected values alone are not an attestor: callers can copy them from a
    # forged envelope.  Bind the implementation identity to the running code.
    if (provenance.get("extractor_id") != EXTRACTOR_ID
            or provenance.get("extractor_version") != EXTRACTOR_VERSION
            or provenance.get("extractor_sha256") != extractor_sha256()):
        return unknown("preprocessing_extractor_identity_mismatch")
    for name, keys in _COMPONENT_KEYS.items():
        value = envelope.get(name)
        if not isinstance(value, dict) or set(value) != keys or value.get("status") not in {"observed", "unavailable"}:
            return unknown(f"{name}_schema_invalid")
        if value["status"] == "unavailable":
            data_keys = keys - {"status", "reason"}
            if (not isinstance(value.get("reason"), str) or not value["reason"]
                    or any(value.get(key) is not None for key in data_keys)):
                return unknown(f"{name}_unavailable_invalid")
        else:
            if value.get("reason") is not None:
                return unknown(f"{name}_observed_invalid")
            if name == "compile_command" and not all(_is_sha(value.get(key)) for key in
                    ("argv_sha256", "working_directory_sha256", "compiler_binary_sha256")):
                return unknown("compile_command_observed_invalid")
            if name == "include_graph" and (not _is_sha(value.get("graph_sha256"))
                    or not all(isinstance(value.get(key), int) and value[key] >= 0
                               for key in ("node_count", "edge_count"))):
                return unknown("include_graph_observed_invalid")
            if name == "macro_definitions" and (not _is_sha(value.get("definitions_sha256"))
                    or not isinstance(value.get("count"), int) or value["count"] < 0):
                return unknown("macro_definitions_observed_invalid")
            if name == "preprocessed_output" and (not _is_sha(value.get("sha256"))
                    or not isinstance(value.get("bytes"), int) or value["bytes"] < 0):
                return unknown("preprocessed_output_observed_invalid")
    body = {k: v for k, v in envelope.items() if k not in {"content_sha256", "seal"}}
    if envelope.get("content_sha256") != _sha(_canonical(body)):
        return unknown("preprocessing_content_hash_mismatch")
    seal = envelope.get("seal")
    unsigned = {k: v for k, v in envelope.items() if k != "seal"}
    if (not isinstance(runtime_secret, bytes) or len(runtime_secret) < 32
            or not isinstance(seal, dict) or set(seal) != {"algorithm", "tag"}
            or seal.get("algorithm") != "HMAC-SHA256" or not _is_sha(seal.get("tag"))):
        return unknown("preprocessing_seal_missing")
    tag = hmac.new(runtime_secret, _canonical(unsigned), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(tag, seal["tag"]):
        return unknown("preprocessing_seal_mismatch")
    statuses = [envelope[name]["status"] for name in _COMPONENT_KEYS]
    missing = envelope.get("missing_context")
    if not isinstance(missing, list) or any(item not in _COMPONENT_KEYS for item in missing) or len(set(missing)) != len(missing):
        return unknown("preprocessing_missing_context_invalid")
    if statuses != ["observed"] * len(statuses):
        expected_missing = [name for name in _COMPONENT_KEYS if envelope[name]["status"] == "unavailable"]
        if missing != expected_missing:
            return unknown("preprocessing_missing_context_mismatch")
        return {"verified": True, "usable": False, "reason": "preprocessing_context_unavailable"}
    if missing:
        return unknown("preprocessing_observed_with_missing_context")
    # This version deliberately has no trusted observed-capture builder.  Hash
    # shaped assertions—even with a valid transport MAC—do not prove compiler
    # invocation, environment, include contents, macro order, diagnostics, or
    # replay equivalence.  Keep observed envelopes fail-closed until such an
    # attestor is implemented and its manifest is independently recomputed.
    return {"verified": True, "usable": False,
            "reason": "trusted_preprocessing_capture_unimplemented"}
