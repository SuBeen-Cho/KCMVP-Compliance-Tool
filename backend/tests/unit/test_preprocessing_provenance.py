import hashlib
import hmac
import json
import os
import shutil
from pathlib import Path

import pytest
import app.services.preprocessing_provenance as provenance_module

from app.services.preprocessing_provenance import (
    EXTRACTOR_ID, EXTRACTOR_VERSION, extractor_sha256,
    unavailable_preprocessing_provenance, verify_preprocessing_provenance,
    capture_trusted_preprocessing, write_private_capture,
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
                      "reason": "private_preprocessing_capture_required"}


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


@pytest.fixture
def c_compiler():
    compiler = shutil.which("clang") or shutil.which("cc") or shutil.which("gcc")
    if compiler is None:
        pytest.skip("C preprocessor unavailable")
    return compiler


def _trusted(tmp_path: Path, c_compiler: str):
    header = tmp_path / "value.h"
    header.write_text("#define VALUE 7\n", encoding="utf-8")
    source = tmp_path / "unit.c"
    source.write_text('#include "value.h"\nint f(void) { return VALUE; }\n', encoding="utf-8")
    return capture_trusted_preprocessing(
        source_path=source, compiler=c_compiler, arguments=["-I", str(tmp_path)],
        cwd=tmp_path, environment={"LC_ALL": "C"},
        allowlisted_environment={"LC_ALL"}, candidate_id="c-1",
        rule_id="LEA-011", runtime_secret=SECRET,
    )


def test_trusted_capture_replays_exactly_and_is_usable(tmp_path, c_compiler):
    captured = _trusted(tmp_path, c_compiler)
    envelope = captured["envelope"]
    result = verify_preprocessing_provenance(
        envelope, SECRET, envelope["provenance"], captured["private_capture"],
    )
    assert result == {"verified": True, "usable": True,
                      "reason": "trusted_preprocessing_replay_exact"}
    assert envelope["compile_command"]["status"] == "observed"
    assert envelope["include_graph"]["node_count"] >= 1
    assert envelope["macro_definitions"]["count"] >= 1


def test_trusted_capture_requires_private_replay_material(tmp_path, c_compiler):
    captured = _trusted(tmp_path, c_compiler)
    envelope = captured["envelope"]
    assert verify_preprocessing_provenance(
        envelope, SECRET, envelope["provenance"],
    )["reason"] == "private_preprocessing_capture_required"


def test_replay_detects_header_change(tmp_path, c_compiler):
    captured = _trusted(tmp_path, c_compiler)
    (tmp_path / "value.h").write_text("#define VALUE 8\n", encoding="utf-8")
    result = verify_preprocessing_provenance(
        captured["envelope"], SECRET, captured["envelope"]["provenance"],
        captured["private_capture"],
    )
    assert result == {"verified": False, "usable": False,
                      "reason": "preprocessing_replay_mismatch"}


def test_capture_rejects_non_allowlisted_environment(tmp_path, c_compiler):
    source = tmp_path / "unit.c"
    source.write_text("int x;\n", encoding="utf-8")
    with pytest.raises(ValueError, match="not_allowlisted"):
        capture_trusted_preprocessing(
            source_path=source, compiler=c_compiler, arguments=[], cwd=tmp_path,
            environment={"SECRET_TOKEN": "no"}, allowlisted_environment={"LC_ALL"},
            candidate_id="c-1", rule_id="LEA-011", runtime_secret=SECRET,
        )


def test_private_capture_is_written_owner_only(tmp_path, c_compiler):
    captured = _trusted(tmp_path, c_compiler)
    path = tmp_path / "private.json"
    write_private_capture(path, captured["private_capture"])
    assert os.stat(path).st_mode & 0o777 == 0o600


@pytest.mark.parametrize("arguments", [
    ["-o", "out.i"], ["-MF", "deps.d"], ["-include", "evil.h"],
    ["-Xclang", "-load"], ["@flags.rsp"], ["other.c"],
    ["--sysroot=/"], ["-I/system"],
])
def test_capture_rejects_unmodelled_or_escaping_flags(tmp_path, c_compiler, arguments):
    source = tmp_path / "unit.c"
    source.write_text("int x;\n", encoding="utf-8")
    with pytest.raises(ValueError, match="argument|include_root"):
        capture_trusted_preprocessing(
            source_path=source, compiler=c_compiler, arguments=arguments, cwd=tmp_path,
            environment={"LC_ALL": "C"}, allowlisted_environment={"LC_ALL"},
            candidate_id="c-1", rule_id="LEA-011", runtime_secret=SECRET,
        )


def test_caller_cannot_expand_fixed_environment_policy(tmp_path, c_compiler):
    source = tmp_path / "unit.c"
    source.write_text("int x;\n", encoding="utf-8")
    with pytest.raises(ValueError, match="not_allowlisted"):
        capture_trusted_preprocessing(
            source_path=source, compiler=c_compiler, arguments=[], cwd=tmp_path,
            environment={"CPATH": str(tmp_path)}, allowlisted_environment={"CPATH"},
            candidate_id="c-1", rule_id="LEA-011", runtime_secret=SECRET,
        )


def test_source_must_be_inside_cwd(tmp_path, c_compiler):
    project = tmp_path / "project"
    project.mkdir()
    source = tmp_path / "outside.c"
    source.write_text("int x;\n", encoding="utf-8")
    with pytest.raises(ValueError, match="source_or_cwd"):
        capture_trusted_preprocessing(
            source_path=source, compiler=c_compiler, arguments=[], cwd=project,
            environment={"LC_ALL": "C"}, allowlisted_environment={"LC_ALL"},
            candidate_id="c-1", rule_id="LEA-011", runtime_secret=SECRET,
        )


def test_unreadable_include_trace_node_is_never_observed(tmp_path, c_compiler, monkeypatch):
    source = tmp_path / "unit.c"
    source.write_text("int x;\n", encoding="utf-8")
    monkeypatch.setattr(provenance_module, "_include_trace", lambda stderr, cwd: [
        {"depth": 1, "path": str(tmp_path / "missing.h"), "content_sha256": None},
    ])
    captured = capture_trusted_preprocessing(
        source_path=source, compiler=c_compiler, arguments=[], cwd=tmp_path,
        environment={"LC_ALL": "C"}, allowlisted_environment={"LC_ALL"},
        candidate_id="c-1", rule_id="LEA-011", runtime_secret=SECRET,
    )
    assert captured["envelope"]["include_graph"] == {
        "status": "unavailable", "graph_sha256": None, "node_count": None,
        "edge_count": None, "reason": "include_trace_content_unavailable",
    }
    assert verify_preprocessing_provenance(
        captured["envelope"], SECRET, captured["envelope"]["provenance"],
        captured["private_capture"],
    )["usable"] is False
