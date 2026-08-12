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
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1.0"
EXTRACTOR_ID = "sealed-c-preprocessing-provenance"
EXTRACTOR_VERSION = "1.1.0"

PRIVATE_CAPTURE_SCHEMA = "1.0"
_SAFE_ENVIRONMENT = frozenset({"LANG", "LC_ALL"})
_PRIVATE_KEYS = {
    "schema_version", "compiler", "argv", "cwd", "environment",
    "include_trace", "macro_events", "exit_code", "diagnostics_sha256",
    "preprocessed_sha256", "preprocessed_bytes", "capture_seal",
}

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


def _require_secret(runtime_secret: bytes) -> None:
    if not isinstance(runtime_secret, bytes) or len(runtime_secret) < 32:
        raise ValueError("preprocessing provenance seal requires at least 32 secret bytes")


def _seal_private(body: dict[str, Any], runtime_secret: bytes) -> dict[str, Any]:
    _require_secret(runtime_secret)
    return {"algorithm": "HMAC-SHA256", "tag": hmac.new(
        runtime_secret, _canonical(body), hashlib.sha256,
    ).hexdigest()}


def _compiler_identity(compiler: str) -> dict[str, str]:
    resolved = shutil.which(compiler)
    if resolved is None:
        raise ValueError("compiler_not_found")
    path = Path(resolved).resolve()
    if not path.is_file():
        raise ValueError("compiler_not_regular_file")
    version = subprocess.run(
        [str(path), "--version"], check=False, capture_output=True, timeout=10,
    )
    return {
        "resolved_path": str(path),
        "binary_sha256": _sha(path.read_bytes()),
        "version_sha256": _sha(version.stdout + b"\0" + version.stderr),
    }


def _include_trace(stderr: bytes, cwd: Path) -> list[dict[str, Any]]:
    """Parse GCC/Clang -H output, preserving order and hashing local files."""
    trace: list[dict[str, Any]] = []
    for raw in stderr.decode("utf-8", errors="surrogateescape").splitlines():
        match = re.match(r"^(\.+)\s+(.+)$", raw)
        if not match:
            continue
        candidate = Path(match.group(2))
        if not candidate.is_absolute():
            candidate = cwd / candidate
        try:
            resolved = candidate.resolve(strict=True)
            digest = _sha(resolved.read_bytes()) if resolved.is_file() else None
        except (OSError, RuntimeError):
            resolved, digest = candidate, None
        trace.append({
            "depth": len(match.group(1)), "path": str(resolved),
            "content_sha256": digest,
        })
    return trace


def _macro_events(stdout: bytes) -> list[dict[str, str]]:
    events: list[dict[str, str]] = []
    for raw in stdout.splitlines():
        if raw.startswith(b"#define "):
            kind = "define"
        elif raw.startswith(b"#undef "):
            kind = "undef"
        else:
            continue
        events.append({"kind": kind, "line_sha256": _sha(raw)})
    return events


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _validate_arguments(arguments: list[str], cwd: Path) -> None:
    """Closed preprocessing flag language; reject extra inputs and code loaders."""
    index = 0
    while index < len(arguments):
        arg = arguments[index]
        if arg in {"-I", "-iquote"}:
            if index + 1 >= len(arguments):
                raise ValueError("preprocessing_include_argument_missing")
            root = Path(arguments[index + 1])
            root = (cwd / root).resolve() if not root.is_absolute() else root.resolve()
            if not root.is_dir() or not _inside(root, cwd):
                raise ValueError("preprocessing_include_root_outside_cwd")
            index += 2
            continue
        if arg.startswith("-I") and len(arg) > 2:
            root = Path(arg[2:])
            root = (cwd / root).resolve() if not root.is_absolute() else root.resolve()
            if not root.is_dir() or not _inside(root, cwd):
                raise ValueError("preprocessing_include_root_outside_cwd")
            index += 1
            continue
        if arg.startswith(("-D", "-U")) and len(arg) > 2:
            index += 1
            continue
        if arg.startswith("-std=") and re.fullmatch(r"-std=(c|gnu|c\+\+|gnu\+\+)\d+", arg):
            index += 1
            continue
        if arg == "-x" and index + 1 < len(arguments) and arguments[index + 1] in {
                "c", "c++", "objective-c", "objective-c++"}:
            index += 2
            continue
        # This rejects response files, extra translation units, -o/-MF/-include,
        # plugin loaders, target/sysroot changes, and other unmodelled behavior.
        raise ValueError("preprocessing_argument_not_allowlisted")


def capture_trusted_preprocessing(*, source_path: Path, compiler: str,
                                  arguments: list[str], cwd: Path,
                                  environment: dict[str, str],
                                  allowlisted_environment: set[str],
                                  candidate_id: str, rule_id: str,
                                  runtime_secret: bytes,
                                  timeout_seconds: int = 30) -> dict[str, Any]:
    """Run preprocessing and return a public envelope plus sealed private replay data.

    ``arguments`` must not contain the compiler or source.  Their order is kept
    exactly.  Capture flags are fixed here so a caller cannot silently omit the
    include and macro streams needed by the contract.
    """
    _require_secret(runtime_secret)
    source_path = source_path.resolve(strict=True)
    cwd = cwd.resolve(strict=True)
    if not source_path.is_file() or not cwd.is_dir() or not _inside(source_path, cwd):
        raise ValueError("preprocessing_source_or_cwd_invalid")
    if not all(isinstance(arg, str) and "\0" not in arg for arg in arguments):
        raise ValueError("preprocessing_arguments_invalid")
    # ``allowlisted_environment`` remains in the signature for an explicit
    # caller declaration, but it cannot expand the capture policy.
    if set(environment) - _SAFE_ENVIRONMENT or set(environment) - set(allowlisted_environment):
        raise ValueError("preprocessing_environment_not_allowlisted")
    if not all(isinstance(k, str) and isinstance(v, str) and "\0" not in k + v
               for k, v in environment.items()):
        raise ValueError("preprocessing_environment_invalid")
    _validate_arguments(arguments, cwd)
    identity = _compiler_identity(compiler)
    argv = [identity["resolved_path"], "-E", "-dD", "-H", *arguments, str(source_path)]
    proc = subprocess.run(
        argv, cwd=cwd, env=dict(environment), capture_output=True,
        check=False, timeout=timeout_seconds,
    )
    includes = _include_trace(proc.stderr, cwd)
    macros = _macro_events(proc.stdout)
    include_trace_complete = all(
        isinstance(node.get("depth"), int) and node["depth"] > 0
        and isinstance(node.get("path"), str) and node["path"]
        and _is_sha(node.get("content_sha256")) for node in includes
    )
    private_body: dict[str, Any] = {
        "schema_version": PRIVATE_CAPTURE_SCHEMA,
        "compiler": identity,
        "argv": argv,
        "cwd": str(cwd),
        "environment": [[key, environment[key]] for key in sorted(environment)],
        "include_trace": includes,
        "macro_events": macros,
        "exit_code": proc.returncode,
        "diagnostics_sha256": _sha(proc.stderr),
        "preprocessed_sha256": _sha(proc.stdout),
        "preprocessed_bytes": len(proc.stdout),
    }
    private = dict(private_body, capture_seal=_seal_private(private_body, runtime_secret))
    source_hash = _sha(source_path.read_bytes())
    manifest_hash = _sha(_canonical(private_body))
    provenance = {
        "extractor_id": EXTRACTOR_ID, "extractor_version": EXTRACTOR_VERSION,
        "extractor_sha256": extractor_sha256(), "source_sha256": source_hash,
        "input_manifest_sha256": manifest_hash, "candidate_id": candidate_id,
        "rule_id": rule_id,
    }
    reason = ("preprocessor_exit_nonzero" if proc.returncode != 0 else
              None if include_trace_complete else "include_trace_content_unavailable")
    # A trace path without immutable file content is not include provenance.
    # Preserve it in the private capture for diagnosis, but never expose the
    # capture as usable evidence.
    if reason is None and any(not _is_sha(row.get("content_sha256")) for row in includes):
        reason = "include_trace_content_unverifiable"
    status = "observed" if reason is None else "unavailable"
    envelope: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION, "provenance": provenance,
        "compile_command": {
            "status": status,
            "argv_sha256": _sha(_canonical(argv)) if status == "observed" else None,
            "working_directory_sha256": _sha(str(cwd).encode()) if status == "observed" else None,
            "compiler_binary_sha256": identity["binary_sha256"] if status == "observed" else None,
            "reason": reason,
        },
        "include_graph": {
            "status": status,
            "graph_sha256": _sha(_canonical(includes)) if status == "observed" else None,
            "node_count": len(includes) if status == "observed" else None,
            # This field is retained for schema compatibility.  The value is
            # the number of parent transitions in the ordered -H trace, not a
            # claim that a complete include DAG was recovered.
            "edge_count": max(0, len(includes) - 1) if status == "observed" else None,
            "reason": reason,
        },
        "macro_definitions": {
            "status": status,
            "definitions_sha256": _sha(_canonical(macros)) if status == "observed" else None,
            "count": len(macros) if status == "observed" else None,
            "reason": reason,
        },
        "preprocessed_output": {
            "status": status, "sha256": private_body["preprocessed_sha256"] if status == "observed" else None,
            "bytes": len(proc.stdout) if status == "observed" else None, "reason": reason,
        },
        "missing_context": [] if status == "observed" else list(_COMPONENT_KEYS),
    }
    envelope["content_sha256"] = _sha(_canonical(envelope))
    envelope["seal"] = _seal_private(envelope, runtime_secret)
    return {"envelope": envelope, "private_capture": private}


def write_private_capture(path: Path, capture: dict[str, Any]) -> None:
    """Persist replay material with owner-only permissions."""
    if not isinstance(capture, dict) or set(capture) != _PRIVATE_KEYS:
        raise ValueError("private_capture_schema_invalid")
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(_canonical(capture) + b"\n")
    os.chmod(path, 0o600)


def _replay_private_capture(capture: dict[str, Any], runtime_secret: bytes) -> tuple[bool, str, dict[str, Any] | None]:
    if not isinstance(capture, dict) or set(capture) != _PRIVATE_KEYS:
        return False, "private_capture_schema_invalid", None
    body = {key: value for key, value in capture.items() if key != "capture_seal"}
    seal = capture.get("capture_seal")
    if (not isinstance(seal, dict) or set(seal) != {"algorithm", "tag"}
            or seal.get("algorithm") != "HMAC-SHA256" or not _is_sha(seal.get("tag"))):
        return False, "private_capture_seal_invalid", None
    try:
        expected_tag = _seal_private(body, runtime_secret)["tag"]
    except ValueError:
        return False, "private_capture_seal_invalid", None
    if not hmac.compare_digest(expected_tag, seal["tag"]):
        return False, "private_capture_seal_mismatch", None
    if body.get("schema_version") != PRIVATE_CAPTURE_SCHEMA:
        return False, "private_capture_version_mismatch", None
    compiler = body.get("compiler")
    argv = body.get("argv")
    env_rows = body.get("environment")
    if (not isinstance(compiler, dict)
            or set(compiler) != {"resolved_path", "binary_sha256", "version_sha256"}
            or not isinstance(argv, list) or not argv or argv[0] != compiler["resolved_path"]
            or not isinstance(env_rows, list)):
        return False, "private_capture_manifest_invalid", None
    try:
        compiler_path = Path(compiler["resolved_path"]).resolve(strict=True)
        cwd = Path(body["cwd"]).resolve(strict=True)
        environment = dict(env_rows)
    except (OSError, TypeError, ValueError):
        return False, "private_capture_replay_context_missing", None
    if _sha(compiler_path.read_bytes()) != compiler.get("binary_sha256"):
        return False, "compiler_binary_changed", None
    version = subprocess.run([str(compiler_path), "--version"], capture_output=True,
                             check=False, timeout=10)
    if _sha(version.stdout + b"\0" + version.stderr) != compiler.get("version_sha256"):
        return False, "compiler_version_changed", None
    try:
        proc = subprocess.run(argv, cwd=cwd, env=environment, capture_output=True,
                              check=False, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return False, "preprocessing_replay_failed", None
    observed = {
        "include_trace": _include_trace(proc.stderr, cwd),
        "macro_events": _macro_events(proc.stdout),
        "exit_code": proc.returncode,
        "diagnostics_sha256": _sha(proc.stderr),
        "preprocessed_sha256": _sha(proc.stdout),
        "preprocessed_bytes": len(proc.stdout),
    }
    if any(not _is_sha(node.get("content_sha256"))
           for node in observed["include_trace"]):
        return False, "include_trace_content_unavailable", None
    if any(body.get(key) != value for key, value in observed.items()):
        return False, "preprocessing_replay_mismatch", None
    return True, "trusted_preprocessing_replay_exact", body


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
                                    expected: dict[str, str],
                                    private_capture: dict[str, Any] | None = None) -> dict[str, Any]:
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
    if private_capture is None:
        return {"verified": True, "usable": False,
                "reason": "private_preprocessing_capture_required"}
    replayed, replay_reason, body = _replay_private_capture(private_capture, runtime_secret)
    if not replayed or body is None:
        return unknown(replay_reason)
    if provenance["input_manifest_sha256"] != _sha(_canonical(body)):
        return unknown("preprocessing_manifest_hash_mismatch")
    try:
        replay_source_hash = _sha(Path(body["argv"][-1]).read_bytes())
    except (OSError, TypeError, IndexError):
        return unknown("preprocessing_source_unavailable")
    if replay_source_hash != provenance["source_sha256"]:
        return unknown("preprocessing_source_changed")
    compile_command = envelope["compile_command"]
    include_graph = envelope["include_graph"]
    macros = envelope["macro_definitions"]
    output = envelope["preprocessed_output"]
    if (compile_command["argv_sha256"] != _sha(_canonical(body["argv"]))
            or compile_command["working_directory_sha256"] != _sha(body["cwd"].encode())
            or compile_command["compiler_binary_sha256"] != body["compiler"]["binary_sha256"]
            or include_graph["graph_sha256"] != _sha(_canonical(body["include_trace"]))
            or include_graph["node_count"] != len(body["include_trace"])
            or include_graph["edge_count"] != max(0, len(body["include_trace"]) - 1)
            or macros["definitions_sha256"] != _sha(_canonical(body["macro_events"]))
            or macros["count"] != len(body["macro_events"])
            or output["sha256"] != body["preprocessed_sha256"]
            or output["bytes"] != body["preprocessed_bytes"]):
        return unknown("preprocessing_public_private_mismatch")
    return {"verified": True, "usable": True, "reason": replay_reason}
