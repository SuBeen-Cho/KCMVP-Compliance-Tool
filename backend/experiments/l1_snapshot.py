"""Create and validate immutable, label-free L1 candidate snapshots."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import tempfile
from typing import Any, Iterable


SCHEMA_VERSION = "1.0"
SOURCE_SUFFIXES = {".c", ".h", ".cc", ".cpp", ".hpp"}
SOURCE_LABEL_MARKER_RE = re.compile(
    # A bare `*` is only a comment leader at the beginning of a line. Treating
    # every `*` as one falsely classified ordinary C pointers such as `FILE *fp`.
    r"(?:(?://|/\*)\s*|^\s*\*\s*)(?:\[\s*)?(?:위반|정답|TP|FP|FN|true[ _-]?positive|"
    r"false[ _-]?positive|false[ _-]?negative|ground[ _-]?truth|expected[ _-]?label|"
    r"verdict|answer)\b",
    re.IGNORECASE | re.MULTILINE,
)
CANDIDATE_LABEL_MARKER_RE = re.compile(
    # A generated detector message may legitimately describe a "위반".  Only
    # the answer-annotation form is label bearing; the physical source sanitizer
    # removes it before L1, and this check prevents it from being reintroduced.
    r"(?:\[\s*위반\b|(?<![A-Za-z0-9_])(?:정답|TP|FP|FN|true[ _-]?positive|false[ _-]?positive|"
    r"false[ _-]?negative|ground[ _-]?truth|expected[ _-]?label|verdict|answer)\b)",
    re.IGNORECASE,
)
SECRET_MARKER_RE = re.compile(r"AIza[0-9A-Za-z_-]{20,}")
WORKSTATION_PATH_RE = re.compile(
    r"(?:/Users/|/home/|/tmp/|/private/|/var/folders/|[A-Za-z]:[\\/])"
)
FORBIDDEN_CANDIDATE_KEYS = {
    "gt", "groundtruth", "label", "labels", "expected", "expectedlabel",
    "isviolation", "truelabel", "gold", "verdict", "answer",
}
CANDIDATE_FIELDS = (
    "rule_id", "file", "line", "scope", "message", "severity", "snippet",
    "needs_ai_review", "pattern_type", "ai_context", "confidence",
    "ast_evidence", "func_name", "artifact_rule", "project_artifact_evidence",
    "detection_semantics",
)


class SnapshotError(RuntimeError):
    """Snapshot input or serialized data violates the frozen-run contract."""


def canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise SnapshotError("value is not canonical JSON") from exc


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _safe_source_id(path: Path, root: Path) -> str:
    if path.is_symlink():
        raise SnapshotError("symlink sources are not allowed")
    try:
        relative = path.resolve().relative_to(root.resolve())
    except ValueError:
        raise SnapshotError("source path escapes source root") from None
    source_id = relative.as_posix()
    if not source_id or "::" in source_id or ".." in PurePosixPath(source_id).parts:
        raise SnapshotError("unsafe source id")
    return source_id


def collect_sources(source_root: Path) -> list[dict[str, Any]]:
    if source_root.is_symlink():
        raise SnapshotError("symlink source roots are not allowed")
    root = source_root.resolve()
    if not root.is_dir():
        raise SnapshotError("source root is not a directory")
    sources = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        # Resolve and reject links before reading so an external target is never ingested.
        source_id = _safe_source_id(path, root)
        raw = path.read_bytes()
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise SnapshotError("source is not valid UTF-8") from None
        _assert_source_safe(text)
        sources.append({
            "source_id": source_id,
            "bytes": len(raw),
            "lines": len(text.splitlines()),
            "sha256": sha256_bytes(raw),
            "content": text,
        })
    if not sources:
        raise SnapshotError("no supported source files found")
    return sources


def _tree_hash(sources: Iterable[dict[str, Any]]) -> str:
    identity = [
        {key: source[key] for key in ("source_id", "bytes", "lines", "sha256")}
        for source in sources
    ]
    return sha256_bytes(canonical_bytes(identity))


def _resolve_candidate_source(raw: str, source_root: Path, source_ids: set[str]) -> str:
    normalized = str(raw or "").replace("\\", "/")
    path = Path(raw or "")
    if path.is_absolute():
        try:
            normalized = path.resolve().relative_to(source_root.resolve()).as_posix()
        except ValueError:
            raise SnapshotError("candidate file escapes source root") from None
        if normalized in source_ids:
            return normalized
        raise SnapshotError("candidate file does not reference a collected source")
    parts = PurePosixPath(normalized).parts
    if not normalized or normalized.startswith("/") or any(part in {"", ".", ".."} for part in parts):
        raise SnapshotError("candidate file is an unsafe relative path")
    if normalized not in source_ids:
        raise SnapshotError("candidate file does not reference a collected source")
    return normalized


def _normalized_key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def _assert_source_safe(text: str) -> None:
    if SOURCE_LABEL_MARKER_RE.search(text):
        raise SnapshotError("answer-bearing label marker found in sanitized source")
    if SECRET_MARKER_RE.search(text):
        raise SnapshotError("credential-like marker found in source")


def _assert_label_free(value: Any) -> None:
    if isinstance(value, dict):
        forbidden = {_normalized_key(key) for key in value} & FORBIDDEN_CANDIDATE_KEYS
        if forbidden:
            raise SnapshotError("ground-truth field found in candidate payload")
        for item in value.values():
            _assert_label_free(item)
    elif isinstance(value, list):
        for item in value:
            _assert_label_free(item)
    elif isinstance(value, str):
        if CANDIDATE_LABEL_MARKER_RE.search(value):
            raise SnapshotError("answer-bearing label marker found in candidate payload")
        if SECRET_MARKER_RE.search(value):
            raise SnapshotError("credential-like marker found in candidate payload")
        if WORKSTATION_PATH_RE.search(value):
            raise SnapshotError("workstation path found in candidate payload")


def freeze_candidates(
    candidates: Iterable[dict[str, Any]],
    *,
    set_id: str,
    source_root: Path,
    source_ids: set[str],
) -> list[dict[str, Any]]:
    if not isinstance(set_id, str) or not set_id or "::" in set_id:
        raise SnapshotError("set id must be non-empty and must not contain '::'")
    pending = []
    for raw in candidates:
        if not isinstance(raw, dict) or not raw.get("rule_id"):
            raise SnapshotError("each candidate must be an object with rule_id")
        _assert_label_free(raw)
        source_id = _resolve_candidate_source(str(raw.get("file", "")), source_root, source_ids)
        payload = {key: raw[key] for key in CANDIDATE_FIELDS if key in raw and key != "file"}
        payload["source_id"] = source_id
        payload["rule_id"] = str(raw["rule_id"])
        if "::" in payload["rule_id"]:
            raise SnapshotError("candidate rule id must not contain '::'")
        line = payload.get("line")
        if line is not None and (
            isinstance(line, bool) or not isinstance(line, int) or line < 1
        ):
            raise SnapshotError("candidate line must be null or a positive integer")
        semantics = payload.get("detection_semantics")
        if semantics is not None and semantics not in {
            "prohibited_presence", "required_absence", "structural_violation", "unknown",
        }:
            raise SnapshotError("candidate detection semantics is unsupported")
        _assert_label_free(payload)
        payload_hash = sha256_bytes(canonical_bytes(payload))
        pending.append((source_id, payload["rule_id"], line, payload_hash, payload))

    pending.sort(key=lambda item: (item[0], item[1], item[2] is None, item[2] or 0, item[3]))
    ordinals: dict[tuple[str, str, int | None], int] = {}
    frozen = []
    for source_id, rule_id, line, payload_hash, payload in pending:
        group = (source_id, rule_id, line)
        ordinal = ordinals.get(group, 0) + 1
        ordinals[group] = ordinal
        line_token = str(line) if line is not None else "none"
        frozen.append({
            "candidate_id": (
                f"{set_id}::{source_id}::{rule_id}::{line_token}::{ordinal}::{payload_hash}"
            ),
            "payload_sha256": payload_hash,
            "payload": payload,
        })
    return frozen


def build_snapshot(
    source_root: Path,
    candidates: Iterable[dict[str, Any]],
    *,
    set_id: str,
    provenance: dict[str, str],
) -> dict[str, Any]:
    required = {
        "git_commit", "workspace_sha256", "rules_sha256", "prompts_sha256",
    }
    if set(provenance) != required or any(
        not isinstance(value, str) or not value for value in provenance.values()
    ):
        raise SnapshotError("provenance fields are incomplete")
    if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", provenance["git_commit"], re.I) or any(
        not re.fullmatch(r"[0-9a-f]{64}", provenance[key], re.I)
        for key in ("workspace_sha256", "rules_sha256", "prompts_sha256")
    ):
        raise SnapshotError("provenance hashes are malformed")
    sources = collect_sources(source_root)
    source_tree_sha256 = _tree_hash(sources)
    frozen = freeze_candidates(
        candidates,
        set_id=set_id,
        source_root=source_root,
        source_ids={source["source_id"] for source in sources},
    )
    core = {
        "schema_version": SCHEMA_VERSION,
        "set_id": set_id,
        "provenance": {**provenance, "inputs_sha256": source_tree_sha256},
        "source_tree_sha256": source_tree_sha256,
        "sources": sources,
        "candidates": frozen,
        "l3_candidate_ids": [item["candidate_id"] for item in frozen],
    }
    return {"snapshot_id": sha256_bytes(canonical_bytes(core)), **core}


def validate_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(snapshot, dict) or set(snapshot) != {
        "snapshot_id", "schema_version", "set_id", "provenance",
        "source_tree_sha256", "sources", "candidates", "l3_candidate_ids",
    }:
        raise SnapshotError("snapshot contains missing or unsupported fields")
    if snapshot.get("schema_version") != SCHEMA_VERSION:
        raise SnapshotError("unsupported snapshot schema")
    if (
        not isinstance(snapshot.get("set_id"), str)
        or not snapshot["set_id"]
        or "::" in snapshot["set_id"]
    ):
        raise SnapshotError("snapshot set id is unsafe")
    sources = snapshot.get("sources")
    candidates = snapshot.get("candidates")
    if not isinstance(sources, list) or not isinstance(candidates, list):
        raise SnapshotError("sources and candidates must be lists")
    provenance = snapshot.get("provenance")
    if not isinstance(provenance, dict) or set(provenance) != {
        "git_commit", "workspace_sha256", "rules_sha256", "prompts_sha256",
        "inputs_sha256",
    }:
        raise SnapshotError("snapshot provenance is malformed")
    if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", str(provenance["git_commit"]), re.I) or any(
        not re.fullmatch(r"[0-9a-f]{64}", str(provenance[key]), re.I)
        for key in ("workspace_sha256", "rules_sha256", "prompts_sha256", "inputs_sha256")
    ):
        raise SnapshotError("snapshot provenance hashes are malformed")
    seen_sources = set()
    for source in sources:
        if not isinstance(source, dict) or set(source) != {
            "source_id", "bytes", "lines", "sha256", "content",
        }:
            raise SnapshotError("source contains missing or unsupported fields")
        source_id = source.get("source_id", "")
        if (
            source_id in seen_sources
            or not source_id
            or "::" in source_id
            or Path(source_id).is_absolute()
            or ".." in PurePosixPath(source_id).parts
        ):
            raise SnapshotError("duplicate or unsafe source id")
        seen_sources.add(source_id)
        content = source.get("content")
        if not isinstance(content, str):
            raise SnapshotError("source content must be text")
        raw = content.encode("utf-8")
        if source.get("sha256") != sha256_bytes(raw):
            raise SnapshotError("source hash mismatch")
        if source.get("bytes") != len(raw) or source.get("lines") != len(content.splitlines()):
            raise SnapshotError("source size metadata mismatch")
        _assert_source_safe(content)
    if [source["source_id"] for source in sources] != sorted(seen_sources):
        raise SnapshotError("sources are not in canonical order")
    if snapshot.get("source_tree_sha256") != _tree_hash(sources):
        raise SnapshotError("source tree hash mismatch")
    if provenance["inputs_sha256"] != snapshot["source_tree_sha256"]:
        raise SnapshotError("input provenance hash mismatch")
    ids = []
    expected_ordinals: dict[tuple[str, str, int | None], int] = {}
    for item in candidates:
        if not isinstance(item, dict) or set(item) != {
            "candidate_id", "payload_sha256", "payload",
        }:
            raise SnapshotError("candidate contains missing or unsupported fields")
        payload = item.get("payload")
        if not isinstance(payload, dict) or payload.get("source_id") not in seen_sources:
            raise SnapshotError("candidate payload references an unknown source")
        if (
            not isinstance(payload.get("rule_id"), str)
            or not payload["rule_id"]
            or "::" in payload["rule_id"]
            or set(payload) - ({"source_id"} | (set(CANDIDATE_FIELDS) - {"file"}))
        ):
            raise SnapshotError("candidate payload contains unsupported fields")
        line = payload.get("line")
        if line is not None and (
            isinstance(line, bool) or not isinstance(line, int) or line < 1
        ):
            raise SnapshotError("candidate line must be null or a positive integer")
        semantics = payload.get("detection_semantics")
        if semantics is not None and semantics not in {
            "prohibited_presence", "required_absence", "structural_violation", "unknown",
        }:
            raise SnapshotError("candidate detection semantics is unsupported")
        _assert_label_free(payload)
        if item.get("payload_sha256") != sha256_bytes(canonical_bytes(payload)):
            raise SnapshotError("candidate payload hash mismatch")
        group = (payload["source_id"], str(payload.get("rule_id", "")), payload.get("line"))
        ordinal = expected_ordinals.get(group, 0) + 1
        expected_ordinals[group] = ordinal
        line_token = str(group[2]) if group[2] is not None else "none"
        expected_id = (
            f"{snapshot.get('set_id')}::{group[0]}::{group[1]}::{line_token}::"
            f"{ordinal}::{item['payload_sha256']}"
        )
        if item.get("candidate_id") != expected_id:
            raise SnapshotError("candidate id does not match stable identity fields")
        ids.append(expected_id)
    if len(ids) != len(set(ids)) or snapshot.get("l3_candidate_ids") != ids:
        raise SnapshotError("candidate ids are duplicate or out of order")
    sort_keys = [
        (
            item["payload"]["source_id"],
            str(item["payload"].get("rule_id", "")),
            item["payload"].get("line") is None,
            item["payload"].get("line") or 0,
            item["payload_sha256"],
        )
        for item in candidates
    ]
    if sort_keys != sorted(sort_keys):
        raise SnapshotError("candidates are not in canonical order")
    core = {key: value for key, value in snapshot.items() if key != "snapshot_id"}
    if snapshot.get("snapshot_id") != sha256_bytes(canonical_bytes(core)):
        raise SnapshotError("snapshot id mismatch")
    return {
        "snapshot_id": snapshot["snapshot_id"],
        "source_count": len(sources),
        "candidate_count": len(candidates),
    }


def atomic_write_snapshot(path: Path, snapshot: dict[str, Any]) -> None:
    validate_snapshot(snapshot)
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(snapshot, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        try:
            directory_fd = os.open(path.parent, os.O_RDONLY)
        except OSError:
            directory_fd = None
        if directory_fd is not None:
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
