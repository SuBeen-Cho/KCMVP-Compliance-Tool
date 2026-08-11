"""Build leak-resistant occurrence-level packets for independent annotation."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile
from typing import Any, Iterable
import zipfile

from experiments.l1_snapshot import SnapshotError, canonical_bytes, validate_snapshot
from experiments.labeling import build_packet, validate_packet


SCHEMA_VERSION = "1.0"
CONTEXT_RADIUS = 12
_CUE = re.compile(
    r"(?:violations?|wrong|bad|(?:no|weak|unsafe|insecure)[_-]?zeroi[sz]e|"
    r"expected|answers?|ground[_-]?truth|"
    r"true[_-]?positive|false[_-]?(?:positive|negative)|\b(?:tp|fp|fn)\b|정답|위반)",
    re.IGNORECASE,
)
_ANNOTATION_CUE = re.compile(
    r"(?:\[\s*V\d+\s*\]|\b(?:judg(?:e)?ment|verdict)\b|판정|판단)", re.IGNORECASE,
)
_RULE_HEADING_CUE = re.compile(r"\b[A-Z]{2,}(?:-[A-Z]+)?-\d{3}\b")
_IDENTIFIER = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
_GT = re.compile(r"\[위반[:\s]*([A-Z]+-[A-Z]*-?\d+)\]")
_COMMENT = re.compile(r"//[^\n]*|/\*.*?\*/", re.DOTALL)


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def opaque_id(namespace: str, value: str, salt: bytes) -> str:
    # Decimal-only payloads cannot accidentally spell lexical cue words such
    # as "bad" or "answer", unlike hexadecimal digests.
    digest = hashlib.sha256(salt + b"\0" + value.encode()).digest()
    return f"{namespace}_{int.from_bytes(digest[:12], 'big'):029d}"


def strip_answer_comments(text: str) -> str:
    """Remove complete answer-bearing comments and preserve physical line numbers."""
    def replace(match: re.Match[str]) -> str:
        raw = match.group(0)
        return "\n" * raw.count("\n") if (
            _CUE.search(raw) or _ANNOTATION_CUE.search(raw) or _RULE_HEADING_CUE.search(raw)
        ) else raw
    return _COMMENT.sub(replace, text)


def _code_spans(text: str) -> Iterable[tuple[int, int]]:
    """Yield C code spans, excluding comments, quoted strings and character literals."""
    i = start = 0
    while i < len(text):
        if text.startswith("//", i):
            if start < i:
                yield start, i
            end = text.find("\n", i)
            i = len(text) if end < 0 else end
            start = i
        elif text.startswith("/*", i):
            if start < i:
                yield start, i
            end = text.find("*/", i + 2)
            i = len(text) if end < 0 else end + 2
            start = i
        elif text[i] in {'"', "'"}:
            if start < i:
                yield start, i
            quote = text[i]
            i += 1
            while i < len(text):
                if text[i] == "\\":
                    i += 2
                elif text[i] == quote:
                    i += 1
                    break
                else:
                    i += 1
            start = i
        else:
            i += 1
    if start < len(text):
        yield start, len(text)


def neutralize_identifiers(text: str, salt: bytes) -> tuple[str, dict[str, str]]:
    """Rename cue-bearing C identifiers only; literals and comments remain byte-semantic."""
    replacements: dict[str, str] = {}
    pieces, cursor = [], 0
    for begin, end in _code_spans(text):
        pieces.append(text[cursor:begin])
        code = text[begin:end]
        for match in _IDENTIFIER.finditer(code):
            token = match.group(0)
            if _CUE.search(token):
                replacements.setdefault(token, opaque_id("id", token, salt))
        pieces.append(_IDENTIFIER.sub(lambda m: replacements.get(m.group(0), m.group(0)), code))
        cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces), replacements


def scan_public_cues(source_id: str, text: str) -> None:
    if (_CUE.search(source_id) or _CUE.search(text) or _ANNOTATION_CUE.search(source_id)
            or _ANNOTATION_CUE.search(text)):
        raise SnapshotError("answer-bearing cue remains in public source packet")


def _atomic_json(path: Path, value: Any, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(canonical_bytes(value) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def build_packets(
    snapshot: dict[str, Any], rule_catalog: dict[str, dict[str, str]], *, salt: bytes,
    legacy_gt: set[tuple[str, str]] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return a public label packet and a private identity/legacy-GT sidecar."""
    validate_snapshot(snapshot)
    if len(salt) < 16:
        raise SnapshotError("blind-packet salt must contain at least 16 bytes")
    sources, mappings = {}, {}
    for source in snapshot["sources"]:
        original_id = source["source_id"]
        neutral_id = opaque_id("src", original_id, salt) + Path(original_id).suffix.lower()
        stripped = strip_answer_comments(source["content"])
        neutral, identifiers = neutralize_identifiers(stripped, salt)
        sources[original_id] = (neutral_id, neutral)
        mappings[original_id] = {"source_id": neutral_id, "identifiers": identifiers}

    occurrences, private = [], []
    for frozen in snapshot["candidates"]:
        payload = frozen["payload"]
        source_id = payload["source_id"]
        neutral_id, content = sources[source_id]
        line = payload.get("line") or 1
        lines = content.splitlines() or [""]
        center = min(max(1, line), len(lines))
        begin, end = max(1, center - CONTEXT_RADIUS), min(len(lines), center + CONTEXT_RADIUS)
        context = "\n".join(f"{number:06d}: {lines[number - 1]}" for number in range(begin, end + 1))
        scan_public_cues(neutral_id, context)
        candidate_id = opaque_id("candidate", frozen["candidate_id"], salt)
        rule_id = str(payload["rule_id"])
        rule = rule_catalog.get(rule_id, {})
        cluster_basis = canonical_bytes({"rule_id": rule_id, "context": context})
        reference = rule.get("kcmvp_ref", "") or f"rule catalog {rule_id}"
        requirement = rule.get("description", "") or f"Apply the documented requirement for {rule_id}."
        occurrences.append({
            "candidate_id": candidate_id,
            "group_id": "cluster_" + _sha(cluster_basis)[:20],
            "rule_id": rule_id,
            "requirement": {
                "text": requirement,
                "citations": [{"source": "KCMVP rule guidance", "locator": reference}],
            },
            "source": {
                "source_id": neutral_id, "line_start": begin, "line_end": end,
                "code": context, "context": "Occurrence-level source window",
            },
        })
        legacy = None if legacy_gt is None else (source_id, rule_id) in legacy_gt
        private.append({
            "candidate_id": candidate_id,
            "frozen_candidate_id": frozen["candidate_id"],
            "original_source_id": source_id,
            "original_line": line,
            "rule_id": rule_id,
            "legacy_file_rule_label": legacy,
            "legacy_label_precision": "file_rule_only; independent occurrence review required",
        })
    occurrences.sort(key=lambda row: row["candidate_id"])
    if len({row["candidate_id"] for row in occurrences}) != len(occurrences):
        raise SnapshotError("opaque candidate ID collision")
    public = build_packet(
        snapshot_id=snapshot["snapshot_id"], prepared_by="blind-corpus-builder",
        randomization_id=_sha(salt + snapshot["snapshot_id"].encode()), items=occurrences,
    )
    validate_packet(public)
    sidecar = {
        "schema_version": SCHEMA_VERSION,
        "packet_id": public["packet_id"],
        "snapshot_id": snapshot["snapshot_id"],
        "source_mappings": mappings,
        "occurrences": private,
    }
    return public, sidecar


def write_packets(public_path: Path, private_path: Path, public: dict, private: dict, repo: Path) -> None:
    try:
        private_path.resolve().relative_to(repo.resolve())
    except ValueError:
        pass
    else:
        raise SnapshotError("private sidecar must be written outside the Git repository")
    _atomic_json(private_path, private, 0o600)
    _atomic_json(public_path, public, 0o644)


def extract_legacy_gt(archives: Iterable[Path]) -> set[tuple[str, str]]:
    """Read only safe C-family ZIP members and retain set-qualified legacy labels."""
    result = set()
    for set_number, archive in enumerate(archives, 1):
        with zipfile.ZipFile(archive) as handle:
            for info in handle.infolist():
                logical = PurePosixPath(info.filename)
                mode = info.external_attr >> 16
                if logical.is_absolute() or ".." in logical.parts or stat.S_ISLNK(mode):
                    raise SnapshotError("ZIP contains an unsafe entry")
                if info.is_dir() or logical.suffix.lower() not in {".c", ".h", ".cc", ".cpp", ".hpp"}:
                    continue
                if info.file_size > 10 * 1024 * 1024:
                    raise SnapshotError("ZIP source exceeds size limit")
                raw = handle.read(info)
                try:
                    text = raw.decode("utf-8-sig")
                except UnicodeDecodeError:
                    text = raw.decode("cp949")
                # Frozen real-set snapshots preserve the archive-relative path,
                # including the conventional src/ prefix.
                path = logical.as_posix()
                for rule_id in _GT.findall(text):
                    result.add((f"set-{set_number}/{path}", rule_id))
    return result
