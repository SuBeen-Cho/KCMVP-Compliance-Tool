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
EXPANDED_MAX_WINDOWS = 8
EXPANDED_WINDOW_RADIUS = 18
EXPANDED_MAX_LINES = 240
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
_REQUIREMENT_OUTCOME_CUE = re.compile(
    r"\b(?:violations?|wrong|bad|expected|answers?|ground[_-]?truth|"
    r"true[_-]?positive|false[_-]?(?:positive|negative)|tp|fp|fn)\b|정답|위반",
    re.IGNORECASE,
)
_SEARCH_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}|[\uAC00-\uD7A3]{2,}")
_STOP_TOKENS = {
    "requirement", "documented", "apply", "source", "project", "file", "rule",
    "kcmvp", "검증", "준수", "확인", "규격", "요구사항", "적용", "관리",
}
_SEMANTIC_ALIASES = {
    "메모리": {"memset", "memcpy", "clear", "cleanse", "erase"},
    "제거": {"memset", "clear", "cleanse", "erase", "free"},
    "비밀키": {"key", "secret", "private"},
    "키": {"key", "keylen", "keybits", "schedule"},
    "카운터": {"counter", "ctr", "nonce", "increment"},
    "난수": {"random", "rng", "drbg", "entropy"},
    "라운드": {"round", "rotate", "rotl", "rotr"},
    "암호화": {"encrypt", "enc", "cipher"},
    "복호화": {"decrypt", "dec", "cipher"},
    "오류": {"error", "return", "fail"},
    "시험": {"test", "kat", "mct", "mmt", "request", "response"},
}


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def opaque_id(namespace: str, value: str, salt: bytes) -> str:
    # Decimal-only payloads cannot accidentally spell lexical cue words such
    # as "bad" or "answer", unlike hexadecimal digests.
    digest = hashlib.sha256(salt + b"\0" + value.encode()).digest()
    return f"{namespace}_{int.from_bytes(digest[:12], 'big'):029d}"


def strip_answer_comments(text: str) -> str:
    """Remove all comments, preserving quoted literals and physical layout."""
    output: list[str] = []
    i = 0
    while i < len(text):
        if text.startswith("//", i):
            end = text.find("\n", i)
            while end >= 0:
                backslashes = 0
                cursor = end - 1
                while cursor >= i and text[cursor] == "\\":
                    backslashes += 1
                    cursor -= 1
                if backslashes % 2 == 0:
                    break
                next_end = text.find("\n", end + 1)
                if next_end < 0:
                    end = len(text)
                    break
                end = next_end
            end = len(text) if end < 0 else end
            output.extend("\n" if char == "\n" else " " for char in text[i:end])
            i = end
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            end = len(text) if end < 0 else end + 2
            output.extend("\n" if char == "\n" else " " for char in text[i:end])
            i = end
        elif text[i] in {'"', "'"}:
            quote = text[i]
            output.append(quote)
            i += 1
            while i < len(text):
                output.append(text[i])
                if text[i] == "\\" and i + 1 < len(text):
                    i += 1
                    output.append(text[i])
                elif text[i] == quote:
                    i += 1
                    break
                i += 1
        else:
            output.append(text[i])
            i += 1
    return "".join(output)


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


def _semantic_terms(*values: str) -> set[str]:
    """Return neutral retrieval terms; never use detector outcome or path metadata."""
    terms = set()
    for value in values:
        for token in _SEARCH_TOKEN.findall(value or ""):
            lowered = token.lower()
            if lowered not in _STOP_TOKENS and not _CUE.search(lowered):
                terms.add(lowered)
        lowered_value = value.lower()
        for concept, aliases in _SEMANTIC_ALIASES.items():
            if concept in lowered_value:
                terms.update(alias for alias in aliases if not _CUE.search(alias))
    return terms


def neutralize_requirement(text: str, salt: bytes) -> tuple[str, dict[str, str]]:
    """Remove outcome wording/examples while retaining normative meaning."""
    neutral, identifiers = neutralize_identifiers(text, salt)
    neutral = _REQUIREMENT_OUTCOME_CUE.sub("비준수 조건", neutral)
    return neutral, identifiers


def display_alias_risk_lines(text: str, identifiers: dict[str, str]) -> set[int]:
    """Return lines whose aliased rendering may misrepresent C semantics."""
    if not identifiers:
        return set()
    risks: set[int] = set()
    tokens = tuple(identifiers)
    for number, line in enumerate(text.splitlines(), 1):
        macro_risk = line.lstrip().startswith("#") and (
            "##" in line or re.search(r"(?:^|\s)#\s*[A-Za-z_]", line) is not None
        )
        dynamic_risk = re.search(r"\b(?:dlsym|GetProcAddress)\s*\(", line) is not None
        string_risk = any(re.search(
            rf"[\"'][^\"']*\b{re.escape(token)}\b[^\"']*[\"']", line,
        ) for token in tokens)
        external_definition_risk = any(re.search(
            rf"^\s*(?!static\b)[^;{{}}]*\b{re.escape(token)}\s*\([^;{{}}]*\)\s*{{", line,
        ) for token in tokens)
        if macro_risk or dynamic_risk or string_risk or external_definition_risk or "__func__" in line:
            risks.add(number)
    return risks


def _line_windows(text: str, terms: set[str]) -> list[tuple[int, int, int]]:
    """Rank bounded source windows by requirement-term matches, deterministically."""
    lines = text.splitlines() or [""]
    hits = []
    for number, line in enumerate(lines, 1):
        lowered = line.lower()
        score = sum(1 for term in terms if term in lowered)
        if score:
            hits.append((score, number))
    ranked = sorted(hits, key=lambda row: (-row[0], row[1]))
    windows: list[tuple[int, int, int]] = []
    for score, center in ranked:
        begin = max(1, center - EXPANDED_WINDOW_RADIUS)
        end = min(len(lines), center + EXPANDED_WINDOW_RADIUS)
        if any(not (end < old_begin or begin > old_end) for old_begin, old_end, _ in windows):
            continue
        windows.append((begin, end, score))
        if len(windows) >= EXPANDED_MAX_WINDOWS:
            break
    return windows


def _expanded_context(
    source_id: str, sources: dict[str, tuple[str, str]], payload: dict[str, Any],
    requirement: str, display_risks: dict[str, set[int]],
) -> tuple[str, int, int, str, list[dict[str, Any]]]:
    """Build a bounded, path-free evidence bundle for absence/project candidates.

    Retrieval depends only on published requirement text and neutralized source
    content. Detector messages, labels, original paths and L3 outcomes are not
    used, which prevents the expansion itself from becoming an answer channel.
    """
    scope = str(payload.get("scope", ""))
    needs_expansion = payload.get("detection_semantics") == "required_absence" or scope in {
        "project", "submission-package",
    }
    neutral_id, primary = sources[source_id]
    if not needs_expansion:
        line = payload.get("line") or 1
        lines = primary.splitlines() or [""]
        center = min(max(1, line), len(lines))
        begin, end = max(1, center - CONTEXT_RADIUS), min(len(lines), center + CONTEXT_RADIUS)
        if display_risks.get(source_id, set()).intersection(range(begin, end + 1)):
            return (
                "Display context withheld because safe identifier aliasing could not be established.",
                1, 1, "Insufficient context: display-blinding safety exclusion", [],
            )
        code = "\n".join(f"{number:06d}: {lines[number - 1]}" for number in range(begin, end + 1))
        return code, begin, end, "Occurrence-level source window", [
            {"display_line": number, "original_source_id": source_id, "original_line": number}
            for number in range(begin, end + 1)
        ]

    terms = _semantic_terms(requirement)
    # A set prefix is structural provenance, not an answer cue. It prevents a
    # project-level absence check from borrowing evidence from another module.
    set_prefix = source_id.split("/", 1)[0]
    eligible = [
        key for key in sorted(sources)
        if key.split("/", 1)[0] == set_prefix
    ]
    ranked: list[tuple[int, str, int, int]] = []
    for key in eligible:
        for begin, end, score in _line_windows(sources[key][1], terms):
            if display_risks.get(key, set()).intersection(range(begin, end + 1)):
                continue
            window_lines = (sources[key][1].splitlines() or [""])[begin - 1:end]
            # Do not rewrite string literals (which would change program
            # semantics); omit a retrieval window if it contains a cue.
            try:
                scan_public_cues(sources[key][0], "\n".join(window_lines))
            except SnapshotError:
                continue
            ranked.append((-score, key, begin, end))
    ranked.sort()
    selected = ranked[:EXPANDED_MAX_WINDOWS]
    if not selected:
        return (
            "Display context withheld because no safe evidence window was available.",
            1, 1, "Insufficient context: display-blinding safety exclusion", [],
        )

    rendered, evidence = [], []
    for index, (_, key, begin, end) in enumerate(selected, 1):
        neutral_source_id, text = sources[key]
        lines = text.splitlines() or [""]
        rendered.append(f"/* evidence_{index:03d} {neutral_source_id} */")
        evidence.append({"display_line": len(rendered), "original_source_id": key,
                         "original_line": None})
        for number in range(begin, end + 1):
            rendered.append(f"source_line_{number:06d} | {lines[number - 1]}")
            evidence.append({"display_line": len(rendered), "original_source_id": key,
                             "original_line": number})
        if len(rendered) >= EXPANDED_MAX_LINES:
            rendered = rendered[:EXPANDED_MAX_LINES]
            evidence = evidence[:EXPANDED_MAX_LINES]
            break
    code = "\n".join(f"{number:06d}: {line}" for number, line in enumerate(rendered, 1))
    return (code, 1, max(1, len(rendered)),
            "Requirement-keyed neutral evidence bundle; bounded windows may not prove global absence",
            evidence)


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
    equivalence_report: dict[str, Any],
    legacy_gt: set[tuple[str, str]] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build a display packet from a label-free sanitized-analysis L1 snapshot.

    The snapshot is the analysis layer. Identifier aliases are a separate
    reviewer-display layer and deliberately carry no compile-equivalence claim.
    A passing strict analysis and detector-blindness report is required before
    display-packet issuance.
    """
    validate_snapshot(snapshot)
    from experiments.blind_equivalence import validate_equivalence_report
    validate_equivalence_report(equivalence_report, snapshot["snapshot_id"])
    if len(salt) < 16:
        raise SnapshotError("blind-packet salt must contain at least 16 bytes")
    sources, mappings, display_risks = {}, {}, {}
    for source in snapshot["sources"]:
        original_id = source["source_id"]
        neutral_id = opaque_id("src", original_id, salt) + Path(original_id).suffix.lower()
        stripped = strip_answer_comments(source["content"])
        neutral, identifiers = neutralize_identifiers(stripped, salt)
        sources[original_id] = (neutral_id, neutral)
        mappings[original_id] = {"source_id": neutral_id, "identifiers": identifiers}
        # Any cue-bearing identifier makes the complete source view unsafe.
        # This conservative policy avoids relying on incomplete macro/data-flow
        # reasoning when producing evidence for an independent labeler.
        display_risks[original_id] = (
            set(range(1, len(stripped.splitlines()) + 1)) if identifiers or _CUE.search(stripped)
            else display_alias_risk_lines(stripped, identifiers)
        )

    from experiments.blind_equivalence import BLIND_EVALUATION_EXCLUDED_RULES
    occurrences, private = [], []
    for frozen in snapshot["candidates"]:
        payload = frozen["payload"]
        if str(payload.get("rule_id", "")) in BLIND_EVALUATION_EXCLUDED_RULES:
            continue
        source_id = payload["source_id"]
        neutral_id, content = sources[source_id]
        candidate_id = opaque_id("candidate", frozen["candidate_id"], salt)
        rule_id = str(payload["rule_id"])
        rule = rule_catalog.get(rule_id, {})
        reference = rule.get("kcmvp_ref", "") or f"rule catalog {rule_id}"
        raw_requirement = rule.get("description", "") or f"Apply the documented requirement for {rule_id}."
        requirement, requirement_identifiers = neutralize_requirement(raw_requirement, salt)
        context, begin, end, context_kind, evidence_line_mappings = _expanded_context(
            source_id, sources, payload, requirement, display_risks,
        )
        public_source_id = neutral_id if context_kind == "Occurrence-level source window" else opaque_id(
            "bundle", f"{source_id}\0{rule_id}", salt,
        ) + ".txt"
        scan_public_cues(public_source_id, context)
        cluster_basis = canonical_bytes({
            "context": context,
            "withheld_source_family": neutral_id if context_kind.startswith("Insufficient context") else None,
        })
        occurrences.append({
            "candidate_id": candidate_id,
            "group_id": opaque_id("cluster", _sha(cluster_basis), salt),
            "rule_id": rule_id,
            "requirement": {
                "text": requirement,
                "citations": [{"source": "KCMVP rule guidance", "locator": reference}],
            },
            "source": {
                "source_id": public_source_id, "line_start": begin, "line_end": end,
                "code": context, "context": context_kind,
            },
        })
        private.append({
            "candidate_id": candidate_id,
            "frozen_candidate_id": frozen["candidate_id"],
            "original_source_id": source_id,
            "original_line": payload.get("line") or 1,
            "rule_id": rule_id,
            "requirement_identifiers": requirement_identifiers,
            "display_context_withheld": context_kind.startswith("Insufficient context"),
            "evidence_line_mappings": evidence_line_mappings,
        })
    occurrences.sort(key=lambda row: row["candidate_id"])
    if len({row["candidate_id"] for row in occurrences}) != len(occurrences):
        raise SnapshotError("opaque candidate ID collision")
    encoded_items = canonical_bytes(occurrences).decode("utf-8")
    forbidden_outcomes = ("is_real_issue", "l3_result", "ground_truth", "legacy_file_rule_label")
    checks = {
        "outcome_fields_absent": not any(term in encoded_items for term in forbidden_outcomes),
        "answer_cues_absent": not (_CUE.search(encoded_items) or _ANNOTATION_CUE.search(encoded_items)),
        "original_paths_absent": not any(source_id in encoded_items for source_id in mappings),
        "original_identifiers_absent": not any(
            re.search(rf"(?<![A-Za-z0-9_]){re.escape(identifier)}(?![A-Za-z0-9_])", encoded_items)
            for mapping in mappings.values() for identifier in mapping["identifiers"]
        ),
        "analysis_snapshot_validated": True,
        "display_alias_compile_equivalence_not_claimed": True,
        "duplicate_family_keys_cue_free": all(
            row["group_id"].removeprefix("cluster_").isdigit() for row in occurrences
        ),
    }
    blind_audit_report = {
        "passed": all(checks.values()), "checks": checks,
        "audited_items_sha256": _sha(canonical_bytes(occurrences)),
    }
    public = build_packet(
        snapshot_id=snapshot["snapshot_id"], prepared_by="blind-corpus-builder",
        randomization_id=_sha(salt + snapshot["snapshot_id"].encode()), items=occurrences,
        blind_audit_report=blind_audit_report,
    )
    validate_packet(public)
    sidecar = {
        "schema_version": SCHEMA_VERSION,
        "packet_id": public["packet_id"],
        "snapshot_id": snapshot["snapshot_id"],
        "source_mappings": mappings,
        "occurrences": private,
        "legacy_file_rule_labels": [] if legacy_gt is None else [
            {"original_source_id": source_id, "rule_id": rule_id,
             "label_precision": "file_rule_only; independent occurrence review required"}
            for source_id, rule_id in sorted(legacy_gt)
        ],
        "blind_audit_report": blind_audit_report,
        "equivalence_report_sha256": (
            _sha(canonical_bytes(equivalence_report))
        ),
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
