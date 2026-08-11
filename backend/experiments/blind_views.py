"""Issue three joined reviewer views without conflating realism and blinding.

The artifact-aware and minimal views deliberately retain ordinary program
identifiers.  Only the fully opaque view is suitable for lexical-dependence
stress testing.  All three use the same opaque occurrence identity.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import PurePosixPath
from typing import Any

from experiments.blind_corpus import (
    CONTEXT_RADIUS, _sha, neutralize_identifiers, opaque_id, strip_answer_comments,
)
from experiments.l1_snapshot import SnapshotError, canonical_bytes, validate_snapshot
from experiments.labeling import SCHEMA_VERSION, build_packet, validate_packet


VIEWS = ("analysis_artifact_aware", "minimal_cue_controlled", "fully_opaque")
# LEA-048 makes the request/response filename itself normative.  More rules
# can be added only after their primary-source basis is recorded in the catalog.
DEFAULT_NAME_EVIDENCE_RULES = frozenset({"LEA-048"})
_OUTCOME_COMMENT = re.compile(
    r"(?:\[\s*V\d+\s*\]|\[\s*위반\s*[:\]]|(?:정답|의도적(?:으로)?|"
    r"ground[_ -]?truth|expected|true[_ -]?positive|false[_ -]?(?:positive|negative))|"
    r"\b[A-Z]{2,}(?:-[A-Z]+)?-\d{3}\b)", re.IGNORECASE,
)
_DIRECT_OUTCOME = re.compile(
    r"(?:\[\s*V\d+\s*\]|\[\s*위반\s*[:\]]|\b(?:ground[_ -]?truth|expected[_ -]?label|"
    r"true[_ -]?positive|false[_ -]?(?:positive|negative)|정답)\b)", re.I,
)


def _blank_preserving_layout(value: str) -> str:
    return "".join("\n" if char == "\n" else " " for char in value)


def _selective_comment_strip(text: str, cue: re.Pattern[str]) -> tuple[str, list[str]]:
    """Strip matching C comments without interpreting literals as comments.

    Backslash-newline continuations in ``//`` comments are consumed as part of
    the comment, matching C translation semantics. Physical line layout is
    preserved so occurrence line references remain stable.
    """
    removed: list[str] = []
    output: list[str] = []
    index = 0
    while index < len(text):
        if text.startswith("//", index):
            end = index + 2
            while end < len(text):
                newline = text.find("\n", end)
                if newline < 0:
                    end = len(text)
                    break
                end = newline + 1
                # Translation phase 2 removes a backslash immediately followed
                # by a newline.  This is not the string-literal odd/even escape
                # rule: even a run of two backslashes still has a final
                # backslash adjacent to the newline and continues the comment.
                if newline == 0 or text[newline - 1] != "\\":
                    break
            value = text[index:end]
            if cue.search(value):
                removed.append(hashlib.sha256(value.encode()).hexdigest())
                output.append(_blank_preserving_layout(value))
            else:
                output.append(value)
            index = end
        elif text.startswith("/*", index):
            end = text.find("*/", index + 2)
            end = len(text) if end < 0 else end + 2
            value = text[index:end]
            if cue.search(value):
                removed.append(hashlib.sha256(value.encode()).hexdigest())
                output.append(_blank_preserving_layout(value))
            else:
                output.append(value)
            index = end
        elif text[index] in {'"', "'"}:
            quote, begin = text[index], index
            index += 1
            while index < len(text):
                if text[index] == "\\" and index + 1 < len(text):
                    index += 2
                elif text[index] == quote:
                    index += 1; break
                else:
                    index += 1
            output.append(text[begin:index])
        else:
            output.append(text[index]); index += 1
    return "".join(output), removed


def strip_outcome_comments(text: str) -> tuple[str, list[str]]:
    return _selective_comment_strip(text, _OUTCOME_COMMENT)


def strip_provenance_answer_comments(
    text: str, comment_patterns: tuple[str, ...] | None = None,
) -> tuple[str, list[str]]:
    """Remove comments matched by an explicit generator-provenance manifest."""
    patterns = comment_patterns or (r"\[\s*V\d+\s*\]", r"\[\s*위반\s*[:\]]")
    cue = re.compile("(?:" + ")|(?:".join(patterns) + ")", re.I)
    return _selective_comment_strip(text, cue)


def minimal_source_id(
    source_id: str, rule_id: str, path_prefixes: tuple[str, ...] = ("violations_",),
) -> tuple[str, bool]:
    """Suppress a known generator prefix unless the filename is normative evidence."""
    if rule_id in DEFAULT_NAME_EVIDENCE_RULES:
        return source_id, False
    parts = list(PurePosixPath(source_id).parts)
    changed = False
    for index, part in enumerate(parts):
        stem = PurePosixPath(part).stem
        suffix = PurePosixPath(part).suffix
        replacement = stem
        for prefix in path_prefixes:
            if replacement.lower().startswith(prefix.lower()):
                replacement = replacement[len(prefix):]
                break
        if replacement != stem:
            parts[index] = (replacement or "source") + suffix
            changed = True
    return PurePosixPath(*parts).as_posix(), changed


def _window(text: str, line: int) -> tuple[str, int, int]:
    lines = text.splitlines() or [""]
    center = min(max(1, int(line or 1)), len(lines))
    begin, end = max(1, center - CONTEXT_RADIUS), min(len(lines), center + CONTEXT_RADIUS)
    return "\n".join(f"{number:06d}: {lines[number - 1]}" for number in range(begin, end + 1)), begin, end


def _audit(items: list[dict[str, Any]], checks: dict[str, bool]) -> dict[str, Any]:
    return {"passed": all(checks.values()), "checks": checks,
            "audited_items_sha256": _sha(canonical_bytes(items))}


def validate_generator_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    required = {"schema_version", "generator_id", "source_tree_sha256", "provenance_evidence",
                "comment_patterns", "path_prefixes", "identifier_patterns", "name_evidence_rules"}
    if not isinstance(manifest, dict) or set(manifest) != required:
        raise SnapshotError("generator provenance manifest does not match the closed schema")
    if manifest["schema_version"] != "1.0" or not str(manifest["generator_id"]).strip():
        raise SnapshotError("generator provenance manifest identity is invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", str(manifest["source_tree_sha256"]), re.I):
        raise SnapshotError("generator provenance source-tree hash is invalid")
    if (not isinstance(manifest["provenance_evidence"], list) or not manifest["provenance_evidence"]
            or not all(isinstance(value, str) and value.strip()
                       for value in manifest["provenance_evidence"])):
        raise SnapshotError("generator provenance requires explicit evidence")
    for key in ("comment_patterns", "path_prefixes", "identifier_patterns", "name_evidence_rules"):
        if not isinstance(manifest[key], list) or not all(isinstance(v, str) and v for v in manifest[key]):
            raise SnapshotError(f"generator provenance {key} must be a text list")
    try:
        for pattern in manifest["comment_patterns"] + manifest["identifier_patterns"]:
            re.compile(pattern)
    except re.error as exc:
        raise SnapshotError("generator provenance contains an invalid regex") from exc
    return manifest


def _neutralize_manifest_identifiers(
    text: str, patterns: tuple[str, ...], salt: bytes,
) -> tuple[str, dict[str, str]]:
    if not patterns:
        return text, {}
    cue = re.compile("(?:" + ")|(?:".join(patterns) + ")", re.I)
    # Reuse the C-aware identifier renderer with a temporary exact cue policy.
    identifiers = {token for token in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", text)
                   if cue.search(token)}
    mapping = {token: opaque_id("id", token, salt) for token in sorted(identifiers)}
    if not mapping:
        return text, {}
    # Protect strings/comments by applying the replacement only to code spans.
    from experiments.blind_corpus import _code_spans
    pieces, cursor = [], 0
    token_re = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
    for begin, end in _code_spans(text):
        pieces.append(text[cursor:begin])
        pieces.append(token_re.sub(lambda m: mapping.get(m.group(0), m.group(0)), text[begin:end]))
        cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces), mapping


def build_three_view_packets(
    snapshot: dict[str, Any], rule_catalog: dict[str, dict[str, str]], *, salt: bytes,
    equivalence_report: dict[str, Any], generator_manifest: dict[str, Any],
    excluded_rules: frozenset[str] | None = None,
) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    """Build three joined packets and a sealed occurrence/transformation sidecar."""
    validate_snapshot(snapshot)
    from experiments.blind_equivalence import validate_equivalence_report
    validate_equivalence_report(equivalence_report, snapshot["snapshot_id"])
    manifest = validate_generator_manifest(generator_manifest)
    if manifest["source_tree_sha256"] != snapshot["source_tree_sha256"]:
        raise SnapshotError("generator provenance manifest is not bound to the snapshot source tree")
    if len(salt) < 16:
        raise SnapshotError("blind-packet salt must contain at least 16 bytes")
    # The realistic and minimal views intentionally restore name evidence, so
    # name-dependent rules are not silently dropped.  A caller may preregister
    # exclusions, but the default joined experiment retains every occurrence.
    if excluded_rules is None:
        excluded_rules = frozenset()

    sources = {row["source_id"]: row["content"] for row in snapshot["sources"]}
    items = {view: [] for view in VIEWS}
    sealed_occurrences: list[dict[str, Any]] = []
    for frozen in sorted(snapshot["candidates"], key=lambda row: row["candidate_id"]):
        payload = frozen["payload"]
        rule_id, source_id = str(payload["rule_id"]), str(payload["source_id"])
        if rule_id in excluded_rules:
            continue
        raw = sources[source_id]
        occurrence_id = opaque_id("occurrence", frozen["candidate_id"], salt)
        clone_content = strip_answer_comments(raw)
        group_basis = canonical_bytes({"rule_id": rule_id, "line": payload.get("line") or 1,
                                       "content_sha256": _sha(clone_content.encode())}).decode()
        group_id = opaque_id("cluster", group_basis, salt)
        rule = rule_catalog.get(rule_id, {})
        requirement = str(rule.get("description") or f"Apply the documented requirement for {rule_id}.")
        reference = str(rule.get("kcmvp_ref") or f"rule catalog {rule_id}")
        artifact, artifact_removed_comments = strip_outcome_comments(raw)
        minimal, removed_comments = strip_provenance_answer_comments(
            raw, tuple(manifest["comment_patterns"]),
        )
        name_evidence_rules = frozenset(manifest["name_evidence_rules"]) | DEFAULT_NAME_EVIDENCE_RULES
        if rule_id in name_evidence_rules:
            minimal_id, path_changed = source_id, False
            minimal_identifier_map = {}
        else:
            minimal_id, path_changed = minimal_source_id(
                source_id, rule_id, tuple(manifest["path_prefixes"]),
            )
            minimal, minimal_identifier_map = _neutralize_manifest_identifiers(
                minimal, tuple(manifest["identifier_patterns"]), salt,
            )
        opaque = strip_answer_comments(raw)
        opaque, identifier_map = neutralize_identifiers(opaque, salt)
        opaque, manifest_opaque_map = _neutralize_manifest_identifiers(
            opaque, tuple(manifest["identifier_patterns"]), salt,
        )
        identifier_map.update(manifest_opaque_map)
        opaque_source_id = opaque_id("src", source_id, salt) + PurePosixPath(source_id).suffix.lower()
        representations = {
            "analysis_artifact_aware": (
                source_id, artifact,
                "Sanitized analysis artifact; ordinary names/comments retained and outcome annotations removed",
            ),
            "minimal_cue_controlled": (
                minimal_id, minimal,
                "Ordinary names preserved; provenance-confirmed synthetic answer annotations removed",
            ),
            "fully_opaque": (
                opaque_source_id, opaque,
                "Selected-cue lexical stress view; comments removed and configured cue identifiers aliased",
            ),
        }
        for view, (display_id, content, context) in representations.items():
            code, begin, end = _window(content, payload.get("line") or 1)
            items[view].append({
                "candidate_id": occurrence_id, "group_id": group_id, "rule_id": rule_id,
                "requirement": {"text": requirement, "citations": [
                    {"source": "KCMVP rule guidance", "locator": reference},
                ]},
                "source": {"source_id": display_id, "line_start": begin, "line_end": end,
                           "code": code, "context": context},
            })
        sealed_occurrences.append({
            "occurrence_id": occurrence_id, "frozen_candidate_id": frozen["candidate_id"],
            "original_source_id": source_id, "original_line": payload.get("line") or 1,
            "rule_id": rule_id, "minimal_removed_comment_sha256": removed_comments,
            "artifact_removed_comment_sha256": artifact_removed_comments,
            "minimal_path_changed": path_changed,
            "minimal_identifier_map": minimal_identifier_map,
            "opaque_identifier_map": identifier_map,
        })

    packets: dict[str, dict[str, Any]] = {}
    expected_ids = {row["candidate_id"] for row in items[VIEWS[0]]}
    for view in VIEWS:
        view_ids = {row["candidate_id"] for row in items[view]}
        if view_ids != expected_ids:
            raise SnapshotError("three-view occurrence join is not one-to-one")
        encoded = canonical_bytes(items[view]).decode("utf-8")
        checks = {
            "outcome_fields_absent": not any(key in encoded for key in (
                '"ground_truth"', '"l3_result"', '"is_real_issue"', '"system_output"',
            )),
            "direct_outcome_annotations_absent": not _DIRECT_OUTCOME.search(encoded),
            "same_occurrence_join": view_ids == expected_ids,
            "view_policy_registered": view in VIEWS,
        }
        randomization_id = _sha(salt + b"\0" + view.encode() + b"\0" + snapshot["snapshot_id"].encode())
        packets[view] = build_packet(
            snapshot_id=snapshot["snapshot_id"], prepared_by="three-view-corpus-builder",
            randomization_id=randomization_id, items=items[view],
            blind_audit_report=_audit(items[view], checks), view=view,
        )
        validate_packet(packets[view])
    sidecar_core = {
        "schema_version": SCHEMA_VERSION, "snapshot_id": snapshot["snapshot_id"],
        "equivalence_report_sha256": _sha(canonical_bytes(equivalence_report)),
        "generator_manifest_sha256": _sha(canonical_bytes(manifest)),
        "order_strategy": "independently seeded by view; reviewer assignment is not encoded and must be preregistered externally",
        "packet_ids": {view: packets[view]["packet_id"] for view in VIEWS},
        "occurrences": sealed_occurrences,
    }
    return packets, {"sidecar_id": _sha(canonical_bytes(sidecar_core)), **sidecar_core}
