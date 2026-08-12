"""Conservative, shadow-only LEA-011 program-fact extractor.

This extractor intentionally recognizes one narrow shape.  It does not grant
production authorization; callers must separately verify the sealed envelope
and keep the resulting verdict in shadow evaluation.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from app.services.program_fact_contract import build_program_fact, seal_program_fact

EXTRACTOR_ID = "lea011-delta-defuse"
EXTRACTOR_VERSION = "2.0.0"
RULE_ID = "LEA-011"
EXPECTED_DELTA = (
    0xC3EFE9DB, 0x44626B02, 0x79E27C8A, 0x78DF30EC,
    0x715EA49E, 0xC785DA0A, 0xE04EF22A, 0xE5C40957,
)

# Deliberately excludes inferred-width ``unsigned`` and typedefs whose width
# cannot be established from the supplied text.
_TABLE = re.compile(
    r"(?P<type>uint32_t\s+const|const\s+uint32_t)\s+"
    r"(?P<name>[A-Za-z_]\w*)\s*\[\s*8\s*\]\s*=\s*"
    r"\{(?P<body>[^{}]*)\}\s*;",
    re.MULTILINE,
)
_INTEGER = re.compile(r"0[xX]([0-9A-Fa-f]{1,8})(?:[uU](?:[lL])?|[lL][uU]?)?")
_FUNCTION = re.compile(
    r"(?m)^[ \t]*(?:static\s+)?(?:inline\s+)?(?:void|int|uint32_t)\s+"
    r"(?P<name>[A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{"
)


def extractor_sha256() -> str:
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def _line_column(source: str, offset: int) -> dict[str, int]:
    return {
        "line": source.count("\n", 0, offset) + 1,
        "column": offset - source.rfind("\n", 0, offset),
    }


def _mask_comments_and_literals(source: str) -> str:
    """Replace ordinary C comments/string/char contents while preserving offsets."""
    chars = list(source)
    index = 0
    state = "code"
    while index < len(chars):
        pair = source[index:index + 2]
        if state == "code" and pair in {"//", "/*"}:
            state = "line_comment" if pair == "//" else "block_comment"
            chars[index:index + 2] = "  "
            index += 2
            continue
        if state == "code" and source[index] in {'"', "'"}:
            state = "string" if source[index] == '"' else "char"
            chars[index] = " "
        elif state == "line_comment":
            if source[index] == "\n":
                state = "code"
            else:
                chars[index] = " "
        elif state == "block_comment":
            if pair == "*/":
                chars[index:index + 2] = "  "
                state = "code"
                index += 2
                continue
            if source[index] != "\n":
                chars[index] = " "
        elif state in {"string", "char"}:
            delimiter = '"' if state == "string" else "'"
            if source[index] == "\\" and index + 1 < len(chars):
                chars[index:index + 2] = "  "
                index += 2
                continue
            chars[index] = " " if source[index] != "\n" else "\n"
            if source[index] == delimiter:
                state = "code"
        index += 1
    return "".join(chars)


def _unknown_reason(source: str, *, source_complete: bool,
                    applicability: dict[str, str]) -> str | None:
    if not source_complete:
        return "source_completeness_unproved"
    if applicability != {"algorithm": "LEA", "operation": "key_schedule"}:
        return "applicability_unproved"
    # Preprocessor expansion changes the program seen by the compiler.  This
    # first extractor has no preprocessor provenance, so it must abstain.
    if re.search(r"(?m)^\s*#\s*(?:include|define|if|ifdef|ifndef|elif|else|endif)\b", source):
        return "preprocessor_context_present"
    if 'R"' in source:
        return "unsupported_raw_string_context"
    return None


def _function_bodies(source: str) -> list[tuple[str, int, int, str]] | None:
    """Return direct function bodies, or None when braces cannot be proven."""
    result: list[tuple[str, int, int, str]] = []
    for match in _FUNCTION.finditer(source):
        depth = 1
        cursor = match.end()
        while cursor < len(source) and depth:
            if source[cursor] == "{":
                depth += 1
            elif source[cursor] == "}":
                depth -= 1
            cursor += 1
        if depth:
            return None
        result.append((match.group("name"), match.end(), cursor - 1,
                       source[match.end():cursor - 1]))
    return result


def _variant_usage(source: str, table_name: str) -> tuple[list[dict[str, Any]], str | None]:
    """Prove direct delta use in explicit 128/192/256 key-schedule bodies."""
    functions = _function_bodies(source)
    if functions is None:
        return [], "unbalanced_function_context"
    observations: list[dict[str, Any]] = []
    for variant in (128, 192, 256):
        matches = [row for row in functions
                   if str(variant) in row[0]
                   and re.search(r"(?i)(?:key.*(?:sched|expand)|(?:sched|expand).*key)", row[0])]
        if len(matches) != 1:
            return [], f"key_schedule_{variant}_function_unproved"
        name, start, _end, body = matches[0]
        # A direct reference is mandatory. Calls to helpers are not followed,
        # because that would require interprocedural and alias analysis.
        direct = re.compile(
            rf"(?is)(?:rol|rotl|rotate)[A-Za-z0-9_]*\s*\([^;]*\+\s*"
            rf"\b{re.escape(table_name)}\s*\[[^\]\n]+\][^;]*\)"
            rf"|(?:rol|rotl|rotate)[A-Za-z0-9_]*\s*\([^;]*"
            rf"\b{re.escape(table_name)}\s*\[[^\]\n]+\]\s*\+[^;]*\)"
        )
        use = direct.search(body)
        if use is None:
            return [], f"delta_direct_defuse_{variant}_unproved"
        absolute = start + use.start()
        observations.append({
            "kind": "lea_delta_key_schedule_use",
            "locator": {**_line_column(source, absolute), "function": name,
                        "key_bits": variant, "array": table_name},
            "value": {"direct_array_reference": True,
                      "addition_operand": True, "rotation_input": True},
        })
    return observations, None


def extract_lea011_program_fact(
    source: str,
    *,
    candidate_id: str,
    claim_id: str,
    applicability: dict[str, str],
    source_complete: bool,
    runtime_secret: bytes,
) -> dict[str, Any]:
    """Extract and authenticate a fact from one complete, preprocessed-free unit."""
    source_bytes = source.encode("utf-8")
    provenance = {
        "extractor_id": EXTRACTOR_ID,
        "extractor_version": EXTRACTOR_VERSION,
        "extractor_sha256": extractor_sha256(),
        "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "candidate_id": candidate_id,
        "rule_id": RULE_ID,
        "claim_id": claim_id,
    }
    reason = _unknown_reason(source, source_complete=source_complete,
                             applicability=applicability)
    lexical_source = _mask_comments_and_literals(source)
    matches = list(_TABLE.finditer(lexical_source)) if reason is None else []
    if reason is None and len(matches) != 1:
        reason = "delta_table_missing" if not matches else "ambiguous_typed_tables"

    observations: list[dict[str, Any]] = []
    state = "unknown"
    if reason is None:
        match = matches[0]
        body = match.group("body")
        # Only a comma-separated sequence of eight hexadecimal literals is
        # accepted. Expressions, decimal values, casts, strings and comments
        # cannot silently enter the observation.
        parts = [part.strip() for part in body.split(",")]
        if len(parts) != 8 or any(not _INTEGER.fullmatch(part) for part in parts):
            reason = "initializer_not_eight_hex_literals"
        else:
            values = [int(_INTEGER.fullmatch(part).group(1), 16) for part in parts]  # type: ignore[union-attr]
            observations = [{
                "kind": "lea_delta_table",
                "locator": {**_line_column(source, match.start()),
                            "array": match.group("name"), "element_count": 8},
                "value": [f"0x{value:08x}" for value in values],
            }]
            uses, use_reason = _variant_usage(lexical_source, match.group("name"))
            observations.extend(uses)
            if use_reason:
                reason = use_reason
            else:
                # Regex establishes only a lexical co-occurrence.  It cannot
                # prove reachability, symbol identity/shadowing, alias targets,
                # correct variant-specific indices, or influence on round-key
                # output.  Therefore neither a matching nor mismatching table
                # may be promoted to a semantic program fact here.
                reason = "semantic_defuse_and_reachability_unproved"

    if not observations:
        observations = [{
            "kind": "extraction_abstention",
            "locator": {"line": 1, "column": 1},
            "value": reason or "unknown",
        }]
    fact = build_program_fact(
        provenance=provenance,
        state=state,
        observations=observations,
        missing_context=[reason] if reason else None,
    )
    return seal_program_fact(fact, runtime_secret)
