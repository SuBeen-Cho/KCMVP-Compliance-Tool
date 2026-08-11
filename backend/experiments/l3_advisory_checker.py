"""Opt-in deterministic fact extractor for L3 advisory research."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from pycparser import c_ast, c_parser

_ROOT_KEYS = {"schema_version", "collection", "default_enforcement", "advisories"}
_ADVISORY_KEYS = {"advisory_id", "title", "normative_level", "evidence_unit_ids", "required_features", "allowed_outcomes", "implementation_status"}


def load_specs(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if set(data) != _ROOT_KEYS or data.get("schema_version") != "1.0" or data.get("collection") != "l3_advisory":
        raise ValueError("invalid or open l3_advisory root schema")
    if data.get("default_enforcement") != "disabled" or not isinstance(data.get("advisories"), list):
        raise ValueError("advisories must be disabled by default")
    seen: set[str] = set()
    for row in data["advisories"]:
        if not isinstance(row, dict) or set(row) != _ADVISORY_KEYS:
            raise ValueError("invalid or open advisory schema")
        if row["advisory_id"] in seen or row["allowed_outcomes"] != ["satisfied", "unsafe_observed", "unknown"]:
            raise ValueError("duplicate advisory or invalid outcomes")
        seen.add(row["advisory_id"])
        if not row["evidence_unit_ids"] or not row["required_features"]:
            raise ValueError("advisory evidence and prerequisites are required")
    return data


def _mask_comments_and_strings(source: str) -> str:
    pattern = re.compile(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', re.S)
    return pattern.sub(lambda m: "".join("\n" if c == "\n" else " " for c in m.group()), source)


_EVENT_NAMES = {
    "decrypt_event": re.compile(r"^(?:cbc_)?decrypt\w*$", re.I),
    "padding_validation_event": re.compile(r"^(?:validate|verify|check)_(?:pkcs\d*_|iso\w*_)?padding$", re.I),
    "padding_removal_event": re.compile(r"^(?:remove|strip|unpad)_(?:pkcs\d*_|iso\w*_)?padding$", re.I),
    "plaintext_release_event": re.compile(r"^(?:return_plaintext|release_plaintext|send_plaintext|copy_plaintext)$", re.I),
}


def _call_name(node: c_ast.Node | None) -> str | None:
    if isinstance(node, c_ast.FuncCall) and isinstance(node.name, c_ast.ID):
        return node.name.name
    return None


def _event_kind(node: c_ast.Node | None) -> str | None:
    name = _call_name(node)
    if not name:
        return None
    return next((kind for kind, pattern in _EVENT_NAMES.items() if pattern.fullmatch(name)), None)


def _terminal_return(node: c_ast.Node | None) -> bool:
    if isinstance(node, c_ast.Return):
        return True
    return isinstance(node, c_ast.Compound) and bool(node.block_items) and all(
        isinstance(item, c_ast.Return) for item in node.block_items
    )


def _validation_guard(node: c_ast.If) -> tuple[bool, bool] | None:
    """Return validation truth only when success polarity is explicit.

    A validator-like function name does not define whether 0, 1, or a status
    enum means success.  Only comparison with the semantic enum identifiers
    ``PADDING_VALID``/``PADDING_INVALID`` is accepted as a proof fact.
    """
    cond = node.cond
    if not isinstance(cond, c_ast.BinaryOp) or cond.op not in {"==", "!="}:
        return None
    pairs = ((cond.left, cond.right), (cond.right, cond.left))
    for call, marker in pairs:
        if _event_kind(call) != "padding_validation_event" or not isinstance(marker, c_ast.ID):
            continue
        if marker.name not in {"PADDING_VALID", "PADDING_INVALID"}:
            return None
        equals_valid = marker.name == "PADDING_VALID"
        true_means_valid = equals_valid if cond.op == "==" else not equals_valid
        return true_means_valid, not true_means_valid
    return None


def _contains_relevant_event(node: c_ast.Node | None) -> bool:
    found = False

    class Visitor(c_ast.NodeVisitor):
        def visit_FuncCall(self, call):
            nonlocal found
            found = found or _event_kind(call) is not None

    if node is not None:
        Visitor().visit(node)
    return found


def _analyse_function(function: c_ast.FuncDef) -> dict[str, Any]:
    """Conservative path analysis for one C function; no callee inference."""
    sinks: list[tuple[bool | None, bool]] = []
    observed = {name: False for name in _EVENT_NAMES}
    unsupported = False

    class ForeignCalls(c_ast.NodeVisitor):
        def visit_FuncCall(self, call):
            nonlocal unsupported
            if _event_kind(call) is None:
                unsupported = True

    # A callee may validate, remove, release, or mutate aliases. Until an
    # interprocedural summary exists, no unknown call is transparent to proof.
    ForeignCalls().visit(function.body)

    def process(node: c_ast.Node | None, states: list[tuple[bool | None, bool]]) -> list[tuple[bool | None, bool]]:
        nonlocal unsupported
        if node is None or not states:
            return states
        if isinstance(node, c_ast.Compound):
            current = states
            for item in node.block_items or []:
                current = process(item, current)
            return current
        if isinstance(node, c_ast.Return):
            if _contains_relevant_event(node.expr):
                # Returning the result of an event-bearing callee does not
                # establish whether validation happened in that callee.
                unsupported = True
            return []
        if isinstance(node, (c_ast.For, c_ast.While, c_ast.DoWhile, c_ast.Switch, c_ast.Goto, c_ast.Label)):
            if _contains_relevant_event(node):
                unsupported = True
            return [(None, True) for _ in states]
        if isinstance(node, c_ast.If):
            guard = _validation_guard(node)
            if guard is not None:
                observed["padding_validation_event"] = True
                true_states = [(guard[0], ambiguous) for _, ambiguous in states]
                false_states = [(guard[1], ambiguous) for _, ambiguous in states]
                true_out = process(node.iftrue, true_states)
                false_out = process(node.iffalse, false_states) if node.iffalse is not None else false_states
                # The canonical early-return guard leaves only the validated
                # continuation path.
                if _terminal_return(node.iftrue) and guard == (False, True):
                    return false_out
                if _terminal_return(node.iffalse) and guard == (True, False):
                    return true_out
                return [(value, True) for value, _ in true_out + false_out]
            true_out = process(node.iftrue, [(value, True) for value, _ in states])
            false_out = process(node.iffalse, [(value, True) for value, _ in states]) if node.iffalse is not None else [(value, True) for value, _ in states]
            return true_out + false_out
        kind = _event_kind(node)
        if kind:
            observed[kind] = True
            if kind in {"padding_removal_event", "plaintext_release_event"}:
                sinks.extend(states)
            elif kind == "padding_validation_event":
                # A bare call observes a check but does not prove its result is
                # enforced before release.
                states = [(None, ambiguous) for _, ambiguous in states]
            return states
        # Calls nested in assignments/casts are observable, but a validation
        # result used in an unmodelled expression remains unknown.
        class Calls(c_ast.NodeVisitor):
            def visit_FuncCall(self, call):
                kind = _event_kind(call)
                if kind:
                    observed[kind] = True
                    if kind in {"padding_removal_event", "plaintext_release_event"}:
                        sinks.extend((None, True) for _ in states)
        Calls().visit(node)
        return states

    process(function.body, [(False, False)])
    if unsupported:
        outcome, reason = "unknown", "unsupported_control_flow_or_interprocedural_event"
    elif not observed["decrypt_event"]:
        outcome, reason = "unknown", "decrypt_event_absent_or_interprocedural"
    elif not sinks:
        outcome, reason = "unknown", "no_observable_removal_or_release"
    elif all(validated is True for validated, _ in sinks):
        outcome, reason = "satisfied", "validation_guard_dominates_all_removal_and_release_paths"
    elif any(validated is False and not ambiguous for validated, ambiguous in sinks):
        outcome, reason = "unsafe_observed", "straight_line_removal_or_release_without_validation_guard"
    else:
        outcome, reason = "unknown", "validation_dominance_not_proven"
    return {"outcome": outcome, "reason": reason, "facts": observed}


def extract_pad002_facts(source: str) -> dict[str, Any]:
    """Prove validation dominance only within one parseable C function."""
    masked = _mask_comments_and_strings(source)
    empty = {name: False for name in _EVENT_NAMES}
    if re.search(r"(?m)^\s*#|::|\b(?:class|template|namespace)\b", masked):
        return {"advisory_id": "PAD-002", "outcome": "unknown", "reason": "macro_or_cpp_not_supported", "facts": empty, "analysis": "pycparser_cfg_v1", "enforcement": "none"}
    try:
        tree = c_parser.CParser().parse(masked)
    except Exception:
        return {"advisory_id": "PAD-002", "outcome": "unknown", "reason": "c_parse_failed", "facts": empty, "analysis": "pycparser_cfg_v1", "enforcement": "none"}
    functions = [node for node in tree.ext if isinstance(node, c_ast.FuncDef)]
    relevant = [function for function in functions if _contains_relevant_event(function.body)]
    if len(relevant) != 1:
        return {"advisory_id": "PAD-002", "outcome": "unknown", "reason": "interprocedural_or_ambiguous_function_scope", "facts": empty, "analysis": "pycparser_cfg_v1", "enforcement": "none"}
    result = _analyse_function(relevant[0])
    return {"advisory_id": "PAD-002", **result, "analysis": "pycparser_cfg_v1", "enforcement": "none"}


def run(path: Path, *, enabled: bool) -> dict[str, Any]:
    if not enabled:
        return {"schema_version": "1.0", "enabled": False, "findings": [], "gate": "no_fp_default"}
    source = path.read_text(encoding="utf-8")
    return {"schema_version": "1.0", "enabled": True, "findings": [extract_pad002_facts(source)], "gate": "advisory_only"}


def main() -> int:
    backend = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--spec", type=Path, default=backend / "rag/l3_advisory_specs.json")
    parser.add_argument("--enable-experimental", action="store_true")
    args = parser.parse_args()
    load_specs(args.spec)
    print(json.dumps(run(args.source, enabled=args.enable_experimental), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
