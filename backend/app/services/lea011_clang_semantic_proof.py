"""Narrow Clang-AST proof for LEA-011, for shadow evaluation only.

The proof deliberately accepts only a straight-line, direct assignment shape.
It is not a general C data-flow analysis and must never be used as a production
authorization by itself.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Iterator

PROOF_ID = "lea011-clang-direct-round-key"
PROOF_VERSION = "1.0.0"
VARIANT_MODULUS = {128: 4, 192: 6, 256: 8}


def _walk(node: Any) -> Iterator[dict[str, Any]]:
    if isinstance(node, dict):
        yield node
        for child in node.get("inner", []):
            yield from _walk(child)


def _children(node: dict[str, Any]) -> list[dict[str, Any]]:
    return [value for value in node.get("inner", []) if isinstance(value, dict)]


def _strip(node: dict[str, Any]) -> dict[str, Any]:
    wrappers = {"ImplicitCastExpr", "ParenExpr", "CStyleCastExpr", "ConstantExpr"}
    while node.get("kind") in wrappers and len(_children(node)) == 1:
        node = _children(node)[0]
    return node


def _decl_id(node: dict[str, Any]) -> str | None:
    node = _strip(node)
    ref = node.get("referencedDecl")
    return ref.get("id") if node.get("kind") == "DeclRefExpr" and isinstance(ref, dict) else None


def _integer(node: dict[str, Any]) -> int | None:
    node = _strip(node)
    if node.get("kind") != "IntegerLiteral":
        return None
    try:
        return int(node["value"], 0)
    except (KeyError, TypeError, ValueError):
        return None


def _array_access(node: dict[str, Any], array_decl: str, round_decl: str,
                  modulus: int) -> bool:
    node = _strip(node)
    if node.get("kind") != "ArraySubscriptExpr" or len(_children(node)) != 2:
        return False
    base, index = map(_strip, _children(node))
    if _decl_id(base) != array_decl:
        return False
    if index.get("kind") != "BinaryOperator" or index.get("opcode") != "%":
        return False
    parts = _children(index)
    return (len(parts) == 2 and _decl_id(parts[0]) == round_decl
            and _integer(parts[1]) == modulus)


def _direct_rotation_add(node: dict[str, Any], table_decl: str, round_decl: str,
                         modulus: int) -> bool:
    """Accept only rotate(value + exact-table-access, literal-count)."""
    node = _strip(node)
    if node.get("kind") != "CallExpr":
        return False
    parts = _children(node)
    if len(parts) != 3:
        return False
    callee = _strip(parts[0])
    ref = callee.get("referencedDecl", {})
    name = str(ref.get("name", "")).lower()
    if callee.get("kind") != "DeclRefExpr" or not (
        name.startswith("rotate") or name.startswith("rotl") or name.startswith("rol")
    ):
        return False
    addition = _strip(parts[1])
    operands = _children(addition)
    return (addition.get("kind") == "BinaryOperator"
            and addition.get("opcode") == "+" and len(operands) == 2
            and sum(_array_access(part, table_decl, round_decl, modulus)
                    for part in operands) == 1
            and _integer(parts[2]) is not None)


def _function_proof(function: dict[str, Any], table_decl: str,
                    modulus: int) -> tuple[bool, str]:
    params = [n for n in _children(function) if n.get("kind") == "ParmVarDecl"]
    rounds = [n for n in params if n.get("name") in {"round", "round_index"}]
    outputs = [n for n in params if n.get("name") in {"round_keys", "round_key"}]
    if len(rounds) != 1 or len(outputs) != 1:
        return False, "canonical_parameters_unproved"
    body = next((n for n in _children(function) if n.get("kind") == "CompoundStmt"), None)
    if body is None:
        return False, "function_body_unproved"
    forbidden = {"IfStmt", "SwitchStmt", "ForStmt", "WhileStmt", "DoStmt",
                 "GotoStmt", "IndirectGotoStmt", "ConditionalOperator",
                 "ReturnStmt", "LabelStmt"}
    if any(n.get("kind") in forbidden for n in _walk(body)):
        return False, "straight_line_reachability_unproved"

    assignments = [n for n in _walk(body)
                   if n.get("kind") == "BinaryOperator" and n.get("opcode") == "="]
    matches = 0
    for assignment in assignments:
        parts = _children(assignment)
        if len(parts) != 2:
            continue
        lhs, rhs = parts
        # Direct output influence: the root statement writes the designated
        # round-key parameter, not a temporary or aliased pointer.
        if not _array_access(lhs, outputs[0]["id"], rounds[0]["id"], modulus):
            continue
        if _direct_rotation_add(rhs, table_decl, rounds[0]["id"], modulus):
            matches += 1
    if matches != 1:
        return False, "direct_round_key_influence_unproved"
    return True, "proved"


def prove_lea011_clang_semantics(source: str, *, preprocessed: bool) -> dict[str, Any]:
    """Return a conservative proof report; failures always remain unknown."""
    base = {"proof_id": PROOF_ID, "proof_version": PROOF_VERSION,
            "state": "unknown", "variants": {}}
    if not preprocessed:
        return {**base, "reason": "preprocessor_provenance_unproved"}
    clang = shutil.which("clang")
    if clang is None:
        return {**base, "reason": "clang_unavailable"}
    with tempfile.TemporaryDirectory(prefix="lea011-proof-") as directory:
        path = Path(directory) / "unit.i"
        path.write_text(source, encoding="utf-8")
        command = [clang, "-x", "c", "-std=c11", "-fsyntax-only",
                   "-Xclang", "-ast-dump=json", str(path)]
        result = subprocess.run(command, capture_output=True, text=True,
                                timeout=15, check=False)
    if result.returncode != 0:
        return {**base, "reason": "clang_parse_failed"}
    try:
        ast = json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError):
        return {**base, "reason": "clang_ast_invalid"}

    tables = [n for n in _walk(ast) if n.get("kind") == "VarDecl"
              and n.get("name") in {"delta", "constants"}
              and str(n.get("type", {}).get("qualType", "")).endswith("[8]")]
    if len(tables) != 1:
        return {**base, "reason": "canonical_delta_symbol_unproved"}
    functions = [n for n in _walk(ast) if n.get("kind") == "FunctionDecl"]
    for bits, modulus in VARIANT_MODULUS.items():
        matches = [n for n in functions if n.get("name") == f"lea_key_schedule_{bits}"]
        if len(matches) != 1:
            base["variants"][str(bits)] = "canonical_function_unproved"
            continue
        ok, reason = _function_proof(matches[0], tables[0]["id"], modulus)
        base["variants"][str(bits)] = reason
    if all(value == "proved" for value in base["variants"].values()) \
            and len(base["variants"]) == 3:
        # Clang's JSON AST establishes canonical Decl identity and a narrow
        # direct syntax shape, but it is not a reaching-definition/SSA proof.
        # In particular, a later overwrite or caller-visible output cannot be
        # excluded here.  Keep this evidence structural and fail closed.
        return {**base, "structural_complete": True,
                "reason": "ssa_reaching_definition_unproved"}
    return {**base, "reason": "variant_semantic_proof_incomplete"}
