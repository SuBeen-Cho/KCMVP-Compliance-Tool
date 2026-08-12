"""Fail-closed LEA-001 output coverage and RHS-origin shadow proof.

Only a direct 16-octet copy is recognized, either unrolled or in one canonical
loop, after exact preprocessing provenance is authenticated.  This establishes
coverage and an operative input origin, not LEA algorithm identity.  Semantic
authorization therefore remains false for every result.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Iterator

from app.services.clang_straightline_reaching_def import (
    VerifiedPreprocessingBinding,
    prove_straightline_output_reaching_defs,
    verified_binding_matches_source,
)

PROOF_ID = "lea001-direct-octet-rhs-coverage"
PROOF_VERSION = "1.0.0"


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _children(node: dict[str, Any]) -> list[dict[str, Any]]:
    return [item for item in node.get("inner", []) if isinstance(item, dict)]


def _walk(node: Any) -> Iterator[dict[str, Any]]:
    if isinstance(node, dict):
        yield node
        for child in _children(node):
            yield from _walk(child)


def _strip(node: dict[str, Any]) -> dict[str, Any]:
    while node.get("kind") in {
        "ImplicitCastExpr", "ParenExpr", "CStyleCastExpr", "ConstantExpr",
    } and len(_children(node)) == 1:
        node = _children(node)[0]
    return node


def _decl(node: dict[str, Any]) -> str | None:
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


def _subscript_index(node: dict[str, Any], object_id: str) -> dict[str, Any] | None:
    node = _strip(node)
    parts = _children(node)
    if node.get("kind") != "ArraySubscriptExpr" or len(parts) != 2 or _decl(parts[0]) != object_id:
        return None
    return _strip(parts[1])


def _byte_pointer(node: dict[str, Any], *, const: bool) -> bool:
    info = node.get("type", {})
    spelling = str(info.get("desugaredQualType", info.get("qualType", ""))) if isinstance(info, dict) else ""
    return "".join(spelling.split()) == ("constunsignedchar*" if const else "unsignedchar*")


def _base(source: str, function_name: str) -> dict[str, Any]:
    return {
        "proof_id": PROOF_ID, "proof_version": PROOF_VERSION,
        "state": "unknown", "semantic_authorized": False,
        "algorithm_identity_proved": False,
        "source_sha256": _sha(source.encode("utf-8")),
        "function_name": function_name,
    }


def _parse(source: str) -> tuple[dict[str, Any] | None, str]:
    clang = shutil.which("clang")
    if clang is None:
        return None, "clang_unavailable"
    with tempfile.TemporaryDirectory(prefix="lea001-rhs-") as directory:
        path = Path(directory) / "unit.i"
        path.write_text(source, encoding="utf-8")
        try:
            result = subprocess.run(
                [clang, "-x", "c", "-std=c11", "-fsyntax-only", "-Xclang",
                 "-ast-dump=json", str(path)], capture_output=True, timeout=15,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return None, "clang_execution_failed"
    if result.returncode != 0:
        return None, "clang_parse_failed"
    try:
        return json.loads(result.stdout), "parsed"
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
        return None, "clang_ast_invalid"


def _canonical_loop(loop: dict[str, Any], index_id: str) -> bool:
    declarations = [node for node in _walk(loop) if node.get("kind") == "VarDecl"
                    and node.get("id") == index_id]
    if len(declarations) != 1 or not any(_integer(child) == 0 for child in _children(declarations[0])):
        return False
    index_type = str(declarations[0].get("type", {}).get("qualType", ""))
    # ``_Bool`` increment saturates at one, so ``i < 16; ++i`` never covers
    # sixteen elements.  Require a conventional integer type whose range is
    # sufficient for the closed 0..15 induction domain.
    compact_type = "".join(index_type.split())
    if compact_type in {"_Bool", "bool", "signedchar", "unsignedchar", "char"}:
        return False
    conditions = [node for node in _walk(loop)
                  if node.get("kind") == "BinaryOperator" and node.get("opcode") == "<"]
    if len(conditions) != 1 or len(_children(conditions[0])) != 2:
        return False
    if _decl(_children(conditions[0])[0]) != index_id or _integer(_children(conditions[0])[1]) != 16:
        return False
    increments = [node for node in _walk(loop) if node.get("kind") == "UnaryOperator"
                  and node.get("opcode") == "++" and len(_children(node)) == 1
                  and _decl(_children(node)[0]) == index_id]
    return len(increments) == 1


def prove_lea001_rhs_coverage(
    source: str, *, function_name: str, input_parameter: str = "input",
    output_parameter: str = "output",
    preprocessing_binding: VerifiedPreprocessingBinding | None = None,
) -> dict[str, Any]:
    """Prove a narrow direct-copy fact; never authorize an LEA verdict."""
    base = _base(source, function_name)
    if not verified_binding_matches_source(preprocessing_binding, source):
        return {**base, "reason": "preprocessor_provenance_unproved"}
    ast, reason = _parse(source)
    if ast is None:
        return {**base, "reason": reason}
    functions = [node for node in _walk(ast) if node.get("kind") == "FunctionDecl"
                 and node.get("name") == function_name
                 and any(child.get("kind") == "CompoundStmt" for child in _children(node))]
    if len(functions) != 1:
        return {**base, "reason": "unique_function_definition_unproved"}
    function = functions[0]
    parameters = [node for node in _children(function) if node.get("kind") == "ParmVarDecl"]
    inputs = [node for node in parameters if node.get("name") == input_parameter]
    outputs = [node for node in parameters if node.get("name") == output_parameter]
    if (len(parameters) != 2 or len(inputs) != 1 or len(outputs) != 1
            or not _byte_pointer(inputs[0], const=True) or not _byte_pointer(outputs[0], const=False)):
        return {**base, "reason": "non_aliasing_octet_io_unproved"}
    body = next(child for child in _children(function) if child.get("kind") == "CompoundStmt")
    forbidden = {"IfStmt", "SwitchStmt", "WhileStmt", "DoStmt", "GotoStmt",
                 "IndirectGotoStmt", "ConditionalOperator", "CallExpr", "ReturnStmt",
                 "CompoundAssignOperator", "AsmStmt"}
    if any(node.get("kind") in forbidden for node in _walk(body)):
        return {**base, "reason": "control_or_side_effect_freedom_unproved"}
    loops = [node for node in _walk(body) if node.get("kind") == "ForStmt"]
    unary_operators = [node for node in _walk(body) if node.get("kind") == "UnaryOperator"]
    assignments = [node for node in _walk(body)
                   if node.get("kind") == "BinaryOperator" and node.get("opcode") == "="]
    shape: str
    coverage: list[int]
    if not loops:
        if unary_operators:
            return {**base, "reason": "control_or_side_effect_freedom_unproved"}
        rd = prove_straightline_output_reaching_defs(
            source, function_name=function_name, output_parameter=output_parameter,
            preprocessing_binding=preprocessing_binding,
        )
        if rd.get("structural_complete") is not True:
            return {**base, "reason": "caller_visible_reaching_definition_unproved"}
        coverage = []
        for assignment in assignments:
            parts = _children(assignment)
            if len(parts) != 2:
                return {**base, "reason": "rhs_origin_unproved"}
            left = _subscript_index(parts[0], outputs[0]["id"])
            right = _subscript_index(parts[1], inputs[0]["id"])
            left_index = _integer(left) if left else None
            right_index = _integer(right) if right else None
            if left_index is None or left_index != right_index:
                return {**base, "reason": "rhs_origin_unproved"}
            coverage.append(left_index)
        if sorted(coverage) != list(range(16)) or len(coverage) != 16:
            return {**base, "reason": "exact_16_octet_coverage_unproved"}
        shape = "unrolled_direct_copy"
    elif len(loops) == 1:
        loop = loops[0]
        indices = [node for node in _walk(loop) if node.get("kind") == "VarDecl"]
        if len(indices) != 1 or not _canonical_loop(loop, indices[0]["id"]):
            return {**base, "reason": "canonical_16_iteration_loop_unproved"}
        if (len(unary_operators) != 1 or unary_operators[0].get("opcode") != "++"
                or len(_children(unary_operators[0])) != 1
                or _decl(_children(unary_operators[0])[0]) != indices[0]["id"]):
            return {**base, "reason": "unexpected_unary_side_effect"}
        if len(assignments) != 1:
            return {**base, "reason": "single_loop_store_unproved"}
        parts = _children(assignments[0])
        left = _subscript_index(parts[0], outputs[0]["id"]) if len(parts) == 2 else None
        right = _subscript_index(parts[1], inputs[0]["id"]) if len(parts) == 2 else None
        if left is None or right is None or _decl(left) != indices[0]["id"] or _decl(right) != indices[0]["id"]:
            return {**base, "reason": "rhs_origin_unproved"}
        coverage = list(range(16))
        shape = "canonical_loop_direct_copy"
    else:
        return {**base, "reason": "single_coverage_shape_unproved"}
    return {
        **base, "structural_complete": True,
        "coverage": {"unit": "octet", "indices": coverage, "bits": 128},
        "rhs_origin": "direct_input_same_index",
        "input_output_non_aliasing_proved": False,
        "reaching_definition_proved": True, "shape": shape,
        "reason": "direct_copy_proved_but_lea_algorithm_identity_unproved",
    }
