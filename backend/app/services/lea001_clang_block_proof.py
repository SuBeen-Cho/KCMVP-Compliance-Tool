"""Conservative Clang-AST evidence for the LEA 128-bit block claim.

This is a shadow-only structural recognizer, not an authorization mechanism.
It binds a 16-byte object to a direct input-to-output block loop while rejecting
unrelated literals and ambiguous units.  Even a complete structural match stays
``unknown`` until interprocedural algorithm identity and SSA output influence
are proved independently.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Iterator

from app.services.clang_straightline_reaching_def import (
    VerifiedPreprocessingBinding,
    verified_binding_matches_source,
)

PROOF_ID = "lea001-clang-operative-block"
PROOF_VERSION = "1.0.0"


def _walk(node: Any) -> Iterator[dict[str, Any]]:
    if isinstance(node, dict):
        yield node
        for child in node.get("inner", []):
            yield from _walk(child)


def _children(node: dict[str, Any]) -> list[dict[str, Any]]:
    return [child for child in node.get("inner", []) if isinstance(child, dict)]


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


def _subscript(node: dict[str, Any], object_id: str, index_id: str) -> bool:
    node = _strip(node)
    parts = _children(node)
    return (node.get("kind") == "ArraySubscriptExpr" and len(parts) == 2
            and _decl_id(parts[0]) == object_id and _decl_id(parts[1]) == index_id)


def _byte_pointer(parameter: dict[str, Any], *, const: bool,
                  uint8_alias_proved: bool) -> bool:
    type_info = parameter.get("type", {})
    if not isinstance(type_info, dict):
        return False
    # ``qualType`` preserves a typedef spelling, so accepting ``uint8_t`` from
    # that field alone lets a hostile unit redefine it as ``unsigned short``.
    # Clang's desugared type is the unit evidence; a typedef with no canonical
    # desugaring remains ambiguous and is rejected.
    qual = str(type_info.get("desugaredQualType", type_info.get("qualType", "")))
    qual = qual.replace(" ", "")
    accepted = {"constunsignedchar*" if const else "unsignedchar*"}
    if uint8_alias_proved:
        accepted.add("constuint8_t*" if const else "uint8_t*")
    return qual in accepted


def _loop_bound(loop: dict[str, Any], index_id: str) -> bool:
    comparisons = [node for node in _walk(loop)
                   if node.get("kind") == "BinaryOperator" and node.get("opcode") == "<"]
    return any(len(_children(node)) == 2
               and _decl_id(_children(node)[0]) == index_id
               and _integer(_children(node)[1]) == 16 for node in comparisons)


def _function_shape(function: dict[str, Any], *,
                    uint8_alias_proved: bool) -> tuple[bool, str, dict[str, Any]]:
    parameters = [node for node in _children(function) if node.get("kind") == "ParmVarDecl"]
    inputs = [node for node in parameters if node.get("name") == "input"]
    outputs = [node for node in parameters if node.get("name") == "output"]
    if len(inputs) != 1 or len(outputs) != 1:
        return False, "canonical_io_parameters_unproved", {}
    if (not _byte_pointer(inputs[0], const=True,
                          uint8_alias_proved=uint8_alias_proved)
            or not _byte_pointer(outputs[0], const=False,
                                 uint8_alias_proved=uint8_alias_proved)):
        return False, "octet_io_types_unproved", {}
    body = next((node for node in _children(function) if node.get("kind") == "CompoundStmt"), None)
    if body is None:
        return False, "function_body_unproved", {}
    if any(node.get("kind") in {"IfStmt", "SwitchStmt", "WhileStmt", "DoStmt", "GotoStmt",
                                "IndirectGotoStmt", "ConditionalOperator", "CallExpr"}
           for node in _walk(body)):
        return False, "control_or_call_effect_unproved", {}
    loops = [node for node in _walk(body) if node.get("kind") == "ForStmt"]
    if len(loops) != 1:
        return False, "single_block_loop_unproved", {}
    loop = loops[0]
    indices = [node for node in _walk(loop) if node.get("kind") == "VarDecl"
               and node.get("name") in {"i", "byte_index"}]
    if len(indices) != 1 or not _loop_bound(loop, indices[0]["id"]):
        return False, "exact_16_byte_bound_unproved", {}
    assignments = [node for node in _walk(loop)
                   if node.get("kind") == "BinaryOperator" and node.get("opcode") == "="]
    direct = [node for node in assignments if len(_children(node)) == 2
              and _subscript(_children(node)[0], outputs[0]["id"], indices[0]["id"])
              and _subscript(_children(node)[1], inputs[0]["id"], indices[0]["id"])]
    if len(direct) != 1 or len(assignments) != 1:
        return False, "direct_block_io_influence_unproved", {}
    return True, "proved", {
        "unit": "byte", "extent": 16, "bits": 128,
        "input_decl_id": inputs[0]["id"], "output_decl_id": outputs[0]["id"],
        "index_decl_id": indices[0]["id"],
    }


def prove_lea001_block_semantics(
    source: str, *,
    preprocessing_binding: VerifiedPreprocessingBinding | None = None,
    preprocessed: bool | None = None,
) -> dict[str, Any]:
    """Recognize a narrow operative 16-byte shape; never emit an observed fact."""
    base = {"proof_id": PROOF_ID, "proof_version": PROOF_VERSION, "state": "unknown"}
    if not verified_binding_matches_source(preprocessing_binding, source):
        return {**base, "reason": ("legacy_preprocessed_flag_untrusted"
                                    if preprocessed is True
                                    else "preprocessor_provenance_unproved")}
    clang = shutil.which("clang")
    if clang is None:
        return {**base, "reason": "clang_unavailable"}
    with tempfile.TemporaryDirectory(prefix="lea001-proof-") as directory:
        path = Path(directory) / "unit.i"
        path.write_text(source, encoding="utf-8")
        result = subprocess.run(
            [clang, "-x", "c", "-std=c11", "-fsyntax-only", "-Xclang", "-ast-dump=json", str(path)],
            capture_output=True, text=True, timeout=15, check=False,
        )
    if result.returncode != 0:
        return {**base, "reason": "clang_parse_failed"}
    try:
        ast = json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError):
        return {**base, "reason": "clang_ast_invalid"}
    functions = [node for node in _walk(ast) if node.get("kind") == "FunctionDecl"
                 and node.get("name") == "lea_encrypt_block"]
    if len(functions) != 1:
        return {**base, "reason": "canonical_lea_entrypoint_unproved"}
    aliases = [node for node in _walk(ast) if node.get("kind") == "TypedefDecl"
               and node.get("name") == "uint8_t"
               and str(node.get("type", {}).get("qualType", "")) == "unsigned char"]
    complete, reason, observation = _function_shape(
        functions[0], uint8_alias_proved=len(aliases) == 1,
    )
    if not complete:
        return {**base, "reason": reason}
    return {**base, "structural_complete": True, "observation": observation,
            "reason": "interprocedural_ssa_and_algorithm_identity_unproved"}
