"""Shadow-only Clang AST to closed LEA round-operation graph proof."""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Iterator

from app.services.clang_straightline_reaching_def import (
    VerifiedPreprocessingBinding, verified_binding_matches_source,
)

PROOF_ID, PROOF_VERSION = "lea-round-operation-graph", "1.0.0"
CLAIM_ID = "LEA.014"
RULE_IDS = ("LEA-027", "LEA-028", "LEA-029", "LEA-030", "LEA-031")
SOURCE_ID = "LEA_DATASHEET_KO"
SOURCE_SHA256 = "b0c065c527be33984c779b16f9bd26024b92254bf8bf374a13b95d599fb3b795"
# rule_evidence_audit.json currently leaves these exact rules unbound.
EVIDENCE_UNIT_IDS: tuple[str, ...] = ()


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canon(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _leaf(space: str, index: int) -> dict[str, Any]:
    return {"op": "load", "space": space, "index": index,
            "value_semantics": "pure_uint32_ssa", "width": 32}


def _bin(op: str, a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    semantics = "uint32_bitwise" if op == "xor" else "uint32_mod_2^32"
    return {"op": op, "args": [a, b], "semantics": semantics, "width": 32}


def _rot(direction: str, amount: int, value: dict[str, Any]) -> dict[str, Any]:
    return {"op": "rotate", "direction": direction, "amount": amount,
            "arg": value, "semantics": "total_uint32_rotate", "width": 32}


def _value(out: int) -> dict[str, Any]:
    pairs = ((0, 0, 1, 1, "left", 9), (1, 2, 2, 3, "right", 5),
             (2, 4, 3, 5, "right", 3))
    if out == 3:
        return _leaf("in", 0)
    x, k, y, l, direction, amount = pairs[out]
    return _rot(direction, amount, _bin("add", _bin("xor", _leaf("in", x), _leaf("rk", k)),
                                       _bin("xor", _leaf("in", y), _leaf("rk", l))))


EXPECTED_GRAPH = [{"op": "store", "space": "out", "index": i,
                   "value": _value(i), "width": 32} for i in range(4)]
EXPECTED_GRAPH_SHA256 = _sha(_canon(EXPECTED_GRAPH))


def _children(node: dict[str, Any]) -> list[dict[str, Any]]:
    return [x for x in node.get("inner", []) if isinstance(x, dict)]


def _walk(node: Any) -> Iterator[dict[str, Any]]:
    if isinstance(node, dict):
        yield node
        for child in _children(node):
            yield from _walk(child)


def _strip(node: dict[str, Any]) -> dict[str, Any]:
    while node.get("kind") in {"ImplicitCastExpr", "ParenExpr", "CStyleCastExpr",
                                "ConstantExpr"} and len(_children(node)) == 1:
        node = _children(node)[0]
    return node


def _integer(node: dict[str, Any]) -> int | None:
    node = _strip(node)
    try:
        return int(node["value"], 0) if node.get("kind") == "IntegerLiteral" else None
    except (KeyError, TypeError, ValueError):
        return None


def _decl(node: dict[str, Any]) -> str | None:
    node = _strip(node)
    ref = node.get("referencedDecl")
    return ref.get("id") if node.get("kind") == "DeclRefExpr" and isinstance(ref, dict) else None


def _subscript(node: dict[str, Any], spaces: dict[str, str]) -> tuple[str, int] | None:
    node, parts = _strip(node), _children(_strip(node))
    if node.get("kind") != "ArraySubscriptExpr" or len(parts) != 2:
        return None
    identity, index = _decl(parts[0]), _integer(parts[1])
    space = next((name for name, value in spaces.items() if value == identity), None)
    return (space, index) if space is not None and index is not None else None


def _expr(node: dict[str, Any], spaces: dict[str, str]) -> dict[str, Any] | None:
    node = _strip(node)
    loaded = _subscript(node, spaces)
    if loaded and loaded[0] in {"in", "rk"}:
        return _leaf(*loaded)
    parts, opcode = _children(node), node.get("opcode")
    if node.get("kind") == "BinaryOperator" and opcode in {"^", "+"} and len(parts) == 2:
        left, right = _expr(parts[0], spaces), _expr(parts[1], spaces)
        return _bin("xor" if opcode == "^" else "add", left, right) \
            if left is not None and right is not None else None
    if node.get("kind") != "BinaryOperator" or opcode != "|" or len(parts) != 2:
        return None
    shifts: dict[str, tuple[dict[str, Any], int]] = {}
    for part in parts:
        part, children = _strip(part), _children(_strip(part))
        if (part.get("kind") != "BinaryOperator" or part.get("opcode") not in {"<<", ">>"}
                or len(children) != 2):
            return None
        value, amount = _expr(children[0], spaces), _integer(children[1])
        if value is None or amount is None or not 0 < amount < 32:
            return None
        shifts[part["opcode"]] = (value, amount)
    if set(shifts) != {"<<", ">>"}:
        return None
    lv, la = shifts["<<"]
    rv, ra = shifts[">>"]
    if lv != rv or la + ra != 32:
        return None
    return _rot("left", la, lv) if la < ra else _rot("right", ra, rv)


def _uint32_pointer(node: dict[str, Any], const: bool, alias_proved: bool) -> bool:
    info = node.get("type", {})
    spelling = str(info.get("desugaredQualType", info.get("qualType", ""))) \
        if isinstance(info, dict) else ""
    accepted = {"constunsignedint*restrict" if const else "unsignedint*restrict"}
    if alias_proved:
        accepted.add("constuint32_t*restrict" if const else "uint32_t*restrict")
    return spelling.replace(" ", "") in accepted


def prove_lea_round_operation_graph(
    source: str, *, preprocessing_binding: VerifiedPreprocessingBinding | None = None,
) -> dict[str, Any]:
    base = {"proof_id": PROOF_ID, "proof_version": PROOF_VERSION, "state": "unknown",
            "claim_id": CLAIM_ID, "rule_ids": list(RULE_IDS), "source_id": SOURCE_ID,
            "normative_source_sha256": SOURCE_SHA256,
            "evidence_unit_ids": list(EVIDENCE_UNIT_IDS),
            "expected_graph_sha256": EXPECTED_GRAPH_SHA256}
    if not verified_binding_matches_source(preprocessing_binding, source):
        return {**base, "reason": "preprocessor_provenance_unproved"}
    bind = preprocessing_binding
    prep = {"original_source_sha256": bind.original_source_sha256,
            "preprocessed_sha256": bind.preprocessed_sha256,
            "input_manifest_sha256": bind.input_manifest_sha256,
            "compiler_binary_sha256": bind.compiler_binary_sha256}
    clang = shutil.which("clang")
    if clang is None:
        return {**base, "preprocessing": prep, "reason": "clang_unavailable"}
    try:
        proof_compiler_sha = _sha(Path(clang).read_bytes())
    except OSError:
        return {**base, "preprocessing": prep, "reason": "clang_binary_unreadable"}
    if proof_compiler_sha != bind.compiler_binary_sha256:
        return {**base, "preprocessing": prep,
                "reason": "proof_capture_toolchain_mismatch"}
    version = subprocess.run([clang, "--version"], capture_output=True, timeout=5, check=False)
    if version.returncode:
        return {**base, "preprocessing": prep, "reason": "clang_version_unavailable"}
    args = ("-x", "c", "-std=c11", "-fsyntax-only", "-Xclang", "-ast-dump=json")
    with tempfile.TemporaryDirectory(prefix="lea-round-graph-") as directory:
        path = Path(directory) / "unit.i"
        path.write_text(source, encoding="utf-8")
        result = subprocess.run([clang, *args, str(path)], capture_output=True, timeout=15,
                                check=False)
    tool = {"clang_version_sha256": _sha(version.stdout),
            "ast_command_sha256": _sha(_canon([clang, *args, "<sealed-unit.i>"]))}
    if result.returncode:
        return {**base, "preprocessing": prep, "toolchain": tool, "reason": "clang_parse_failed"}
    abi_source = source + "\n_Static_assert(sizeof(uint32_t)==4 && __CHAR_BIT__==8, \"uint32 ABI\");\n"
    with tempfile.TemporaryDirectory(prefix="lea-round-abi-") as directory:
        abi_path = Path(directory) / "abi.i"
        abi_path.write_text(abi_source, encoding="utf-8")
        abi = subprocess.run([clang, "-x", "c", "-std=c11", "-fsyntax-only", str(abi_path)],
                             capture_output=True, timeout=15, check=False)
    if abi.returncode:
        return {**base, "preprocessing": prep, "toolchain": tool,
                "reason": "uint32_target_abi_unproved"}
    try:
        ast = json.loads(result.stdout)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {**base, "preprocessing": prep, "toolchain": tool, "reason": "clang_ast_invalid"}
    funcs = [x for x in _walk(ast) if x.get("kind") == "FunctionDecl"
             and x.get("name") == "lea_round_graph_fixture"]
    if len(funcs) != 1:
        return {**base, "preprocessing": prep, "toolchain": tool,
                "reason": "bounded_entrypoint_unproved"}
    parameters = [x for x in _children(funcs[0]) if x.get("kind") == "ParmVarDecl"]
    named = {x.get("name"): x for x in parameters}
    aliases = [x for x in _walk(ast) if x.get("kind") == "TypedefDecl"
               and x.get("name") == "uint32_t"
               and str(x.get("type", {}).get("qualType", "")) == "unsigned int"]
    alias_proved = len(aliases) == 1
    if (len(parameters) != 3 or set(named) != {"out", "in", "rk"}
            or not _uint32_pointer(named["out"], False, alias_proved)
            or not _uint32_pointer(named["in"], True, alias_proved)
            or not _uint32_pointer(named["rk"], True, alias_proved)):
        return {**base, "preprocessing": prep, "toolchain": tool,
                "reason": "closed_uint32_io_shape_unproved"}
    body = next((x for x in _children(funcs[0]) if x.get("kind") == "CompoundStmt"), None)
    forbidden = {"CallExpr", "IfStmt", "ForStmt", "WhileStmt", "DoStmt", "SwitchStmt",
                 "ConditionalOperator", "GotoStmt", "UnaryOperator", "CompoundAssignOperator"}
    if body is None or any(x.get("kind") in forbidden for x in _walk(body)):
        return {**base, "preprocessing": prep, "toolchain": tool,
                "reason": "closed_straightline_body_unproved"}
    spaces = {name: named[name]["id"] for name in named}
    assignments = [x for x in _children(body) if x.get("kind") == "BinaryOperator"
                   and x.get("opcode") == "="]
    stores = []
    for assignment in assignments:
        parts = _children(assignment)
        target = _subscript(parts[0], spaces) if len(parts) == 2 else None
        value = _expr(parts[1], spaces) if len(parts) == 2 else None
        if not target or target[0] != "out" or value is None:
            return {**base, "preprocessing": prep, "toolchain": tool,
                    "reason": "closed_operation_vocabulary_unproved"}
        stores.append({"op": "store", "space": "out", "index": target[1],
                       "value": value, "width": 32})
    observed = _sha(_canon(stores))
    ast_hash = _sha(_canon(funcs[0]))
    if len(assignments) != 4 or stores != EXPECTED_GRAPH:
        return {**base, "preprocessing": prep, "toolchain": tool,
                "function_ast_sha256": ast_hash, "observed_graph_sha256": observed,
                "reason": "normative_graph_mismatch"}
    return {**base, "preprocessing": prep, "toolchain": tool,
            "function_ast_sha256": ast_hash, "observed_graph_sha256": observed,
            "structural_complete": True, "graph_equal": True,
            "evidence_binding_complete": False,
            "reason": "official_evidence_units_unbound_and_independent_audit_pending"}
