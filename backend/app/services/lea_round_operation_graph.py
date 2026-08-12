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

PROOF_ID, PROOF_VERSION = "lea-round-operation-graph", "1.1.0"
CLAIM_ID = "LEA.014"
RULE_IDS = ("LEA-027", "LEA-028", "LEA-029", "LEA-030", "LEA-031")
SOURCE_ID = "LEA_DATASHEET_KO"
SOURCE_SHA256 = "b0c065c527be33984c779b16f9bd26024b92254bf8bf374a13b95d599fb3b795"
_BACKEND = Path(__file__).resolve().parents[2]
_AUDIT = _BACKEND / "mapping" / "rule_evidence_audit.json"
_ATOMIC = _BACKEND / "mapping" / "atomic_claim_evidence_registry.json"
_INDEX = _BACKEND / "data" / "evidence" / "official_units.local.json"
_REQUIRED_UNITS = {
    "LEA-027": ("LEA_DATASHEET_KO:p0013:b007", "LEA_DATASHEET_KO:p0013:b008", "LEA_DATASHEET_KO:p0013:b006"),
    "LEA-028": ("LEA_DATASHEET_KO:p0013:b010", "LEA_DATASHEET_KO:p0013:b011", "LEA_DATASHEET_KO:p0013:b009"),
    "LEA-029": ("LEA_DATASHEET_KO:p0013:b013", "LEA_DATASHEET_KO:p0013:b014", "LEA_DATASHEET_KO:p0013:b012"),
    "LEA-030": ("LEA_DATASHEET_KO:p0013:b015",),
    "LEA-031": ("LEA_DATASHEET_KO:p0013:b007", "LEA_DATASHEET_KO:p0013:b008", "LEA_DATASHEET_KO:p0013:b006", "LEA_DATASHEET_KO:p0013:b010", "LEA_DATASHEET_KO:p0013:b011", "LEA_DATASHEET_KO:p0013:b009", "LEA_DATASHEET_KO:p0013:b013", "LEA_DATASHEET_KO:p0013:b014", "LEA_DATASHEET_KO:p0013:b012"),
}
_AUDIT_APPLICABILITY = {
    "LEA-027": {"algorithm": ["LEA"], "operation": ["encryption_round"], "output_word": [0]},
    "LEA-028": {"algorithm": ["LEA"], "operation": ["encryption_round"], "output_word": [1]},
    "LEA-029": {"algorithm": ["LEA"], "operation": ["encryption_round"], "output_word": [2]},
    "LEA-030": {"algorithm": ["LEA"], "operation": ["encryption_round"], "output_word": [3]},
    "LEA-031": {"algorithm": ["LEA"], "operation": ["encryption_round"], "expression_order": "xor_then_modular_add_then_rotate"},
}
_ATOMIC_APPLICABILITY = {
    rule_id: {key: value for key, value in applicability.items() if key != "expression_order"}
    for rule_id, applicability in _AUDIT_APPLICABILITY.items()
}
_UNIT_TEXT_SHA256 = {
    "LEA_DATASHEET_KO:p0013:b006": "2ac68d1c79b788c9e80be3ddbdd3d11b0e7a1ae725d122b3931d312fe1f066f5",
    "LEA_DATASHEET_KO:p0013:b007": "531c77cd66d8e658b9c05197cb1e26d57a1f908091c2adfdf4f026d1488d9188",
    "LEA_DATASHEET_KO:p0013:b008": "173852e2e2daa18c84b640492bdcfc15180c930c7076543f65f0253d4f26c595",
    "LEA_DATASHEET_KO:p0013:b009": "277625ccc2189098d9b5fa3e5f2f0bcaf67b36d8b034e2a1e421ba37af83fc8a",
    "LEA_DATASHEET_KO:p0013:b010": "9d80cb72a7d665184e2104b838dde0ce6da1adb58589dc46b900a417cf7432c8",
    "LEA_DATASHEET_KO:p0013:b011": "c9c7f0c018da62c6e60d0a00b5fcaaa756f6284daebdd4a4d9bab9c88380fc89",
    "LEA_DATASHEET_KO:p0013:b012": "1130ad7e3e1e27f127968b891137c5546c4ab044d31fdeefc427a3e14fae82b9",
    "LEA_DATASHEET_KO:p0013:b013": "0aab8d48a12f98ac3c6072f507fc9034663f5ac233501c8003eef02df6cc35e6",
    "LEA_DATASHEET_KO:p0013:b014": "d624ee3ceabf8edbe0a99c3c3fba3a5077ce17a7b458abaad0d23b29561c6bbf",
    "LEA_DATASHEET_KO:p0013:b015": "769755bac55d0faeb71e05acf6632f9e24144425f1ed2d57f742b66162d96f29",
}
EVIDENCE_UNIT_IDS = tuple(_UNIT_TEXT_SHA256)


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canon(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _load_json(path: Path) -> tuple[dict[str, Any], str]:
    raw = path.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("root_not_object")
    return value, _sha(raw)


def _live_evidence_binding() -> dict[str, Any]:
    """Bind the proof to the current, closed official evidence registries."""
    try:
        audit, audit_sha = _load_json(_AUDIT)
        atomic, atomic_sha = _load_json(_ATOMIC)
        index, index_sha = _load_json(_INDEX)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return {"complete": False, "reason": f"evidence_registry_unreadable:{type(exc).__name__}"}
    result = {"mapping_registry_sha256": audit_sha, "atomic_registry_sha256": atomic_sha,
              "official_index_sha256": index_sha,
              "official_units_manifest_sha256": index.get("units_manifest_sha256")}
    audit_rows, atomic_rows = audit.get("rules"), atomic.get("rules")
    if audit.get("policy") != "fail_closed" or not isinstance(audit_rows, dict):
        return {**result, "complete": False, "reason": "mapping_registry_not_fail_closed"}
    if not isinstance(atomic_rows, dict):
        return {**result, "complete": False, "reason": "atomic_registry_invalid"}
    for rule_id in RULE_IDS:
        row = audit_rows.get(rule_id)
        if (not isinstance(row, dict) or row.get("status") != "verified"
                or row.get("review_required") is not False
                or row.get("authority_class") != "normative_standard"
                or row.get("evidence_role") != "normative_requirement"
                or row.get("source_sha256") != SOURCE_SHA256
                or row.get("evidence_unit_ids") != list(_REQUIRED_UNITS[rule_id])
                or row.get("applicability") != _AUDIT_APPLICABILITY[rule_id]):
            return {**result, "complete": False, "reason": f"mapping_row_not_exact:{rule_id}"}
        claims = atomic_rows.get(rule_id)
        if (not isinstance(claims, list) or len(claims) != 1
                or not isinstance(claims[0], dict)
                or claims[0].get("claim_id") != f"{rule_id}:C1"
                or claims[0].get("polarity") != "required"
                or claims[0].get("allowed_evidence_unit_ids") != list(_REQUIRED_UNITS[rule_id])
                or claims[0].get("applicability") != _ATOMIC_APPLICABILITY[rule_id]
                or claims[0].get("exceptions") != []
                or claims[0].get("program_fact", {}).get("context_required") is not True):
            return {**result, "complete": False, "reason": f"atomic_claim_not_exact:{rule_id}"}
    sources, units = index.get("sources"), index.get("units")
    if (index.get("schema_version") != "1.0"
            or index.get("collection") != "official_source"
            or not isinstance(sources, list) or not isinstance(units, list)):
        return {**result, "complete": False, "reason": "official_index_invalid"}
    public_units = [{key: value for key, value in row.items() if key != "text"}
                    for row in units if isinstance(row, dict)]
    if (len(public_units) != len(units)
            or _sha(json.dumps(public_units, ensure_ascii=False, sort_keys=True,
                               separators=(",", ":")).encode())
            != index.get("units_manifest_sha256")):
        return {**result, "complete": False, "reason": "official_units_manifest_mismatch"}
    source_rows = [row for row in sources if row.get("source_id") == SOURCE_ID]
    if len(source_rows) != 1 or source_rows[0].get("sha256") != SOURCE_SHA256:
        return {**result, "complete": False, "reason": "official_source_hash_mismatch"}
    by_id = {row.get("unit_id"): row for row in units if isinstance(row, dict)}
    if len(by_id) != len(units):
        return {**result, "complete": False, "reason": "official_unit_id_duplicate"}
    for unit_id, expected_hash in _UNIT_TEXT_SHA256.items():
        unit = by_id.get(unit_id)
        block = int(unit_id.rsplit("b", 1)[1])
        if (not isinstance(unit, dict) or unit.get("source_id") != SOURCE_ID
                or unit.get("authority_tier") != "standard"
                or unit.get("collection") != "official_source"
                or unit.get("locator", {}).get("page") != 13
                or unit.get("locator", {}).get("block") != block
                or unit.get("applicability") != {"algorithm": ["LEA"]}
                or unit.get("text_sha256") != expected_hash
                or not isinstance(unit.get("text"), str)
                or _sha(unit["text"].encode()) != expected_hash
                or unit.get("text_length") != len(unit["text"])):
            return {**result, "complete": False, "reason": f"official_unit_not_exact:{unit_id}"}
    return {**result, "complete": True, "reason": "exact_live_evidence_bound",
            "source_sha256": SOURCE_SHA256, "evidence_unit_ids": list(EVIDENCE_UNIT_IDS)}


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
    evidence = _live_evidence_binding()
    base = {"proof_id": PROOF_ID, "proof_version": PROOF_VERSION, "state": "unknown",
            "claim_id": CLAIM_ID, "rule_ids": list(RULE_IDS), "source_id": SOURCE_ID,
            "normative_source_sha256": SOURCE_SHA256,
            "evidence_unit_ids": list(EVIDENCE_UNIT_IDS),
            "evidence_binding": evidence,
            "evidence_binding_complete": evidence.get("complete") is True,
            "expected_graph_sha256": EXPECTED_GRAPH_SHA256}
    if evidence.get("complete") is not True:
        return {**base, "reason": evidence.get("reason", "official_evidence_binding_unproved")}
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
            "reason": "callsite_and_caller_semantics_unproved"}
