"""Fail-closed reaching-definition substrate for straight-line C functions.

This module is intentionally shadow-only.  It proves only that a direct store
to an element of a designated pointer parameter is the last syntactically
possible store to that exact element in a branch-free, call-free function.
It does not prove the meaning of the right-hand side or an algorithm identity.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from app.services.preprocessing_provenance import verify_preprocessing_provenance

PROOF_ID = "clang-straightline-reaching-definition"
PROOF_VERSION = "1.0.0"
CLANG_ARGS = ("-x", "c", "-std=c11", "-fsyntax-only", "-Xclang", "-ast-dump=json")
_BINDING_ATTESTOR = object()


@dataclass(frozen=True)
class VerifiedPreprocessingBinding:
    original_source_sha256: str
    preprocessed_sha256: str
    input_manifest_sha256: str
    compiler_binary_sha256: str
    _attestor: object

    def __post_init__(self) -> None:
        if self._attestor is not _BINDING_ATTESTOR:
            raise ValueError("preprocessing_binding_not_attested")


def verify_and_bind_preprocessing(
    *, envelope: dict[str, Any], runtime_secret: bytes,
    expected: dict[str, str], private_capture: dict[str, Any], analyzed_source: str,
) -> VerifiedPreprocessingBinding | None:
    """Verify sealed provenance and bind it to the exact AST input bytes."""
    result = verify_preprocessing_provenance(
        envelope, runtime_secret, expected, private_capture)
    digest = _sha(analyzed_source.encode("utf-8"))
    if (result.get("verified") is not True or result.get("usable") is not True
            or envelope.get("preprocessed_output", {}).get("sha256") != digest):
        return None
    provenance = envelope["provenance"]
    return VerifiedPreprocessingBinding(
        original_source_sha256=provenance["source_sha256"],
        preprocessed_sha256=digest,
        input_manifest_sha256=provenance["input_manifest_sha256"],
        compiler_binary_sha256=envelope["compile_command"]["compiler_binary_sha256"],
        _attestor=_BINDING_ATTESTOR,
    )


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def verified_binding_matches_source(
    binding: VerifiedPreprocessingBinding | None, source: str,
) -> bool:
    """Return whether an unforgeable binding names these exact UTF-8 bytes."""
    return (isinstance(binding, VerifiedPreprocessingBinding)
            and binding._attestor is _BINDING_ATTESTOR
            and binding.preprocessed_sha256 == _sha(source.encode("utf-8")))


def _children(node: dict[str, Any]) -> list[dict[str, Any]]:
    return [child for child in node.get("inner", []) if isinstance(child, dict)]


def _walk(node: Any) -> Iterator[dict[str, Any]]:
    if isinstance(node, dict):
        yield node
        for child in _children(node):
            yield from _walk(child)


def _strip(node: dict[str, Any]) -> dict[str, Any]:
    wrappers = {"ImplicitCastExpr", "ParenExpr", "CStyleCastExpr", "ConstantExpr"}
    while node.get("kind") in wrappers and len(_children(node)) == 1:
        node = _children(node)[0]
    return node


def _decl_id(node: dict[str, Any]) -> str | None:
    node = _strip(node)
    ref = node.get("referencedDecl")
    return ref.get("id") if node.get("kind") == "DeclRefExpr" and isinstance(ref, dict) else None


def _source_offset(node: dict[str, Any]) -> int | None:
    begin = node.get("range", {}).get("begin", {})
    value = begin.get("offset")
    return value if isinstance(value, int) and value >= 0 else None


def _canonical_json_sha(node: dict[str, Any]) -> str:
    def semantic(value: Any, *, referenced: bool = False) -> Any:
        if isinstance(value, dict):
            return {key: semantic(item, referenced=key == "referencedDecl")
                    for key, item in value.items()
                    if key not in {"loc", "range"} and (key != "id" or referenced)}
        if isinstance(value, list):
            return [semantic(item, referenced=referenced) for item in value]
        return value
    return _sha(json.dumps(semantic(node), ensure_ascii=False, sort_keys=True,
                           separators=(",", ":")).encode("utf-8"))


def _pointer_type(node: dict[str, Any]) -> bool:
    info = node.get("type", {})
    if not isinstance(info, dict):
        return False
    spelling = str(info.get("desugaredQualType", info.get("qualType", "")))
    return "*" in spelling


def _read_only_single_pointer(node: dict[str, Any]) -> bool:
    """A second pointer is safe only as a single-level pointer-to-const input."""
    info = node.get("type", {})
    if not isinstance(info, dict):
        return False
    spelling = " ".join(str(info.get("desugaredQualType", info.get("qualType", ""))).split())
    return spelling.count("*") == 1 and spelling.startswith("const ")


def _single_object_pointer(node: dict[str, Any]) -> bool:
    """Exclude pointer-to-pointer/function/void shapes from element proofs."""
    info = node.get("type", {})
    if not isinstance(info, dict):
        return False
    spelling = str(info.get("desugaredQualType", info.get("qualType", "")))
    compact = " ".join(spelling.replace("\t", " ").split())
    if compact.count("*") != 1 or "(" in compact or "volatile" in compact:
        return False
    base = compact.split("*", 1)[0].replace("const", "").strip()
    words = set(base.split())
    return bool(words) and words <= {
        "_Bool", "bool", "char", "signed", "unsigned", "short", "int",
        "long", "float", "double",
    } and "void" not in words


def _output_element(node: dict[str, Any], output_id: str) -> tuple[bool, str | None, bool]:
    node = _strip(node)
    parts = _children(node)
    if node.get("kind") != "ArraySubscriptExpr" or len(parts) != 2:
        return False, None, False
    if _decl_id(parts[0]) != output_id:
        return False, None, False
    # The canonical AST digest is the exact syntactic location key.  Equality
    # of arbitrary C expressions is not inferred.
    index = _strip(parts[1])
    literal = index.get("kind") == "IntegerLiteral"
    return True, _canonical_json_sha(index), literal


def _base(*, source: str, function_name: str, output_parameter: str) -> dict[str, Any]:
    return {
        "proof_id": PROOF_ID,
        "proof_version": PROOF_VERSION,
        "state": "unknown",
        "source_sha256": _sha(source.encode("utf-8")),
        "function_name": function_name,
        "output_parameter": output_parameter,
    }


def prove_straightline_output_reaching_defs(
    source: str, *, function_name: str, output_parameter: str,
    preprocessing_binding: VerifiedPreprocessingBinding | None = None,
    preprocessed: bool | None = None,
) -> dict[str, Any]:
    """Return authenticated structural evidence, never a semantic verdict."""
    base = _base(source=source, function_name=function_name,
                 output_parameter=output_parameter)
    if preprocessing_binding is None:
        return {**base, "reason": ("legacy_preprocessed_flag_untrusted"
                                    if preprocessed is True
                                    else "preprocessor_provenance_unproved")}
    if not verified_binding_matches_source(preprocessing_binding, source):
        return {**base, "reason": "preprocessor_provenance_unproved"}
    preprocessing = {
        "original_source_sha256": preprocessing_binding.original_source_sha256,
        "preprocessed_sha256": preprocessing_binding.preprocessed_sha256,
        "input_manifest_sha256": preprocessing_binding.input_manifest_sha256,
        "compiler_binary_sha256": preprocessing_binding.compiler_binary_sha256,
    }
    clang = shutil.which("clang")
    if clang is None:
        return {**base, "preprocessing": preprocessing, "reason": "clang_unavailable"}
    try:
        version_result = subprocess.run([clang, "--version"], capture_output=True,
                                        timeout=5, check=False)
    except (OSError, subprocess.SubprocessError):
        return {**base, "reason": "clang_version_unavailable"}
    if version_result.returncode != 0:
        return {**base, "reason": "clang_version_unavailable"}
    with tempfile.TemporaryDirectory(prefix="straightline-rd-") as directory:
        path = Path(directory) / "unit.i"
        path.write_text(source, encoding="utf-8")
        command = [clang, *CLANG_ARGS, str(path)]
        try:
            result = subprocess.run(command, capture_output=True, timeout=15, check=False)
        except (OSError, subprocess.SubprocessError):
            return {**base, "reason": "clang_execution_failed"}
    if result.returncode != 0:
        return {**base, "reason": "clang_parse_failed"}
    try:
        ast = json.loads(result.stdout)
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
        return {**base, "reason": "clang_ast_invalid"}
    try:
        clang_binary_sha = _sha(Path(clang).read_bytes())
    except OSError:
        return {**base, "reason": "clang_binary_unreadable"}
    toolchain = {
        "clang_path_sha256": _sha(str(Path(clang).resolve()).encode("utf-8")),
        "clang_binary_sha256": clang_binary_sha,
        "clang_version_sha256": _sha(version_result.stdout),
        "clang_args_sha256": _sha("\0".join(CLANG_ARGS).encode("utf-8")),
        "ast_sha256": _sha(result.stdout),
    }
    functions = [node for node in _walk(ast) if node.get("kind") == "FunctionDecl"
                 and node.get("name") == function_name
                 and any(child.get("kind") == "CompoundStmt" for child in _children(node))]
    if len(functions) != 1:
        return {**base, "toolchain": toolchain, "reason": "unique_function_definition_unproved"}
    function = functions[0]
    parameters = [node for node in _children(function) if node.get("kind") == "ParmVarDecl"]
    outputs = [node for node in parameters if node.get("name") == output_parameter]
    if len(outputs) != 1 or not _single_object_pointer(outputs[0]):
        return {**base, "toolchain": toolchain, "reason": "output_pointer_identity_unproved"}
    # A read-only input may alias output without creating a hidden store.  Any
    # second writable pointer still invalidates the syntactic last-write claim.
    pointer_parameters = [node for node in parameters if _pointer_type(node)]
    if (len(pointer_parameters) > 2
            or any(node is not outputs[0] and not _read_only_single_pointer(node)
                   for node in pointer_parameters)):
        return {**base, "toolchain": toolchain, "reason": "output_alias_freedom_unproved"}
    body = next(child for child in _children(function) if child.get("kind") == "CompoundStmt")
    forbidden = {
        "IfStmt", "SwitchStmt", "ForStmt", "WhileStmt", "DoStmt", "GotoStmt",
        "IndirectGotoStmt", "ConditionalOperator", "CallExpr", "CXXOperatorCallExpr",
        "UnaryOperator", "CompoundAssignOperator", "LabelStmt", "AsmStmt",
        "ReturnStmt",
    }
    if any(node.get("kind") in forbidden for node in _walk(body)):
        return {**base, "toolchain": toolchain, "reason": "straight_line_effects_unproved"}
    local_pointers = [node for node in _walk(body) if node.get("kind") == "VarDecl"
                      and _pointer_type(node)]
    if local_pointers:
        return {**base, "toolchain": toolchain, "reason": "output_alias_freedom_unproved"}
    assignments = [node for node in _walk(body)
                   if node.get("kind") == "BinaryOperator" and node.get("opcode") == "="]
    stores: list[dict[str, Any]] = []
    for assignment in assignments:
        parts = _children(assignment)
        if len(parts) != 2:
            return {**base, "toolchain": toolchain, "reason": "assignment_shape_unproved"}
        direct, location, literal_location = _output_element(parts[0], outputs[0]["id"])
        if not direct:
            # Any other assignment may mutate state through syntax this narrow
            # substrate does not model.
            return {**base, "toolchain": toolchain, "reason": "non_output_write_effect_unproved"}
        offset = _source_offset(assignment)
        if location is None or offset is None:
            return {**base, "toolchain": toolchain, "reason": "store_location_unproved"}
        stores.append({
            "location_ast_sha256": location,
            "rhs_ast_sha256": _canonical_json_sha(_strip(parts[1])),
            "source_offset": offset,
            "literal_location": literal_location,
        })
    if not stores:
        return {**base, "toolchain": toolchain, "reason": "caller_visible_store_unproved"}
    # Exactly one store per canonical element means its definition reaches the
    # caller-visible function exit and cannot be overwritten in this model.
    if len({store["location_ast_sha256"] for store in stores}) != len(stores):
        return {**base, "toolchain": toolchain, "reason": "later_output_overwrite_detected"}
    if len(stores) > 1 and not all(store["literal_location"] for store in stores):
        return {**base, "toolchain": toolchain,
                "reason": "output_location_disjointness_unproved"}
    return {
        **base,
        "preprocessing": preprocessing,
        "toolchain": toolchain,
        "structural_complete": True,
        "reaching_definitions": stores,
        "reason": "straight_line_caller_visible_reaching_definition_proved",
        # Still unknown: consumers must separately prove RHS semantics and the
        # normative algorithm/rule connection.
    }
