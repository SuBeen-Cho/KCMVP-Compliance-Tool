"""Shadow-only proof of a very small C call-site non-overlap language.

This is not a general alias analysis.  It accepts only a unique direct call
whose selected arguments are distinct, direct fixed-size array objects.  An
audited API contract can be used instead, but is process-local, source-bound,
and names the exact parameter positions it covers.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from app.services.clang_straightline_reaching_def import (
    VerifiedPreprocessingBinding, verified_binding_matches_source,
)

PROOF_ID = "restrict-callsite-nonoverlap"
PROOF_VERSION = "1.0.0"
CLANG_ARGS = ("-x", "c", "-std=c11", "-fsyntax-only", "-Xclang", "-ast-dump=json")
_CONTRACT_ATTESTOR = object()


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class AuditedApiNonOverlapContract:
    source_sha256: str
    callee: str
    parameter_positions: tuple[int, ...]
    audit_record_sha256: str
    _attestor: object

    def __post_init__(self) -> None:
        if self._attestor is not _CONTRACT_ATTESTOR:
            raise ValueError("api_contract_not_attested")


def verify_and_bind_api_nonoverlap_contract(
    *, record: dict[str, Any], runtime_secret: bytes,
) -> AuditedApiNonOverlapContract | None:
    """Verify a closed HMAC-authenticated audit record and bind it in memory."""
    if len(runtime_secret) < 32 or set(record) != {"schema", "source_sha256", "callee",
                                                   "parameter_positions",
                                                   "audit_record_sha256", "seal"}:
        return None
    positions = record.get("parameter_positions")
    if (record.get("schema") != "1.0" or not isinstance(record.get("callee"), str)
            or not record["callee"] or not isinstance(positions, list)
            or len(positions) < 2 or len(set(positions)) != len(positions)
            or any(not isinstance(value, int) or value < 0 for value in positions)
            or not re.fullmatch(r"[0-9a-f]{64}", str(record.get("source_sha256", "")))
            or not re.fullmatch(r"[0-9a-f]{64}", str(record.get("audit_record_sha256", "")))
            or not re.fullmatch(r"[0-9a-f]{64}", str(record.get("seal", "")))):
        return None
    body = {key: record[key] for key in record if key != "seal"}
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    expected = hmac.new(runtime_secret, encoded, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, record["seal"]):
        return None
    return AuditedApiNonOverlapContract(
        record["source_sha256"], record["callee"], tuple(positions),
        record["audit_record_sha256"], _CONTRACT_ATTESTOR)


def _walk(value: Any) -> Iterator[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for child in value.get("inner", []):
            yield from _walk(child)


def _children(node: dict[str, Any]) -> list[dict[str, Any]]:
    return [value for value in node.get("inner", []) if isinstance(value, dict)]


def _strip(node: dict[str, Any]) -> dict[str, Any]:
    wrappers = {"ImplicitCastExpr", "ParenExpr", "CStyleCastExpr"}
    while node.get("kind") in wrappers and len(_children(node)) == 1:
        node = _children(node)[0]
    return node


def _direct_decl_ref(node: dict[str, Any]) -> dict[str, Any] | None:
    node = _strip(node)
    ref = node.get("referencedDecl")
    if node.get("kind") != "DeclRefExpr" or not isinstance(ref, dict):
        return None
    return ref


def _array_extent(ref: dict[str, Any]) -> int | None:
    spelling = str(ref.get("type", {}).get("qualType", ""))
    match = re.fullmatch(r".+\[([1-9][0-9]*)\]", spelling)
    return int(match.group(1)) if match else None


def prove_restrict_callsite_nonoverlap(
    source: str, *, callee: str, parameter_positions: tuple[int, ...] = (0, 1, 2),
    minimum_extents: tuple[int, ...] | None = None,
    preprocessing_binding: VerifiedPreprocessingBinding | None = None,
    api_contract: AuditedApiNonOverlapContract | None = None,
) -> dict[str, Any]:
    """Return structural evidence only; the state deliberately remains unknown."""
    base = {"proof_id": PROOF_ID, "proof_version": PROOF_VERSION,
            "state": "unknown", "source_sha256": _sha(source.encode()),
            "callee": callee, "parameter_positions": list(parameter_positions)}
    if not verified_binding_matches_source(preprocessing_binding, source):
        return {**base, "reason": "preprocessor_provenance_unproved"}
    if (len(parameter_positions) < 2 or len(set(parameter_positions)) != len(parameter_positions)
            or any(not isinstance(value, int) or value < 0 for value in parameter_positions)):
        return {**base, "reason": "parameter_positions_invalid"}
    if minimum_extents is None:
        minimum_extents = tuple(1 for _ in parameter_positions)
    if (len(minimum_extents) != len(parameter_positions)
            or any(not isinstance(value, int) or value < 1 for value in minimum_extents)):
        return {**base, "reason": "minimum_extents_invalid"}

    clang = shutil.which("clang")
    if clang is None:
        return {**base, "reason": "clang_unavailable"}
    try:
        clang_sha = _sha(Path(clang).read_bytes())
    except OSError:
        return {**base, "reason": "clang_binary_unreadable"}
    if clang_sha != preprocessing_binding.compiler_binary_sha256:
        return {**base, "reason": "preprocessing_toolchain_mismatch"}
    try:
        version = subprocess.run([clang, "--version"], capture_output=True,
                                 timeout=5, check=False)
        with tempfile.TemporaryDirectory(prefix="restrict-nonoverlap-") as directory:
            path = Path(directory) / "unit.i"
            path.write_text(source, encoding="utf-8")
            parsed = subprocess.run([clang, *CLANG_ARGS, str(path)], capture_output=True,
                                    timeout=15, check=False)
    except (OSError, subprocess.SubprocessError):
        return {**base, "reason": "clang_execution_failed"}
    if version.returncode != 0 or parsed.returncode != 0:
        return {**base, "reason": "clang_parse_failed"}
    try:
        ast = json.loads(parsed.stdout)
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
        return {**base, "reason": "clang_ast_invalid"}
    toolchain = {"clang_binary_sha256": clang_sha,
                 "clang_version_sha256": _sha(version.stdout),
                 "clang_args_sha256": _sha("\0".join(CLANG_ARGS).encode()),
                 "ast_sha256": _sha(parsed.stdout)}

    calls: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for node in _walk(ast):
        if node.get("kind") != "CallExpr":
            continue
        children = _children(node)
        ref = _direct_decl_ref(children[0]) if children else None
        if ref and ref.get("kind") == "FunctionDecl" and ref.get("name") == callee:
            calls.append((node, ref))
    if len(calls) != 1:
        return {**base, "toolchain": toolchain, "reason": "unique_direct_call_unproved"}
    call, callee_ref = calls[0]
    declarations = [node for node in _walk(ast)
                    if node.get("kind") == "FunctionDecl"
                    and node.get("id") == callee_ref.get("id")]
    if len(declarations) != 1:
        return {**base, "toolchain": toolchain, "reason": "callee_declaration_identity_unproved"}
    parameters = [node for node in _children(declarations[0])
                  if node.get("kind") == "ParmVarDecl"]
    if any(position >= len(parameters) for position in parameter_positions):
        return {**base, "toolchain": toolchain, "reason": "callee_restrict_contract_unproved"}
    parameter_types = [str(parameters[position].get("type", {}).get("qualType", ""))
                       for position in parameter_positions]
    if any("*" not in spelling or not re.search(r"\brestrict\b", spelling)
           for spelling in parameter_types):
        return {**base, "toolchain": toolchain, "reason": "callee_restrict_contract_unproved"}
    # The default out/in/rk graph additionally fixes the observable direction:
    # out is writable; in and rk are pointer-to-const inputs.
    if parameter_positions == (0, 1, 2) and (
            parameter_types[0].lstrip().startswith("const ")
            or not all(value.lstrip().startswith("const ") for value in parameter_types[1:])):
        return {**base, "toolchain": toolchain, "reason": "callee_parameter_roles_unproved"}

    arguments = _children(call)[1:]
    if any(position >= len(arguments) for position in parameter_positions):
        return {**base, "toolchain": toolchain, "reason": "call_arity_unproved"}

    refs = [_direct_decl_ref(arguments[position]) for position in parameter_positions]
    direct_variables = all(ref and ref.get("kind") == "VarDecl" for ref in refs)
    if direct_variables:
        ids = [ref.get("id") for ref in refs if ref]
        extents = [_array_extent(ref) for ref in refs if ref]
        if len(set(ids)) != len(ids):
            return {**base, "toolchain": toolchain, "reason": "argument_objects_not_distinct"}
        if any(extent is None for extent in extents):
            return {**base, "toolchain": toolchain,
                    "reason": "aliases_pointer_arithmetic_or_interprocedural_context_unproved"}
        if any(extent < required
               for extent, required in zip(extents, minimum_extents)):
            return {**base, "toolchain": toolchain, "reason": "array_extent_unproved"}
        return {**base, "toolchain": toolchain, "structural_complete": True,
                "proof_basis": "distinct_direct_fixed_arrays",
                "array_extents": extents,
                "reason": "callsite_nonoverlap_structurally_proved"}

    contract_valid = (isinstance(api_contract, AuditedApiNonOverlapContract)
                      and api_contract._attestor is _CONTRACT_ATTESTOR
                      and api_contract.source_sha256 == base["source_sha256"]
                      and api_contract.callee == callee
                      and api_contract.parameter_positions == parameter_positions)
    if contract_valid:
        # A process-local capability and a hash-shaped audit reference prove
        # neither the audit record's existence nor its entailment.  Until the
        # record is resolved through a closed, independently reviewed registry,
        # preserve the reference for diagnosis but do not claim non-overlap.
        return {**base, "toolchain": toolchain,
                "audit_record_sha256": api_contract.audit_record_sha256,
                "reason": "api_contract_registry_and_entailment_unverified"}
    return {**base, "toolchain": toolchain,
            "reason": "aliases_pointer_arithmetic_or_interprocedural_context_unproved"}
