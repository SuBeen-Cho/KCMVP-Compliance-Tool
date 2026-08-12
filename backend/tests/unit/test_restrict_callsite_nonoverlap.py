import hashlib
import hmac
import json
from pathlib import Path

import pytest

import app.services.restrict_callsite_nonoverlap as proof
from app.services.clang_straightline_reaching_def import VerifiedPreprocessingBinding, _BINDING_ATTESTOR


def binding(source: str, *, valid=True):
    clang = proof.shutil.which("clang")
    compiler_sha = hashlib.sha256(Path(clang).read_bytes()).hexdigest() if clang else "c" * 64
    return VerifiedPreprocessingBinding(
        original_source_sha256="a" * 64,
        preprocessed_sha256=hashlib.sha256((source if valid else source + "x").encode()).hexdigest(),
        input_manifest_sha256="b" * 64, compiler_binary_sha256=compiler_sha,
        _attestor=_BINDING_ATTESTOR)


def run(source: str, **kwargs):
    return proof.prove_restrict_callsite_nonoverlap(
        source, callee="crypt", preprocessing_binding=binding(source), **kwargs)


DECL = "void crypt(unsigned *restrict, const unsigned *restrict, const unsigned *restrict);\n"


def test_distinct_direct_arrays_with_sufficient_extents_are_structurally_complete():
    source = DECL + "void f(void){unsigned out[4], in[4], rk[8]; crypt(out,in,rk); }"
    result = run(source, minimum_extents=(4, 4, 8))
    assert result["state"] == "unknown"
    assert result["structural_complete"] is True
    assert result["array_extents"] == [4, 4, 8]
    assert result["proof_basis"] == "distinct_direct_fixed_arrays"


@pytest.mark.parametrize("body,reason", [
    ("unsigned a[8],rk[8]; crypt(a,a,rk);", "argument_objects_not_distinct"),
    ("unsigned out[3],in[4],rk[8]; crypt(out,in,rk);", "array_extent_unproved"),
    ("unsigned out[4],in[4],rk[8]; crypt(out+1,in,rk);", "aliases_pointer_arithmetic_or_interprocedural_context_unproved"),
    ("unsigned out[4],in[4],rk[8]; unsigned *p=out; crypt(p,in,rk);", "aliases_pointer_arithmetic_or_interprocedural_context_unproved"),
])
def test_alias_pointer_arithmetic_and_extent_fail_closed(body, reason):
    source = DECL + "void f(void){" + body + "}"
    assert run(source, minimum_extents=(4, 4, 8))["reason"] == reason


def test_pointer_parameters_require_exact_source_bound_audit_contract():
    source = DECL + "void f(unsigned *o,unsigned *i,unsigned *r){crypt(o,i,r);}"
    assert run(source)["reason"].endswith("unproved")
    secret = b"s" * 32
    record = {"schema": "1.0", "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
              "callee": "crypt", "parameter_positions": [0, 1, 2],
              "audit_record_sha256": "d" * 64}
    record["seal"] = hmac.new(secret, json.dumps(
        record, sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256).hexdigest()
    contract = proof.verify_and_bind_api_nonoverlap_contract(
        record=record, runtime_secret=secret)
    assert contract is not None
    result = run(source, api_contract=contract)
    assert result.get("structural_complete") is not True
    assert result["reason"] == "api_contract_registry_and_entailment_unverified"
    changed = source + "\n"
    rejected = proof.prove_restrict_callsite_nonoverlap(
        changed, callee="crypt", preprocessing_binding=binding(changed), api_contract=contract)
    assert rejected["reason"].endswith("unproved")

    tampered = dict(record, callee="other")
    assert proof.verify_and_bind_api_nonoverlap_contract(
        record=tampered, runtime_secret=secret) is None
    assert proof.verify_and_bind_api_nonoverlap_contract(
        record=record, runtime_secret=b"x" * 32) is None


def test_preprocessing_and_toolchain_are_bound(monkeypatch):
    source = DECL + "void f(void){unsigned o[1],i[1],r[1];crypt(o,i,r);}"
    result = proof.prove_restrict_callsite_nonoverlap(
        source, callee="crypt", preprocessing_binding=binding(source, valid=False))
    assert result["reason"] == "preprocessor_provenance_unproved"
    token = binding(source)
    object.__setattr__(token, "compiler_binary_sha256", "0" * 64)
    assert proof.prove_restrict_callsite_nonoverlap(
        source, callee="crypt", preprocessing_binding=token)["reason"] == \
        "preprocessing_toolchain_mismatch"


def test_multiple_calls_and_indirect_calls_do_not_prove_unique_direct_graph():
    multiple = DECL + "void f(void){unsigned o[1],i[1],r[1];crypt(o,i,r);crypt(o,i,r);}"
    assert run(multiple)["reason"] == "unique_direct_call_unproved"
    indirect = DECL + "void f(void){unsigned o[1],i[1],r[1];void(*p)(unsigned*,const unsigned*,const unsigned*)=crypt;p(o,i,r);}"
    assert run(indirect)["reason"] == "unique_direct_call_unproved"


def test_restrict_and_out_in_rk_directions_are_part_of_contract():
    absent = "void crypt(unsigned *,const unsigned *,const unsigned *);\n" \
        "void f(void){unsigned o[1],i[1],r[1];crypt(o,i,r);}"
    assert run(absent)["reason"] == "callee_restrict_contract_unproved"
    wrong_roles = "void crypt(const unsigned *restrict,const unsigned *restrict,unsigned *restrict);\n" \
        "void f(void){unsigned o[1],i[1],r[1];crypt(o,i,r);}"
    assert run(wrong_roles)["reason"] == "callee_parameter_roles_unproved"
