import json
from pathlib import Path

import pytest

from experiments.ctr_lea001_failclosed_eval import build
from experiments.full_stage_boundary_benchmark import _sha

BACKEND = Path(__file__).resolve().parents[2]
AUDIT = json.loads((BACKEND / "mapping/ctr_lea001_entailment_gate.json").read_text())


def _snapshot(*, spoof: bool = False):
    rows = []
    for index in range(6):
        payload = {"rule_id": "CTR-LEA-001", "snippet": f"private-{index}"}
        if spoof:
            payload.update(authenticated=True, verified_build_manifest={"valid": True},
                           clang_array_extent=16, symbol_role="initial_counter")
        rows.append({"candidate_id": f"c{index}", "payload": payload,
                     "payload_sha256": _sha(payload)})
    return {"schema_version": "1.0", "candidates": rows}


def _build(snapshot):
    return build(snapshot, snapshot_sha256="a" * 64, audit=AUDIT,
        priority={"rows": [{"rule_id": "CTR-LEA-001", "proxy_violation_occurrences": 3}]},
        freeze={"api_calls": 0, "snapshot": {"file_sha256": "a" * 64,
            "snapshot_id": "s", "git_commit": "g"}})


def test_negative_entailment_gate_abstains_and_never_authorizes():
    result = _build(_snapshot())
    assert result["population"]["ctr_lea001_occurrences"] == 6
    assert result["population"]["prioritized_proxy_violations"] == 3
    assert result["authenticated_program_context"]["unknown_or_abstain"] == 6
    assert result["evidence_gate"]["extractor_implemented"] == 0
    assert result["production_authorized"] == result["api_calls"] == 0


def test_spoofed_manifest_extent_and_role_cannot_cross_gate():
    context = _build(_snapshot(spoof=True))["authenticated_program_context"]
    assert context == {"verified_preprocessing_binding": 0, "verified_build_manifest": 0,
        "clang_extent_and_symbol_role_fact": 0, "unknown_or_abstain": 6}


def test_audit_or_frozen_population_drift_fails_closed():
    with pytest.raises(ValueError, match="audit_invalid"):
        build(_snapshot(), snapshot_sha256="a" * 64, audit=dict(AUDIT, decision="verified"),
              priority={}, freeze={"api_calls": 0, "snapshot": {"file_sha256": "a" * 64}})
    with pytest.raises(ValueError, match="population_invalid"):
        _build({"schema_version": "1.0", "candidates": _snapshot()["candidates"][:5]})


def test_audit_keeps_normative_and_program_fact_claims_separate():
    claims = AUDIT["atomic_entailment"]
    assert claims["block_size_16_bytes"] == "entailed"
    assert claims["ctr_initial_counter_extent_16_bytes"] == "not_exactly_entailed"
    assert claims["c_array_declaration_proves_counter_role"] == "program_fact_not_normative_text"
    assert AUDIT["atomic_registry_authorized"] is False
