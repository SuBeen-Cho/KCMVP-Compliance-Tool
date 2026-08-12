import hashlib
import json

import pytest

from experiments import current45_lea_round_chain_availability as target


def _sha(value):
    return hashlib.sha256(value).hexdigest()


def _inputs(with_receipts=False):
    content = "void f(void) {}\n"
    source_hash = _sha(content.encode())
    snapshot = {"sources": [{"source_id": "S", "content": content, "sha256": source_hash}],
                "candidates": []}
    selected = []
    for index in range(45):
        rule = target.TARGET_RULES[index] if index < 4 else "CBC-001"
        row = {"rule_id": rule, "source_id": "S"}
        if with_receipts and index < 4:
            prep = {"schema_version": "1.0", "authenticated": True,
                    "context_complete": True, "source_sha256": source_hash,
                    "preprocessed_sha256": "a" * 64, "input_manifest_sha256": "b" * 64,
                    "compiler_binary_sha256": "c" * 64,
                    "verification_receipt_sha256": "f" * 64}
            callsite = {"schema_version": "1.0", "structural_complete": True,
                        "nonoverlap_proved": True, "preprocessed_sha256": "a" * 64,
                        "proof_sha256": "d" * 64, "verification_receipt_sha256": "e" * 64}
            row.update(verified_preprocessing_receipt=prep,
                       verified_callsite_nonoverlap_receipt=callsite)
        selected.append((f"id-{index}", row))
    snapshot_hash = "e" * 64
    membership = "f" * 64
    freeze = {
        "scope": "clean_current_head_router_universe_freeze_api_free", "api_calls": 0,
        "router_manifest": {"git_dirty": False},
        "snapshot": {"file_sha256": snapshot_hash, "snapshot_id": "1" * 64,
                     "git_commit": "2" * 40},
        "current_router": {"ai_ready_count": 45,
                           "ordered_envelope_binding_hashes_sha256": membership,
                           "rule_family_counts": {rule: 1 for rule in target.TARGET_RULES}},
    }
    router = {"snapshot": {"file_sha256": snapshot_hash},
              "ai_ready_universe": {"ordered_envelope_binding_hashes_sha256": membership}}
    return snapshot, selected, freeze, router, snapshot_hash


def test_plain_manifest_names_do_not_count_as_authenticated(monkeypatch):
    snapshot, selected, freeze, router, snapshot_hash = _inputs()
    for _, row in selected[:4]:
        row["trusted_preprocessing_manifest"] = {"claimed": True}
        row["trusted_callsite_manifest"] = {"claimed": True}
    monkeypatch.setattr(target, "select_exact_ai_ready", lambda _: selected)
    result = target.build(snapshot, snapshot_sha256=snapshot_hash, freeze=freeze,
                          router_result=router, freeze_sha256="3" * 64)
    assert result["coverage"] == {
        "complete_source": 4, "trusted_preprocessing_manifest": 0,
        "operation_graph_input_available": 0, "callsite_nonoverlap_proved": 0,
        "chain_available": 0,
    }
    assert result["api_calls"] == result["semantic_authorization"] == 0
    assert result["fact_state"] == "unknown"


def test_candidate_supplied_verified_receipts_are_never_trusted(monkeypatch):
    snapshot, selected, freeze, router, snapshot_hash = _inputs(with_receipts=True)
    monkeypatch.setattr(target, "select_exact_ai_ready", lambda _: selected)
    result = target.build(snapshot, snapshot_sha256=snapshot_hash, freeze=freeze,
                          router_result=router, freeze_sha256="3" * 64)
    assert result["coverage"]["complete_source"] == 4
    assert set(value for key, value in result["coverage"].items()
               if key != "complete_source") == {0}
    assert all(identifier not in json.dumps(result) for identifier in ("id-0", "id-1"))
    assert result["semantic_authorization"] == 0


def test_tampered_receipt_fails_closed(monkeypatch):
    snapshot, selected, freeze, router, snapshot_hash = _inputs(with_receipts=True)
    selected[0][1]["verified_preprocessing_receipt"]["preprocessed_sha256"] = "0" * 64
    monkeypatch.setattr(target, "select_exact_ai_ready", lambda _: selected)
    result = target.build(snapshot, snapshot_sha256=snapshot_hash, freeze=freeze,
                          router_result=router, freeze_sha256="3" * 64)
    assert result["coverage"]["trusted_preprocessing_manifest"] == 0
    assert result["coverage"]["chain_available"] == 0


def test_frozen_snapshot_or_exact_target_membership_cannot_drift(monkeypatch):
    snapshot, selected, freeze, router, snapshot_hash = _inputs()
    monkeypatch.setattr(target, "select_exact_ai_ready", lambda _: selected)
    with pytest.raises(ValueError, match="snapshot_hash_mismatch"):
        target.build(snapshot, snapshot_sha256="0" * 64, freeze=freeze,
                     router_result=router, freeze_sha256="3" * 64)
    selected[0][1]["rule_id"] = "CBC-001"
    with pytest.raises(ValueError, match="exact_occurrences_invalid"):
        target.build(snapshot, snapshot_sha256=snapshot_hash, freeze=freeze,
                     router_result=router, freeze_sha256="3" * 64)
