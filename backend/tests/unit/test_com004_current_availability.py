import pytest

from experiments import com004_current_availability as target


def _snapshot(n=16):
    source = {"source_id": "opaque", "content": "void f(void){}\n"}
    import hashlib
    source["sha256"] = hashlib.sha256(source["content"].encode()).hexdigest()
    candidates = []
    for i in range(n):
        payload = {"rule_id": "COM-004", "source_id": "opaque", "line": i + 1,
                   "snippet": "srand((unsigned)time(NULL));" if i < 10 else "x=rand();"}
        candidates.append({"candidate_id": f"id-{i}", "payload": payload,
                           "payload_sha256": "a" * 64})
    return {"schema_version": "1.0", "snapshot_id": "s", "sources": [source],
            "candidates": candidates}


def test_all_occurrences_remain_unknown_without_authenticated_context(monkeypatch):
    monkeypatch.setattr(target, "validate_snapshot", lambda _: {"ok": True})
    result = target.build(_snapshot(), snapshot_sha256="e" * 64,
                   gate={"decision": "remain_fail_closed", "production_authorized": False})
    assert result["population"] == {"occurrences": 16, "complete_source": 16}
    assert result["authenticated_context"]["verified_weak_rng_to_sensitive_sink_defuse"] == 0
    assert result["outcome"] == {"unknown_or_abstain": 16, "production_authorized": 0}


def test_spoofed_candidate_context_is_never_consumed(monkeypatch):
    monkeypatch.setattr(target, "validate_snapshot", lambda _: {"ok": True})
    snapshot = _snapshot()
    for row in snapshot["candidates"]:
        row["payload"]["verified_build_manifest"] = {"trusted": True}
        row["payload"]["sensitive_sink"] = "key"
    result = target.build(snapshot, snapshot_sha256="e" * 64,
                   gate={"decision": "remain_fail_closed", "production_authorized": False})
    assert not any(result["authenticated_context"].values())


def test_population_and_gate_drift_fail_closed(monkeypatch):
    monkeypatch.setattr(target, "validate_snapshot", lambda _: {"ok": True})
    with pytest.raises(ValueError, match="population_invalid"):
        target.build(_snapshot(15), snapshot_sha256="e" * 64,
              gate={"decision": "remain_fail_closed", "production_authorized": False})
    with pytest.raises(ValueError, match="not_fail_closed"):
        target.build(_snapshot(), snapshot_sha256="e" * 64,
              gate={"decision": "verified", "production_authorized": True})
