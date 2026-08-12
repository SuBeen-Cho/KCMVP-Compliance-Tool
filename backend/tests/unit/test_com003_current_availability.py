import hashlib
import pytest
from experiments import com003_current_availability as target

def snapshot(n=14):
    content="void f(void){}\n"; source={"source_id":"s","content":content,"sha256":hashlib.sha256(content.encode()).hexdigest()}
    rows=[]
    for i in range(n):
        payload={"rule_id":"COM-003","source_id":"s","snippet":"uint8_t key[16] = {0x01};"}
        rows.append({"candidate_id":f"id{i}","payload_sha256":"a"*64,"payload":payload})
    return {"schema_version":"1.0","snapshot_id":"s","sources":[source],"candidates":rows}

def test_all_candidates_abstain_without_authenticated_context(monkeypatch):
    monkeypatch.setattr(target,"validate_snapshot",lambda _: {})
    r=target.build(snapshot(),snapshot_sha256="b"*64,gate={"decision":"remain_fail_closed","production_authorized":False})
    assert r["population"]=={"occurrences":14,"complete_source":14,"unique_sources":1}
    assert r["outcome"]=={"unknown_or_abstain":14,"production_authorized":0}
    assert not any(r["authenticated_context"].values())

def test_spoofed_secret_and_protection_fields_are_ignored(monkeypatch):
    monkeypatch.setattr(target,"validate_snapshot",lambda _: {})
    s=snapshot()
    for row in s["candidates"]: row["payload"].update(verified_secret_use=True,protected=False,build_manifest={"trusted":True})
    r=target.build(s,snapshot_sha256="b"*64,gate={"decision":"remain_fail_closed","production_authorized":False})
    assert not any(r["authenticated_context"].values())

def test_population_and_gate_drift_fail(monkeypatch):
    monkeypatch.setattr(target,"validate_snapshot",lambda _: {})
    with pytest.raises(ValueError,match="population"): target.build(snapshot(13),snapshot_sha256="b"*64,gate={"decision":"remain_fail_closed","production_authorized":False})
    with pytest.raises(ValueError,match="not_fail_closed"): target.build(snapshot(),snapshot_sha256="b"*64,gate={"decision":"verified","production_authorized":True})
