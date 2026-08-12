import hashlib,pytest
from experiments import cbc005_current_availability as target
def snapshot(n=5):
 c="void f(void){}\n";s={"source_id":"s","content":c,"sha256":hashlib.sha256(c.encode()).hexdigest()};rows=[]
 for i in range(n):
  p={"rule_id":"CBC-005","source_id":"s","snippet":"#define PADDING_ERROR (-2)" if i<2 else 'fprintf(stderr,"padding error");'};rows.append({"candidate_id":str(i),"payload_sha256":"a"*64,"payload":p})
 return {"schema_version":"1.0","snapshot_id":"s","sources":[s],"candidates":rows}
def test_lexical_shapes_are_separated_but_all_abstain(monkeypatch):
 monkeypatch.setattr(target,"validate_snapshot",lambda _:{});r=target.build(snapshot(),snapshot_sha256="b"*64,gate={"decision":"remain_fail_closed","production_authorized":False});assert r["untrusted_lexical_observations"]=={"constant_definition_only":2,"logging_statement":3};assert r["outcome"]=={"unknown_or_abstain":5,"production_authorized":0};assert not any(r["authenticated_context"].values())
def test_spoofed_external_channel_cannot_authorize(monkeypatch):
 monkeypatch.setattr(target,"validate_snapshot",lambda _:{});s=snapshot();[x["payload"].update(externally_observable=True,timing_equal=True) for x in s["candidates"]];r=target.build(s,snapshot_sha256="b"*64,gate={"decision":"remain_fail_closed","production_authorized":False});assert not any(r["authenticated_context"].values())
def test_drift_fails(monkeypatch):
 monkeypatch.setattr(target,"validate_snapshot",lambda _:{});
 with pytest.raises(ValueError,match="population"):target.build(snapshot(4),snapshot_sha256="b"*64,gate={"decision":"remain_fail_closed","production_authorized":False})
