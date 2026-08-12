import pytest
from experiments.atomic_claim_v3_eval import _execution_spec, require_api_key, strict_json

def test_strict_json_rejects_duplicate_keys():
 with pytest.raises(ValueError,match="duplicate"):
  strict_json('{"claim_assessments":[],"claim_assessments":[]}')

def test_strict_json_accepts_closed_single_object():
 assert strict_json('{"claim_assessments":[]}')=={"claim_assessments":[]}

def test_api_key_fails_closed_before_client_construction():
 with pytest.raises(SystemExit,match="no API request"):
  require_api_key("  ")
 assert require_api_key(" private ")=="private"

def test_execution_spec_seals_ordered_universe_and_inputs(tmp_path,monkeypatch):
 snapshot=tmp_path/"snapshot.json";snapshot.write_text("{}",encoding="utf-8")
 paths=[]
 for name in ("registry","audit","index","runner"):
  path=tmp_path/name;path.write_text(name,encoding="utf-8");paths.append(path)
 import experiments.atomic_claim_v3_eval as module
 monkeypatch.setattr(module,"ATOMIC_REGISTRY",paths[0]);monkeypatch.setattr(module,"RULE_EVIDENCE_AUDIT",paths[1])
 monkeypatch.setattr(module,"OFFICIAL_INDEX",paths[2]);monkeypatch.setattr(module,"__file__",str(paths[3]))
 selected=[("id-a",{"rule_id":"A"}),("id-b",{"rule_id":"B"})]
 spec,digest=_execution_spec(snapshot,selected,"abc123")
 assert len(digest)==64
 assert spec["candidate_universe_sha256"]==module._sha(spec["ordered_candidate_binding_hashes"])
 assert len(spec["ordered_candidate_binding_hashes"])==2
 reversed_spec,reversed_digest=_execution_spec(snapshot,list(reversed(selected)),"abc123")
 assert reversed_spec["candidate_universe_sha256"]!=spec["candidate_universe_sha256"]
 assert reversed_digest!=digest
