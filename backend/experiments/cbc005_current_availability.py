"""API-free CBC-005 evidence and observability availability audit."""
from __future__ import annotations
from collections import Counter
import hashlib,json
from pathlib import Path
from typing import Any
from experiments.l1_snapshot import validate_snapshot
from experiments.workspace_guard import guarded_output_path
BACKEND=Path(__file__).resolve().parents[1];GATE=BACKEND/"mapping/cbc005_entailment_gate.json"
def sha(b:bytes)->str:return hashlib.sha256(b).hexdigest()
def build(snapshot:dict[str,Any],*,snapshot_sha256:str,gate:dict[str,Any]):
 validate_snapshot(snapshot)
 if gate.get("decision")!="remain_fail_closed" or gate.get("production_authorized") is not False:raise ValueError("cbc005_gate_not_fail_closed")
 sources={x["source_id"]:x for x in snapshot["sources"]};rows=[x["payload"] for x in snapshot["candidates"] if x["payload"].get("rule_id")=="CBC-005"]
 if len(rows)!=5:raise ValueError("cbc005_population_invalid")
 lexical=Counter()
 for r in rows:
  s=sources.get(r.get("source_id"));
  if not s or sha(s["content"].encode())!=s["sha256"]:raise ValueError("source_binding_invalid")
  t=str(r.get("snippet") or "").lower();lexical["logging_statement"]+=int(any(x in t for x in ("fprintf","printf","puts","cerr","cout","log")));lexical["constant_definition_only"]+=int(t.lstrip().startswith("#define"))
 return {"schema_version":"1.0","evaluation":"frozen_cbc005_observability_availability_api_free",
  "population":{"occurrences":5,"complete_source":5},"untrusted_lexical_observations":dict(sorted(lexical.items())),
  "authenticated_context":{"complete_service_boundary":0,"external_observability_proved":0,"timing_equivalence_proved":0,"mac_or_ae_ordering_proved":0},
  "outcome":{"unknown_or_abstain":5,"production_authorized":0},"api_calls":0,
  "provenance":{"snapshot_id":snapshot["snapshot_id"],"snapshot_sha256":snapshot_sha256,"gate_sha256":sha(GATE.read_bytes()),"runner_sha256":sha(Path(__file__).read_bytes())},
  "claim_limit":"Lexical triage only; named errors and logging statements are not semantic vulnerability proof.","privacy":"aggregate_only"}
def evaluate(p:Path):raw=p.read_bytes();return build(json.loads(raw),snapshot_sha256=sha(raw),gate=json.loads(GATE.read_text()))
def main():
 import argparse
 p=argparse.ArgumentParser();p.add_argument("snapshot",type=Path);p.add_argument("--output",type=Path,required=True);a=p.parse_args();o=guarded_output_path(a.output);o.write_text(json.dumps(evaluate(a.snapshot),sort_keys=True,indent=2)+"\n")
if __name__=="__main__":main()
