"""No-API replay; old ledgers remain explicitly partial provenance."""
import argparse,json,hashlib
from collections import Counter
from pathlib import Path
from app.services.atomic_claim_contract import verify_atomic_assessments

def replay(path):
 rows=[json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x]
 if len(rows)!=41 or [r.get("index") for r in rows]!=list(range(41)): raise ValueError("not exact 41 universe")
 results=[]
 for r in rows:
  # Contract text is not retained, so exact structural replay is limited to stored outcome.
  results.append((bool(r.get("structurally_valid")),str(r.get("reason"))))
 missing=sorted({"run_instance_sha256","experiment_spec_sha256","universe_sha256"}-set(rows[0]))
 return {"schema_version":"1.0","evaluation":"atomic_v3_offline_ledger_audit","api_calls":0,
  "population":41,"unique_candidate_bindings":len({r.get("candidate_binding_sha256") for r in rows}),
  "structurally_valid_stored":sum(x for x,_ in results),"stored_reasons":dict(sorted(Counter(y for _,y in results).items())),
  "provenance_status":"legacy_provenance_partial" if missing else "at_execution_complete",
  "missing_row_stamps":missing,"semantic_authorized":0,
  "limitation":"Canonical decisions are present, but missing contract bodies/stamps are not imputed; this audits stored structure outcomes rather than recomputing semantics.",
  "private_ledger_sha256":hashlib.sha256(path.read_bytes()).hexdigest()}
def main():
 p=argparse.ArgumentParser();p.add_argument("ledger",type=Path);p.add_argument("--output",type=Path,required=True);a=p.parse_args();a.output.write_text(json.dumps(replay(a.ledger),sort_keys=True,indent=2)+"\n")
if __name__=="__main__":main()
