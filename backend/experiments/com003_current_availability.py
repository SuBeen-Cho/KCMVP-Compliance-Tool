"""API-free availability audit for frozen COM-003 candidates."""
from __future__ import annotations
from collections import Counter
import hashlib, json
from pathlib import Path
from typing import Any
from experiments.l1_snapshot import validate_snapshot
from experiments.workspace_guard import guarded_output_path

BACKEND = Path(__file__).resolve().parents[1]
GATE = BACKEND / "mapping/com003_entailment_gate.json"

def _sha(raw: bytes) -> str: return hashlib.sha256(raw).hexdigest()

def build(snapshot: dict[str, Any], *, snapshot_sha256: str, gate: dict[str, Any]) -> dict[str, Any]:
    validate_snapshot(snapshot)
    if gate.get("decision") != "remain_fail_closed" or gate.get("production_authorized") is not False:
        raise ValueError("com003_gate_not_fail_closed")
    sources={x["source_id"]:x for x in snapshot["sources"]}
    rows=[x["payload"] for x in snapshot["candidates"] if x["payload"].get("rule_id")=="COM-003"]
    if len(rows)!=14: raise ValueError("com003_population_invalid")
    lexical=Counter(); complete=0
    for row in rows:
        source=sources.get(row.get("source_id"))
        if not source or _sha(source["content"].encode())!=source["sha256"]: raise ValueError("source_binding_invalid")
        complete+=1; text=str(row.get("snippet") or "").lower()
        lexical["key_name"]+=int("key" in text)
        lexical["iv_or_counter_name"]+=int(any(x in text for x in ("iv","ctr","counter")))
        lexical["test_name"]+=int("test" in text)
    return {"schema_version":"1.0","evaluation":"frozen_com003_program_fact_availability_api_free",
      "population":{"occurrences":14,"complete_source":complete,"unique_sources":len({x["source_id"] for x in rows})},
      "untrusted_lexical_observations":dict(sorted(lexical.items())),
      "authenticated_context":{"trusted_preprocessing":0,"verified_build_manifest":0,
        "verified_operational_secret_use":0,"verified_exception_and_protection_status":0},
      "outcome":{"unknown_or_abstain":14,"production_authorized":0},"api_calls":0,
      "provenance":{"snapshot_id":snapshot["snapshot_id"],"snapshot_sha256":snapshot_sha256,
        "entailment_gate_sha256":_sha(GATE.read_bytes()),"runner_sha256":_sha(Path(__file__).read_bytes())},
      "privacy":"aggregate_only; no candidate identity, path, source, snippet, or literal bytes",
      "claim_limit":"Availability and lexical triage only; no accuracy or secret-use claim."}

def evaluate(path: Path):
    raw=path.read_bytes(); return build(json.loads(raw),snapshot_sha256=_sha(raw),gate=json.loads(GATE.read_text()))

def main():
    import argparse
    p=argparse.ArgumentParser();p.add_argument("snapshot",type=Path);p.add_argument("--output",type=Path,required=True);a=p.parse_args()
    out=guarded_output_path(a.output);out.write_text(json.dumps(evaluate(a.snapshot),sort_keys=True,indent=2)+"\n")
if __name__=="__main__": main()
