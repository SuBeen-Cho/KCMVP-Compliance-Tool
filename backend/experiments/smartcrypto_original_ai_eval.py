"""Isolated AI comparator for the frozen original smart-crypto snapshot."""
from __future__ import annotations

import contextlib, hashlib, io, json, os, statistics, time
from collections import Counter
from pathlib import Path
from typing import Any

from app.services.llm.candidate_selector import _select_l3_candidates
from app.services.rag_service import run_l2_rag_context
from experiments.full_stage_boundary_benchmark import load_candidates
from experiments.no_evidence_41_eval import build_prompt

MODEL="gemini-2.5-flash-lite"; INPUT=0.10; OUTPUT=0.40

def select(snapshot:dict[str,Any])->list[dict[str,Any]]:
    with contextlib.redirect_stdout(io.StringIO()):
        routed=run_l2_rag_context(load_candidates(snapshot));chosen={id(x) for x in _select_l3_candidates(routed)}
    return [x for x in routed if id(x) in chosen]

def run(client:Any,snapshot_path:Path,private_path:Path,public_path:Path)->dict[str,Any]:
    snapshot=json.loads(snapshot_path.read_text());selected=select(snapshot)
    if len(snapshot.get("candidates",[]))!=11 or len(selected)!=9:raise ValueError("sealed_11_candidate_9_selected_universe_required")
    rows=[]
    for sequence,candidate in enumerate(selected,1):
        prompt=build_prompt(candidate,evidence_block="")
        started=time.monotonic();response=client.models.generate_content(model=MODEL,contents=prompt,config={"response_mime_type":"application/json","temperature":0,"max_output_tokens":512,"thinking_config":{"thinking_budget":0}});latency=(time.monotonic()-started)*1000
        decision=json.loads(response.text)
        if set(decision)!={"label","confidence","rationale"}:raise ValueError("closed_response_schema_required")
        usage=getattr(response,"usage_metadata",None)
        rows.append({"sequence":sequence,"candidate_sha256":hashlib.sha256(json.dumps(candidate,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest(),"prompt_sha256":hashlib.sha256(prompt.encode()).hexdigest(),"response_sha256":hashlib.sha256(response.text.encode()).hexdigest(),"decision":decision,"latency_ms":round(latency,3),"input_tokens":int(getattr(usage,"prompt_token_count",0) or 0),"output_tokens":int(getattr(usage,"candidates_token_count",0) or 0)})
    private_path.write_text(json.dumps({"schema_version":"1.0","rows":rows},sort_keys=True,indent=2)+"\n");os.chmod(private_path,0o600)
    tin=sum(x["input_tokens"] for x in rows);tout=sum(x["output_tokens"] for x in rows);labels=Counter(x["decision"]["label"] for x in rows)
    result={"schema_version":"1.0","experiment":"smartcrypto_original_isolated_no_rag_ai","model":MODEL,"temperature":0,"snapshot_sha256":hashlib.sha256(snapshot_path.read_bytes()).hexdigest(),"population":{"l1_candidates":11,"selector_candidates":9,"production_ai_ready":0,"production_hold":11},"execution":{"api_calls":9,"duplicate":0,"retry":0,"input_tokens":tin,"output_tokens":tout,"estimated_cost_usd":round((tin*INPUT+tout*OUTPUT)/1_000_000,9)},"labels":dict(sorted(labels.items())),"latency_ms":{"mean":round(statistics.mean(x["latency_ms"] for x in rows),3),"median":round(statistics.median(x["latency_ms"] for x in rows),3),"p95_nearest_rank":sorted(x["latency_ms"] for x in rows)[-1]},"grounded_rag":{"eligible":0,"reason":"no verified official evidence bundle for the five detected rule families"},"claim_limit":"Isolated no-RAG AI label distribution only; no GT, accuracy, verified verdict, or production authorization.","private_ledger_sha256":hashlib.sha256(private_path.read_bytes()).hexdigest()}
    public_path.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n");return result

