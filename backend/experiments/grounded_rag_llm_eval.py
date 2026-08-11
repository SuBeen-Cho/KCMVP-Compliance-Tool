"""Small, opt-in paired LLM evaluation for verified official evidence.

Public artifacts contain only hashes, aggregate metrics, and labels.  Prompts,
source spans, responses, API keys, and absolute paths remain private.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import time
from typing import Any

MODEL = "gemini-2.5-flash-lite"
PROMPT_VERSION = "official-evidence-paired-v5-applicability-citation"
CONDITIONS = ("no_rag", "verified_oracle", "irrelevant_official")
LABELS = ("violation", "non_violation", "not_applicable", "abstain")
INPUT_USD_PER_MILLION = 0.10
OUTPUT_USD_PER_MILLION = 0.40

FIXTURES = (
    ("GCM-002-v", "GCM-002", "violation", "GCM authentication tag length is set to 10 bytes."),
    ("GCM-002-n", "GCM-002", "non_violation", "GCM authentication tag length is set to 16 bytes."),
    ("GCM-002-a", "GCM-002", "not_applicable", "This code implements CBC padding and does not implement GCM or GMAC."),
    ("CCM-003-v", "CCM-003", "violation", "CCM authentication tag length is set to 12 bytes."),
    ("CCM-003-n", "CCM-003", "non_violation", "CCM authentication tag length is set to 14 bytes."),
    ("CCM-003-a", "CCM-003", "not_applicable", "This code implements CTR mode and does not implement CCM."),
    ("LEA-048-v", "LEA-048", "violation", "A discovered LEA MOVS KAT REQUEST exchange file is named lea_vector.bin."),
    ("LEA-048-n", "LEA-048", "non_violation", "A discovered LEA MOVS KAT REQUEST exchange file is named LEA128ECBKAT.req."),
    ("LEA-048-a", "LEA-048", "not_applicable", "This is LEA runtime encryption code, not a MOVS KAT/MMT/MCT exchange artifact."),
)
RULE_REQUIREMENTS = {
    "GCM-002": "For the KCMVP GCM/GMAC profile, authentication tags are 14 through 16 bytes (112 through 128 bits).",
    "CCM-003": "For the KCMVP CCM profile, authentication tags are 14 or 16 bytes (112 or 128 bits).",
    "LEA-048": "A discovered LEA MOVS KAT/MMT/MCT exchange artifact must follow LEA[key length][mode][test type].(req|rsp|fax); absence of such artifacts alone is not a violation.",
}


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value: Any) -> str:
    return hashlib.sha256(value if isinstance(value, bytes) else canonical(value)).hexdigest()


def load_evidence(index_path: Path, audit_path: Path) -> tuple[dict[str, list[dict]], dict[str, dict]]:
    index = json.loads(index_path.read_text(encoding="utf-8"))
    audit = json.loads(audit_path.read_text(encoding="utf-8"))["rules"]
    units = {u["unit_id"]: u for u in index["units"]}
    selected = {rid: [units[x] for x in audit[rid]["evidence_unit_ids"]] for rid in {f[1] for f in FIXTURES}}
    return selected, audit


def build_prompt(fixture: tuple[str, str, str, str], condition: str, evidence: list[dict]) -> str:
    fid, rule_id, _gt, observation = fixture
    disclosed = [{"unit_id": u["unit_id"], "source_id": u["source_id"], "locator": u["locator"], "span": u["text"]} for u in evidence]
    return f"""Act as a strict KCMVP evaluator. Judge only the stated observation.
Return JSON only: label (violation|non_violation|not_applicable|abstain), evidence_unit_ids (array),
supporting_spans (exact short substrings of supplied evidence), evidence_entails_verdict (boolean),
applicability (true|false), exceptions_checked (array), counterevidence (array), rationale (max 160 chars).
Do not cite evidence that does not govern rule_id. In a RAG condition, every violation,
non_violation, or not_applicable verdict must cite at least one supplied official unit actually
used to establish the rule domain or applicability boundary. For not_applicable, the cited unit
establishes the governed domain and the observation establishes that the occurrence is outside it.
If the supplied units do not support that applicability reasoning, return label=abstain with empty
evidence arrays; never invent or force a citation. The runner resolves cited IDs to the immutable
exact span; do not paraphrase a supporting span. In no_rag, give the best code-only label and leave
evidence arrays empty.
fixture_id={fid}; rule_id={rule_id}; observation={observation}
rule_requirement={RULE_REQUIREMENTS[rule_id]}
condition={condition}; official_evidence={json.dumps(disclosed, ensure_ascii=False, sort_keys=True)}"""


def final_disposition(raw_label: str, condition: str, verified: bool) -> str:
    if condition == "no_rag":
        return raw_label
    return raw_label if verified else "abstain"


def canonicalize_cited_spans(decision: dict, evidence: list[dict]) -> tuple[dict, bool]:
    """Resolve model-selected IDs to exact immutable spans before verification."""
    ids = decision.get("evidence_unit_ids")
    if not isinstance(ids, list) or not all(isinstance(x, str) for x in ids):
        return decision, False
    by_id = {u["unit_id"]: u["text"] for u in evidence}
    if not ids or any(x not in by_id for x in ids):
        return decision, False
    value = dict(decision)
    value["supporting_spans"] = [by_id[x] for x in ids]
    return value, True


def _metrics(rows: list[dict]) -> dict:
    out: dict[str, Any] = {}
    for condition in CONDITIONS:
        part = [r for r in rows if r["condition"] == condition]
        decided = [r for r in part if r["final_disposition"] != "abstain"]
        tp = sum(r["final_disposition"] == "violation" and r["gt"] == "violation" for r in part)
        fp = sum(r["final_disposition"] == "violation" and r["gt"] != "violation" for r in part)
        fn = sum(r["final_disposition"] != "violation" and r["gt"] == "violation" for r in part)
        precision = tp / (tp + fp) if tp + fp else None
        recall = tp / (tp + fn) if tp + fn else 0.0
        out[condition] = {
            "n": len(part), "raw_accuracy": sum(r["raw_label"] == r["gt"] for r in part) / len(part),
            "final_accuracy_all": sum(r["final_disposition"] == r["gt"] for r in part) / len(part),
            "coverage": len(decided) / len(part), "abstention_rate": 1 - len(decided) / len(part),
            "violation_precision": precision, "violation_recall": recall,
            "input_tokens": sum(r["input_tokens"] or 0 for r in part), "output_tokens": sum(r["output_tokens"] or 0 for r in part),
            "mean_latency_ms": sum(r["latency_ms"] for r in part) / len(part),
            "citation_coverage": sum(bool(r.get("span_canonicalized")) for r in part) / len(part),
            "estimated_cost_usd": round((sum(r["input_tokens"] or 0 for r in part) * INPUT_USD_PER_MILLION + sum(r["output_tokens"] or 0 for r in part) * OUTPUT_USD_PER_MILLION) / 1_000_000, 9),
            "verifier_reasons": dict(Counter(r["verifier_reason"] for r in part)),
        }
    base = {(r["fixture_id"]): r for r in rows if r["condition"] == "no_rag"}
    for condition in CONDITIONS[1:]:
        paired = [(base[r["fixture_id"]], r) for r in rows if r["condition"] == condition]
        gains = sum((b["raw_label"] != b["gt"]) and (x["raw_label"] == x["gt"]) for b,x in paired)
        losses = sum((b["raw_label"] == b["gt"]) and (x["raw_label"] != x["gt"]) for b,x in paired)
        discordant = gains + losses
        exact_p = min(1.0, 2 * sum(math.comb(discordant, k) for k in range(min(gains, losses) + 1)) / (2 ** discordant)) if discordant else 1.0
        out[condition].update({"paired_gains_vs_no_rag":gains, "paired_losses_vs_no_rag":losses, "paired_raw_correctness_delta_vs_no_rag":gains-losses, "mcnemar_exact_two_sided_p":exact_p})
    return out


def stratified_metrics(rows: list[dict]) -> dict:
    """Keep the pending LEA mapping separate from the trusted numeric profiles."""
    return {
        "gcm_ccm": _metrics([row for row in rows if row["rule_id"] != "LEA-048"]),
        "lea_mapping_pending_reaudit": _metrics([row for row in rows if row["rule_id"] == "LEA-048"]),
    }


def run(client: Any, index_path: Path, audit_path: Path, private_ledger: Path, public_output: Path) -> dict:
    from app.services.rag_grounding import normalize_evidence_bundle, verify_citation_bound_decision
    selected, audit = load_evidence(index_path, audit_path)
    irrelevant = {"GCM-002": selected["CCM-003"], "CCM-003": selected["GCM-002"], "LEA-048": selected["GCM-002"]}
    rows = []
    private_ledger.parent.mkdir(parents=True, exist_ok=True)
    for fixture in FIXTURES:
        fid, rule_id, gt, _ = fixture
        for condition in CONDITIONS:
            evidence = [] if condition == "no_rag" else selected[rule_id] if condition == "verified_oracle" else irrelevant[rule_id]
            prompt = build_prompt(fixture, condition, evidence)
            started = time.monotonic()
            response = client.models.generate_content(model=MODEL, contents=prompt, config={"response_mime_type":"application/json", "temperature":0, "max_output_tokens":1024, "thinking_config":{"thinking_budget":0}})
            latency = round((time.monotonic() - started) * 1000, 3)
            decision = json.loads(response.text)
            expected_fields = {"label","evidence_unit_ids","supporting_spans","evidence_entails_verdict","applicability","exceptions_checked","counterevidence","rationale"}
            if not isinstance(decision, dict) or set(decision) != expected_fields:
                raise ValueError("LLM response violates the closed experiment schema")
            decision, span_canonicalized = canonicalize_cited_spans(decision, evidence)
            usage = getattr(response, "usage_metadata", None)
            verified, reason = True, "not_required"
            if condition != "no_rag":
                candidate = {"rule_id": rule_id, "rag_route":{"decision":"retrieve"}, "rag_evidence_bundle": normalize_evidence_bundle([dict(u, status="verified", source_sha256=audit[rule_id]["source_sha256"]) for u in evidence])}
                check = verify_citation_bound_decision(candidate, decision)
                verified, reason = check["verified"], check["reason"]
            raw = decision.get("label") if decision.get("label") in LABELS else "invalid"
            row = {"fixture_id":fid, "rule_id":rule_id, "gt":gt, "condition":condition, "raw_label":raw, "verifier_passed":verified, "verifier_reason":reason, "span_canonicalized":span_canonicalized, "final_disposition":final_disposition(raw, condition, verified), "input_tokens":getattr(usage,"prompt_token_count",None), "output_tokens":getattr(usage,"candidates_token_count",None), "latency_ms":latency, "prompt_sha256":digest(prompt.encode()), "response_sha256":digest(response.text.encode())}
            rows.append(row)
            with private_ledger.open("a", encoding="utf-8") as fh: fh.write(json.dumps(row, sort_keys=True)+"\n")
    safe_rows = [{k:v for k,v in r.items() if k not in {"prompt_sha256","response_sha256"}} for r in rows]
    created_at = datetime.now(timezone.utc).isoformat()
    runner_path = Path(__file__).resolve()
    provenance = {
        "provenance_capture": "at_execution",
        "model": MODEL, "temperature": 0, "seed": None,
        "request_count": len(rows), "response_contract": "closed-json-v1",
        "official_evidence_index_sha256": hashlib.sha256(index_path.read_bytes()).hexdigest(),
        "rule_evidence_audit_sha256": hashlib.sha256(audit_path.read_bytes()).hexdigest(),
        "runner_source_sha256": hashlib.sha256(runner_path.read_bytes()).hexdigest(),
    }
    run_id = digest({"created_at":created_at, "prompt_version":PROMPT_VERSION,
                     "fixture_set_sha256":digest(FIXTURES), "provenance":provenance,
                     "row_hashes":[r["response_sha256"] for r in rows]})
    result = {"schema_version":"1.1", "run_id":run_id, "created_at":created_at, "model":MODEL, "prompt_version":PROMPT_VERSION, "run_provenance":provenance, "pricing_assumption":{"input_usd_per_million":INPUT_USD_PER_MILLION,"output_usd_per_million":OUTPUT_USD_PER_MILLION}, "fixture_set_sha256":digest(FIXTURES), "conditions":list(CONDITIONS), "rows":safe_rows, "metrics":_metrics(rows), "stratified_metrics":stratified_metrics(rows)}
    public_output.write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2)+"\n", encoding="utf-8")
    return result


def main() -> None:
    parser=argparse.ArgumentParser(); parser.add_argument("--execute", action="store_true"); parser.add_argument("--output", type=Path, required=True); parser.add_argument("--ledger", type=Path, required=True); args=parser.parse_args()
    if not args.execute: raise SystemExit("Refusing paid API calls without --execute")
    from app.config import settings
    if not settings.GOOGLE_API_KEY: raise SystemExit("GOOGLE_API_KEY is not configured")
    from google import genai
    client=genai.Client(api_key=settings.GOOGLE_API_KEY)
    root=Path(__file__).resolve().parents[1]
    run(client, root/"data/evidence/official_units.local.json", root/"mapping/rule_evidence_audit.json", args.ledger, args.output)

if __name__ == "__main__": main()
