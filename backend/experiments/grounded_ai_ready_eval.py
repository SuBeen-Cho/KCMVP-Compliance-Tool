"""Opt-in paired Gemini evaluation of the exact AI-ready stage population.

Private inputs, prompts, responses and occurrence identities stay in a mode-0600
JSONL ledger.  The public result is aggregate-only and is not an accuracy claim.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import statistics
import subprocess
import time
from typing import Any

from app.services.analysis_stage_contract import ai_is_authorized, close_for_l3
from app.services.llm.candidate_selector import _select_l3_candidates
from app.services.rag_grounding import route_rag, verify_citation_bound_decision
from app.services.rag_service import run_l2_rag_context
from experiments.full_stage_boundary_benchmark import load_candidates

MODEL = "gemini-2.5-flash-lite"
PROMPT_VERSION = "ai-ready-grounded-paired-v1"
LABELS = frozenset({"violation", "non_violation", "not_applicable", "abstain"})
INPUT_USD_PER_MILLION = 0.10
OUTPUT_USD_PER_MILLION = 0.40
FIELDS = {"label", "evidence_unit_ids", "supporting_spans", "evidence_entails_verdict",
          "applicability", "exceptions_checked", "counterevidence", "rationale"}


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode()


def _sha(value: Any) -> str:
    return hashlib.sha256(value if isinstance(value, bytes) else _canonical(value)).hexdigest()


def select_exact_ai_ready(snapshot: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    envelopes = snapshot.get("candidates") or []
    payloads = load_candidates(snapshot)
    routed = run_l2_rag_context(payloads)
    closed = [close_for_l3(row) for row in routed]
    selected = {id(row) for row in _select_l3_candidates(closed)}
    result = []
    for envelope, row in zip(envelopes, closed, strict=True):
        claimed = row.get("rag_route") or {}
        recomputed = route_rag({k: v for k, v in row.items() if k != "rag_route"})
        if (id(row) in selected and row.get("disposition") == "ai_required"
                and row.get("ai_need") == "required" and ai_is_authorized(row)
                and claimed.get("decision") == recomputed.get("decision") == "retrieve"):
            result.append((str(envelope["candidate_id"]), row))
    return result


def build_prompt(candidate: dict[str, Any], evidence: list[dict[str, Any]]) -> str:
    observation = {
        "rule_id": candidate.get("rule_id"), "pattern_type": candidate.get("pattern_type"),
        "detection_semantics": candidate.get("detection_semantics"),
        "scope": candidate.get("scope"), "snippet": candidate.get("snippet") or "",
        "project_artifact_evidence": candidate.get("project_artifact_evidence") or "",
    }
    disclosed = [{"unit_id": u.get("unit_id"), "source_id": u.get("source_id"),
                  "locator": u.get("locator"), "span": u.get("span")} for u in evidence]
    return """Act as a strict KCMVP occurrence evaluator. Judge only the observation.
Return exactly one JSON object with: label (violation|non_violation|not_applicable|abstain),
evidence_unit_ids (array), supporting_spans (array), evidence_entails_verdict (boolean),
applicability (true|false), exceptions_checked (array), counterevidence (array), rationale (max 160 chars).
Never invent facts. If context is insufficient, abstain. If official_evidence is non-empty, every
non-abstain label must cite only supplied unit IDs and exact substrings. Evidence must establish the
rule and applicability; the observation establishes the program fact.
""" + \
        "observation=" + json.dumps(observation, ensure_ascii=False, sort_keys=True) + "\n" + \
        "official_evidence=" + json.dumps(disclosed, ensure_ascii=False, sort_keys=True)


def _canonicalize(decision: dict[str, Any], evidence: list[dict[str, Any]]) -> tuple[dict[str, Any], bool]:
    ids = decision.get("evidence_unit_ids")
    by_id = {str(u.get("unit_id")): str(u.get("span") or "") for u in evidence}
    if not isinstance(ids, list) or not ids or any(x not in by_id for x in ids):
        return decision, False
    value = dict(decision)
    value["supporting_spans"] = [by_id[x] for x in ids]
    return value, True


def _call(client: Any, prompt: str) -> tuple[dict[str, Any], dict[str, Any]]:
    started = time.monotonic()
    response = client.models.generate_content(
        model=MODEL, contents=prompt,
        config={"response_mime_type": "application/json", "temperature": 0,
                "max_output_tokens": 1024, "thinking_config": {"thinking_budget": 0}},
    )
    latency = round((time.monotonic() - started) * 1000, 3)
    raw = json.loads(response.text)
    schema_valid = isinstance(raw, dict) and set(raw) == FIELDS and raw.get("label") in LABELS
    decision = raw if schema_valid else {
        "label": "abstain", "evidence_unit_ids": [], "supporting_spans": [],
        "evidence_entails_verdict": False, "applicability": False,
        "exceptions_checked": [], "counterevidence": [],
        "rationale": "closed_schema_invalid",
    }
    usage = getattr(response, "usage_metadata", None)
    return decision, {"latency_ms": latency, "schema_valid": schema_valid,
                      "input_tokens": getattr(usage, "prompt_token_count", None),
                      "output_tokens": getattr(usage, "candidates_token_count", None),
                      "response_sha256": _sha(response.text.encode())}


def run(client: Any, snapshot_path: Path, ledger_path: Path, output_path: Path) -> dict[str, Any]:
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    selected = select_exact_ai_ready(snapshot)
    if len(selected) != 41:
        raise ValueError(f"exact AI-ready gate expected 41, got {len(selected)}")
    ordered_hashes = [_sha({k: v for k, v in row.items() if k not in
                            {"rag_evidence_bundle", "rag_guideline_text", "rag_route"}})
                      for _, row in selected]
    envelope_binding_hashes = [_sha({"candidate_id": cid, "payload": row}) for cid, row in selected]
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    ledger_path.touch(mode=0o600, exist_ok=True)
    os.chmod(ledger_path, 0o600)
    rows = [json.loads(line) for line in ledger_path.read_text(encoding="utf-8").splitlines() if line]
    completed = {(row["index"], row["condition"]) for row in rows}
    run_started = datetime.now(timezone.utc).isoformat()
    git_head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=Path(__file__).resolve().parents[2],
                              check=True, capture_output=True, text=True).stdout.strip()
    for index, (candidate_id, candidate) in enumerate(selected):
        evidence = list(candidate.get("rag_evidence_bundle") or [])
        for condition in ("no_rag", "grounded"):
            if (index, condition) in completed:
                continue
            supplied = [] if condition == "no_rag" else evidence
            prompt = build_prompt(candidate, supplied)
            decision, usage = _call(client, prompt)
            canonicalized = False
            verified, reason = False, "evidence_not_supplied"
            if condition == "grounded":
                decision, canonicalized = _canonicalize(decision, supplied)
                check = verify_citation_bound_decision(candidate, decision)
                verified, reason = bool(check["verified"]), str(check["reason"])
            raw_label = decision["label"]
            final = raw_label if condition == "grounded" and verified else "abstain"
            private = {"run_started_at": run_started, "git_head": git_head, "model": MODEL,
                       "prompt_version": PROMPT_VERSION, "index": index,
                       "candidate_id_sha256": _sha(candidate_id.encode()), "condition": condition,
                       "prompt_sha256": _sha(prompt.encode()), "raw_label": raw_label,
                       "verified_final": final, "verifier_passed": verified,
                       "verifier_reason": reason, "span_canonicalized": canonicalized,
                       # Private-only replay payload. Earlier v1 ledgers omitted
                       # this and therefore cannot be scientifically reverified.
                       "decision": decision,
                       "retry_count": 0, **usage}
            with ledger_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(private, ensure_ascii=False, sort_keys=True) + "\n")
            rows.append(private)
    physical_request_count = len(rows)
    physical_input_tokens = sum(row.get("input_tokens") or 0 for row in rows)
    physical_output_tokens = sum(row.get("output_tokens") or 0 for row in rows)
    unique_rows: dict[tuple[int, str], dict[str, Any]] = {}
    for row in rows:
        unique_rows.setdefault((row["index"], row["condition"]), row)
    rows = list(unique_rows.values())
    if len(rows) != 82:
        raise ValueError(f"complete paired ledger expected 82 unique rows, got {len(rows)}")
    by_condition = {}
    for condition in ("no_rag", "grounded"):
        part = [r for r in rows if r["condition"] == condition]
        by_condition[condition] = {
            "request_count": len(part), "raw_labels": dict(sorted(Counter(r["raw_label"] for r in part).items())),
            "verified_final_labels": dict(sorted(Counter(r["verified_final"] for r in part).items())),
            "verifier_pass_count": sum(r["verifier_passed"] for r in part),
            "verifier_reasons": dict(sorted(Counter(r["verifier_reason"] for r in part).items())),
            "input_tokens": sum(r["input_tokens"] or 0 for r in part),
            "output_tokens": sum(r["output_tokens"] or 0 for r in part),
            "latency_ms_mean": statistics.mean(r["latency_ms"] for r in part),
            "latency_ms_median": statistics.median(r["latency_ms"] for r in part),
        }
        by_condition[condition]["estimated_cost_usd"] = round(
            (by_condition[condition]["input_tokens"] * INPUT_USD_PER_MILLION
             + by_condition[condition]["output_tokens"] * OUTPUT_USD_PER_MILLION) / 1_000_000, 9)
    pairs = {(r["index"], r["condition"]): r for r in rows}
    transitions = Counter(f'{pairs[(i,"no_rag")]["raw_label"]}->{pairs[(i,"grounded")]["raw_label"]}' for i in range(41))
    result = {"schema_version": "1.0", "experiment": "historical_265_exact_ai_ready41_paired",
              "claim_limit": "Routing utility and grounded-verifier behavior only; no independent GT and no accuracy claim.",
              "model": MODEL, "prompt_version": PROMPT_VERSION, "run_started_at": run_started,
              "population": {"historical_candidates": 265, "exact_ai_ready": 41,
                             "ordered_candidate_hashes_sha256": _sha(ordered_hashes),
                             "ordered_envelope_binding_hashes_sha256": _sha(envelope_binding_hashes)},
              "execution": {"conditions": ["no_rag", "grounded"], "repeats": 1,
                            "unique_analyzed_request_count": len(rows),
                            "physical_api_request_count": physical_request_count,
                            "duplicate_request_count": physical_request_count - len(rows),
                            "physical_input_tokens": physical_input_tokens,
                            "physical_output_tokens": physical_output_tokens,
                            "physical_estimated_cost_usd": round(
                                (physical_input_tokens * INPUT_USD_PER_MILLION
                                 + physical_output_tokens * OUTPUT_USD_PER_MILLION) / 1_000_000, 9),
                            "retry_count": 0},
              "conditions": by_condition, "raw_label_transitions": dict(sorted(transitions.items())),
              "provenance": {"git_head": git_head, "snapshot_sha256": hashlib.sha256(snapshot_path.read_bytes()).hexdigest(),
                             "official_index_sha256": hashlib.sha256((Path(__file__).resolve().parents[1]/"data/evidence/official_units.local.json").read_bytes()).hexdigest(),
                             "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},
              "privacy": "aggregate_only; prompts, responses, occurrence IDs and source text are private mode-0600"}
    result["result_sha256"] = _sha(result)
    output_path.write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2)+"\n", encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(); parser.add_argument("snapshot", type=Path)
    parser.add_argument("--ledger", type=Path, required=True); parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--execute", action="store_true"); args = parser.parse_args()
    if not args.execute: raise SystemExit("Refusing paid API calls without --execute")
    from app.config import settings
    if not settings.GOOGLE_API_KEY: raise SystemExit("GOOGLE_API_KEY is not configured")
    from google import genai
    run(genai.Client(api_key=settings.GOOGLE_API_KEY), args.snapshot, args.ledger, args.output)


if __name__ == "__main__": main()
