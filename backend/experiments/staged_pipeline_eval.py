"""Strict, offline evaluator for the need-gated AI pipeline.

The module intentionally depends on no production service.  A runner exports one
JSON observation per case; this evaluator validates the closed contract and
produces reproducible aggregate metrics.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any


STAGES = ("deterministic", "retrieval", "ai", "abstain")
VERIFIER = ("pass", "fail", "not_applicable")
ROUTE_PARTITIONS = ("selected_deterministic", "selected_retrieve", "skip", "unresolved")
INTEGRITY_GATES = ("pass", "route_missing", "forged", "live_mismatch")
ALLOWED_TOP = {"schema_version", "run", "pricing", "cases"}
ALLOWED_RUN = {"system", "dataset", "seed", "notes"}
ALLOWED_PRICING = {"input_usd_per_million", "output_usd_per_million"}
ALLOWED_CASE = {
    "case_id", "stage", "evidence_required", "official_evidence_ids",
    "verifier", "final_disposition", "baseline_llm_calls", "actual_llm_calls",
    "input_tokens", "output_tokens", "latency_ms", "cost_usd",
    "route_partition", "integrity_gate",
}


class EvaluationInputError(ValueError):
    """Raised when an observation violates the closed evaluation contract."""


def _closed(obj: Any, allowed: set[str], where: str) -> dict[str, Any]:
    if not isinstance(obj, dict):
        raise EvaluationInputError(f"{where}: object required")
    extra = set(obj) - allowed
    if extra:
        raise EvaluationInputError(f"{where}: unknown fields: {sorted(extra)}")
    return obj


def _nonnegative(value: Any, where: str, integer: bool = False) -> float | int:
    kind = int if integer else (int, float)
    if isinstance(value, bool) or not isinstance(value, kind) or value < 0:
        raise EvaluationInputError(f"{where}: non-negative {'integer' if integer else 'number'} required")
    return value


def validate(payload: Any) -> dict[str, Any]:
    root = _closed(payload, ALLOWED_TOP, "root")
    if root.get("schema_version") != "1.0":
        raise EvaluationInputError("root.schema_version: must be '1.0'")
    run = _closed(root.get("run"), ALLOWED_RUN, "root.run")
    if not all(isinstance(run.get(k), str) and run[k] for k in ("system", "dataset")):
        raise EvaluationInputError("root.run: non-empty system and dataset required")
    if "seed" in run:
        _nonnegative(run["seed"], "root.run.seed", integer=True)
    pricing = _closed(root.get("pricing"), ALLOWED_PRICING, "root.pricing")
    for key in ALLOWED_PRICING:
        _nonnegative(pricing.get(key), f"root.pricing.{key}")
    cases = root.get("cases")
    if not isinstance(cases, list) or not cases:
        raise EvaluationInputError("root.cases: non-empty array required")
    seen: set[str] = set()
    for index, raw in enumerate(cases):
        where = f"root.cases[{index}]"
        case = _closed(raw, ALLOWED_CASE, where)
        missing = ALLOWED_CASE - set(case)
        if missing:
            raise EvaluationInputError(f"{where}: missing fields: {sorted(missing)}")
        cid = case["case_id"]
        if not isinstance(cid, str) or not cid or cid in seen:
            raise EvaluationInputError(f"{where}.case_id: non-empty unique string required")
        seen.add(cid)
        if case["stage"] not in STAGES or case["verifier"] not in VERIFIER:
            raise EvaluationInputError(f"{where}: invalid stage or verifier")
        if case["route_partition"] not in ROUTE_PARTITIONS or case["integrity_gate"] not in INTEGRITY_GATES:
            raise EvaluationInputError(f"{where}: invalid route_partition or integrity_gate")
        if not isinstance(case["evidence_required"], bool):
            raise EvaluationInputError(f"{where}.evidence_required: boolean required")
        ids = case["official_evidence_ids"]
        if not isinstance(ids, list) or any(not isinstance(x, str) or not x for x in ids) or len(ids) != len(set(ids)):
            raise EvaluationInputError(f"{where}.official_evidence_ids: unique non-empty strings required")
        if case["final_disposition"] not in ("accept", "reject", "abstain"):
            raise EvaluationInputError(f"{where}.final_disposition: invalid value")
        for key in ("baseline_llm_calls", "actual_llm_calls", "input_tokens", "output_tokens"):
            _nonnegative(case[key], f"{where}.{key}", integer=True)
        for key in ("latency_ms", "cost_usd"):
            _nonnegative(case[key], f"{where}.{key}")
        if case["actual_llm_calls"] > case["baseline_llm_calls"]:
            raise EvaluationInputError(f"{where}: actual_llm_calls exceeds baseline")
        if case["stage"] == "ai" and case["actual_llm_calls"] < 1:
            raise EvaluationInputError(f"{where}: ai stage requires an LLM call")
        if case["stage"] != "ai" and case["actual_llm_calls"] != 0:
            raise EvaluationInputError(f"{where}: only ai stage may call the LLM")
        if case["stage"] == "abstain" and case["final_disposition"] != "abstain":
            raise EvaluationInputError(f"{where}: abstain stage must abstain")
        if case["integrity_gate"] != "pass" and (
            case["route_partition"] != "unresolved" or case["final_disposition"] != "abstain"
        ):
            raise EvaluationInputError(f"{where}: integrity attack must route unresolved and abstain")
        if case["evidence_required"] and not ids and case["final_disposition"] != "abstain":
            raise EvaluationInputError(f"{where}: missing official evidence must abstain")
        if case["evidence_required"] and case["verifier"] != "pass" and case["final_disposition"] != "abstain":
            raise EvaluationInputError(f"{where}: unverified evidence must abstain")
    return root


def evaluate(payload: Any) -> dict[str, Any]:
    data = validate(payload)
    cases = data["cases"]
    n = len(cases)
    stages = Counter(row["stage"] for row in cases)
    partitions = Counter(row["route_partition"] for row in cases)
    gates = Counter(row["integrity_gate"] for row in cases)
    verifier = Counter(row["verifier"] for row in cases)
    evidence_cases = [row for row in cases if row["evidence_required"]]
    covered = sum(bool(row["official_evidence_ids"]) for row in evidence_cases)
    baseline_calls = sum(row["baseline_llm_calls"] for row in cases)
    actual_calls = sum(row["actual_llm_calls"] for row in cases)
    input_tokens = sum(row["input_tokens"] for row in cases)
    output_tokens = sum(row["output_tokens"] for row in cases)
    observed_cost = sum(float(row["cost_usd"]) for row in cases)
    pricing = data["pricing"]
    token_cost = (
        input_tokens * float(pricing["input_usd_per_million"])
        + output_tokens * float(pricing["output_usd_per_million"])
    ) / 1_000_000
    latencies = sorted(float(row["latency_ms"]) for row in cases)
    p95_index = max(0, (95 * n + 99) // 100 - 1)  # nearest-rank p95
    core = {
        "schema_version": "1.0",
        "run": data["run"],
        "case_count": n,
        "stage_distribution": {
            stage: {"count": stages[stage], "ratio": stages[stage] / n} for stage in STAGES
        },
        "universe_partition": {
            key: {"count": partitions[key], "ratio": partitions[key] / n} for key in ROUTE_PARTITIONS
        },
        "integrity_gate": {
            key: {"count": gates[key], "ratio": gates[key] / n} for key in INTEGRITY_GATES
        },
        "llm": {
            "baseline_calls": baseline_calls,
            "actual_calls": actual_calls,
            "calls_avoided": baseline_calls - actual_calls,
            "avoidance_ratio": (baseline_calls - actual_calls) / baseline_calls if baseline_calls else 0.0,
        },
        "evidence": {
            "required_cases": len(evidence_cases), "covered_cases": covered,
            "coverage": covered / len(evidence_cases) if evidence_cases else 1.0,
        },
        "verifier": {
            "pass": verifier["pass"], "fail": verifier["fail"],
            "not_applicable": verifier["not_applicable"],
            "pass_ratio_applicable": verifier["pass"] / (verifier["pass"] + verifier["fail"])
            if verifier["pass"] + verifier["fail"] else 1.0,
            "abstain_count": sum(row["final_disposition"] == "abstain" for row in cases),
            "abstain_ratio": sum(row["final_disposition"] == "abstain" for row in cases) / n,
        },
        "latency_ms": {"total": sum(latencies), "mean": sum(latencies) / n, "p95_nearest_rank": latencies[p95_index]},
        "cost": {"observed_usd": observed_cost, "token_estimated_usd": token_cost,
                 "input_tokens": input_tokens, "output_tokens": output_tokens, "pricing_snapshot": pricing},
    }
    canonical = json.dumps(core, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    core["result_sha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return core


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate a need-gated staged AI run")
    parser.add_argument("input", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()
    payload = json.loads(args.input.read_text(encoding="utf-8"))
    result = evaluate(payload)
    rendered = json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")


if __name__ == "__main__":
    main()
