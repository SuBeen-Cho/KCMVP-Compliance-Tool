"""Aggregate-only comparison of the sealed 41-candidate v1/v2 runs."""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
from typing import Any


class ComparisonError(ValueError):
    pass


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _ratio(n: int, d: int) -> float:
    return round(n / d, 8) if d else 0.0


def compare(v1: dict[str, Any], v2: dict[str, Any], *, input_sha256: dict[str, str]) -> dict[str, Any]:
    rows1, rows2 = v1.get("rows"), v2.get("rows")
    if not isinstance(rows1, list) or not isinstance(rows2, list) or len(rows1) != 41 or len(rows2) != 41:
        raise ComparisonError("both runs must contain exactly 41 private rows")
    required1 = {"candidate_id_sha256", "raw_label", "input_tokens", "output_tokens", "latency_ms"}
    required2 = required1 | {"verifier_passed", "verifier_reason", "verified_final"}
    if any(not required1 <= set(row) for row in rows1) or any(not required2 <= set(row) for row in rows2):
        raise ComparisonError("required private row fields are missing")
    hashes1 = [row["candidate_id_sha256"] for row in rows1]
    hashes2 = [row["candidate_id_sha256"] for row in rows2]
    if hashes1 != hashes2 or len(set(hashes1)) != 41:
        raise ComparisonError("ordered candidate universe differs")
    labels1 = [row["raw_label"] for row in rows1]
    labels2 = [row["raw_label"] for row in rows2]
    if any(not isinstance(x, str) for x in labels1 + labels2):
        raise ComparisonError("raw labels are required")
    transitions = Counter(zip(labels1, labels2))
    reasons = Counter(str(row.get("verifier_reason", "missing")) for row in rows2)
    verifier_pass = sum(bool(row.get("verifier_passed")) for row in rows2)
    final = [str(row["verified_final"]) for row in rows2]

    def telemetry(rows: list[dict[str, Any]]) -> dict[str, Any]:
        tin = sum(int(row.get("input_tokens") or 0) for row in rows)
        tout = sum(int(row.get("output_tokens") or 0) for row in rows)
        latency = sum(float(row.get("latency_ms") or 0) for row in rows)
        return {"calls": len(rows), "input_tokens": tin, "output_tokens": tout,
                "latency_ms_total": round(latency, 3), "latency_ms_mean": round(latency / len(rows), 3),
                "estimated_cost_usd": round((tin * 0.10 + tout * 0.40) / 1_000_000, 9)}

    t1, t2 = telemetry(rows1), telemetry(rows2)
    return {
        "schema_version": "1.0",
        "scope": "aggregate_same_41_v1_no_evidence_vs_v2_grounded",
        "claim_limit": "No independent GT; this is stability, verification, abstention, and resource comparison, not accuracy.",
        "input_sha256": dict(sorted(input_sha256.items())),
        "candidate_universe": {"count": 41, "ordered_identity_match": True},
        "raw_label_stability": {
            "exact_match_count": sum(a == b for a, b in zip(labels1, labels2)),
            "exact_match_ratio": _ratio(sum(a == b for a, b in zip(labels1, labels2)), 41),
            "v1_distribution": dict(sorted(Counter(labels1).items())),
            "v2_distribution": dict(sorted(Counter(labels2).items())),
            "transitions": {f"{a}->{b}": n for (a, b), n in sorted(transitions.items())},
        },
        "verifier": {
            "v1_final_comparison_status": "invalid_for_v2_final_comparison_legacy_verifier_semantics_not_reused",
            "v2_pass_count": verifier_pass, "v2_pass_ratio": _ratio(verifier_pass, 41),
            "v2_reason_distribution": dict(sorted(reasons.items())),
        },
        "v2_final_disposition": {
            "distribution": dict(sorted(Counter(final).items())),
            "abstention_count": sum(x == "abstain" for x in final),
            "abstention_ratio": _ratio(sum(x == "abstain" for x in final), 41),
        },
        "telemetry": {"v1": t1, "v2": t2,
                      "v2_minus_v1": {key: round(t2[key] - t1[key], 3) for key in
                                      ("input_tokens", "output_tokens", "latency_ms_total", "latency_ms_mean")}},
    }


def evaluate(v1_path: Path, v2_path: Path, v1_public_path: Path | None = None,
             v2_public_path: Path | None = None) -> dict[str, Any]:
    def load_jsonl(path: Path) -> dict[str, Any]:
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        grounded = [row for row in rows if row.get("condition") == "grounded"]
        selected, seen = [], set()
        for row in grounded:
            index = row.get("index")
            if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < 41:
                raise ComparisonError("ledger index is invalid")
            if index not in seen:
                selected.append(row); seen.add(index)
        selected.sort(key=lambda row: row["index"])
        return {"rows": selected}
    hashes = {"v1_private": _sha(v1_path), "v2_private": _sha(v2_path)}
    result = compare(load_jsonl(v1_path), load_jsonl(v2_path), input_sha256=hashes)
    if (v1_public_path is None) != (v2_public_path is None):
        raise ComparisonError("both public aggregate paths are required together")
    if v1_public_path and v2_public_path:
        publications = [json.loads(path.read_text(encoding="utf-8"))
                        for path in (v1_public_path, v2_public_path)]
        summaries = []
        for document in publications:
            execution = document.get("execution", {})
            if execution.get("unique_analyzed_request_count") != 82:
                raise ComparisonError("public paired request population differs")
            summaries.append({
                "analyzed_calls": 82,
                "input_tokens": sum(document["conditions"][c]["input_tokens"] for c in ("no_rag", "grounded")),
                "output_tokens": sum(document["conditions"][c]["output_tokens"] for c in ("no_rag", "grounded")),
                "estimated_cost_usd": round(sum(document["conditions"][c]["estimated_cost_usd"] for c in ("no_rag", "grounded")), 7),
                "duplicate_physical_requests": execution.get("duplicate_request_count"),
            })
        result["paired_resource_totals"] = {"v1": summaries[0], "v2": summaries[1]}
        result["input_sha256"].update({"v1_public": _sha(v1_public_path), "v2_public": _sha(v2_public_path)})
    return result
