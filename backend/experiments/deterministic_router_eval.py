"""Offline cost/latency projection for verified literal routing."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import time

from app.services.rag_service import run_l2_rag_context


LITERALS = {
    "GCM-002": "gcm_tag_len_bytes = 10",
    "CCM-003": "ccm_tag_len_bytes = 12",
    "CMAC-004": "lea_cmac_tag_bits = 64",
}


def candidate(rule_id: str, span: str) -> dict:
    return {
        "rule_id": rule_id, "file": "neutral.c", "line": 1,
        "pattern_type": "regex", "detection_semantics": "prohibited_presence",
        "confidence": "확정", "needs_ai_review": False, "snippet": span,
        "deterministic_literal_evidence": {
            "scanner_id": "kcmvp_explicit_tag_literal_v1", "matched_span": span,
            "matched_span_sha256": hashlib.sha256(span.encode()).hexdigest(),
        },
    }


def evaluate(baseline_path: Path) -> dict:
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))["metrics"]["no_rag"]
    started = time.perf_counter()
    rows = run_l2_rag_context([candidate(rid, span) for rid, span in LITERALS.items()])
    elapsed_ms = (time.perf_counter() - started) * 1000
    assert all((row.get("rag_route") or {}).get("decision") == "deterministic_verified_rule" for row in rows)
    n = len(rows)
    created_at = datetime.now(timezone.utc).isoformat()
    backend = Path(__file__).resolve().parents[1]
    provenance = {
        "provenance_capture": "at_execution",
        "runner_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "official_evidence_index_sha256": hashlib.sha256((backend / "data/evidence/official_units.local.json").read_bytes()).hexdigest(),
        "rule_evidence_audit_sha256": hashlib.sha256((backend / "mapping/rule_evidence_audit.json").read_bytes()).hexdigest(),
        "api_calls": 0, "measurement_repetitions": 1,
    }
    core = {
        "schema_version": "1.1", "created_at": created_at,
        "baseline_result_sha256": hashlib.sha256(baseline_path.read_bytes()).hexdigest(),
        "candidate_count": n, "llm_calls_avoided": sum(row["llm_calls_avoided"] for row in rows),
        "router_and_provenance_latency_ms": round(elapsed_ms, 3),
        "official_unit_counts": {row["rule_id"]: len(row["official_evidence_provenance"]) for row in rows},
        "projected_no_llm_savings": {
            "input_tokens": round(baseline["input_tokens"] / baseline["n"] * n),
            "output_tokens": round(baseline["output_tokens"] / baseline["n"] * n),
            "sequential_latency_ms": round(baseline["mean_latency_ms"] * n, 3),
            "estimated_cost_usd": round(baseline["estimated_cost_usd"] / baseline["n"] * n, 9),
        },
        "decision_source": "deterministic_l1_official_evidence",
        "claim_scope": "projection_from_v5_no_rag_observed_mean_not_new_api_calls",
        "run_provenance": provenance,
    }
    core["run_id"] = hashlib.sha256(json.dumps(core, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return core


if __name__ == "__main__":
    root = Path(__file__).resolve().parent
    result = evaluate(root / "grounded_rag_llm_eval_result.json")
    (root / "deterministic_router_eval_result.json").write_text(
        json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
