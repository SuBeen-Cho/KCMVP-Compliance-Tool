"""Opt-in, isolated no-evidence comparator for the current AI-ready universe.

This is not an operational no-RAG mode. It directly calls Gemini outside the
production stage contract and never reads grounded-condition outputs.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
from collections import Counter
from pathlib import Path
import tempfile
import time
from typing import Any

from app.services.llm.candidate_selector import _select_l3_candidates
from app.services.rag_service import run_l2_rag_context
from experiments.full_stage_boundary_benchmark import load_candidates

MODEL = "gemini-2.5-flash-lite"
PROMPT_VERSION = "need-gated-41-comparator-v1"
LABELS = {"violation", "non_violation", "insufficient_context", "not_applicable"}
INPUT_USD_PER_MILLION = 0.10
OUTPUT_USD_PER_MILLION = 0.40


class ComparatorError(ValueError):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _sha(value: Any) -> str:
    return hashlib.sha256(value if isinstance(value, bytes) else _canonical(value)).hexdigest()


def build_prompt(candidate: dict[str, Any], *, evidence_block: str = "") -> str:
    """Shared prompt shape: conditions differ only in the final evidence block."""
    core = {
        "rule_id": candidate.get("rule_id"), "pattern_type": candidate.get("pattern_type"),
        "message": candidate.get("message"), "snippet": candidate.get("snippet"),
        "detection_semantics": candidate.get("detection_semantics"),
        "scope": candidate.get("scope"), "project_artifact_evidence": candidate.get("project_artifact_evidence"),
    }
    return (
        "Act as a conservative KCMVP code-review adjudicator. Judge only the supplied candidate.\n"
        "Return JSON only with exactly: label (violation|non_violation|insufficient_context|not_applicable), "
        "confidence (integer 0..100), rationale (max 240 chars). Do not invent missing code or requirements.\n"
        f"candidate={json.dumps(core, ensure_ascii=False, sort_keys=True)}\n"
        f"official_evidence={evidence_block}"
    )


def select_ai_ready(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    candidates = load_candidates(snapshot)
    with contextlib.redirect_stdout(io.StringIO()):
        routed = run_l2_rag_context(candidates)
        selected = {id(row) for row in _select_l3_candidates(routed)}
    result = [row for row in routed if row.get("disposition") == "ai_required"
              and row.get("ai_need") == "required" and id(row) in selected]
    return result


def _atomic_private(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, sort_keys=True, indent=2)
            handle.write("\n")
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    except Exception:
        try: os.unlink(temporary)
        except FileNotFoundError: pass
        raise


def run(client: Any, snapshot_path: Path, private_output: Path, public_output: Path) -> dict[str, Any]:
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    selected = select_ai_ready(snapshot)
    if len(selected) != 41:
        raise ComparatorError(f"expected sealed AI-ready universe of 41, got {len(selected)}")
    candidate_hashes = [_sha({k: v for k, v in row.items() if k not in
                              {"rag_evidence_bundle", "rag_guideline_text", "rag_route"}})
                        for row in selected]
    if len(set(candidate_hashes)) != 41:
        raise ComparatorError("candidate hashes are not unique")
    rows = []
    for sequence, (candidate, candidate_hash) in enumerate(zip(selected, candidate_hashes, strict=True), 1):
        prompt = build_prompt(candidate, evidence_block="")
        started = time.monotonic()
        response = client.models.generate_content(
            model=MODEL, contents=prompt,
            config={"response_mime_type": "application/json", "temperature": 0,
                    "max_output_tokens": 512, "thinking_config": {"thinking_budget": 0}},
        )
        latency = round((time.monotonic() - started) * 1000, 3)
        decision = json.loads(response.text)
        if set(decision) != {"label", "confidence", "rationale"} or decision["label"] not in LABELS:
            raise ComparatorError("provider response violates closed schema")
        if isinstance(decision["confidence"], bool) or not isinstance(decision["confidence"], int) or not 0 <= decision["confidence"] <= 100:
            raise ComparatorError("provider confidence violates closed schema")
        usage = getattr(response, "usage_metadata", None)
        rows.append({"sequence": sequence, "candidate_sha256": candidate_hash,
                     "prompt_sha256": _sha(prompt.encode()), "response_sha256": _sha(response.text.encode()),
                     "label": decision["label"], "confidence": decision["confidence"],
                     "rationale": decision["rationale"], "latency_ms": latency,
                     "input_tokens": int(getattr(usage, "prompt_token_count", 0) or 0),
                     "output_tokens": int(getattr(usage, "candidates_token_count", 0) or 0)})
    _atomic_private(private_output, {"schema_version": "1.0", "condition": "no_evidence",
                                     "model": MODEL, "prompt_version": PROMPT_VERSION, "rows": rows})
    labels = Counter(row["label"] for row in rows)
    tin, tout = sum(r["input_tokens"] for r in rows), sum(r["output_tokens"] for r in rows)
    public = {
        "schema_version": "1.0", "scope": "isolated_no_evidence_comparator_not_production",
        "claim_limit": "No independent GT; labels are distributions only and must not be reported as accuracy.",
        "condition": "no_evidence", "model": MODEL, "temperature": 0,
        "prompt_version": PROMPT_VERSION, "snapshot_sha256": hashlib.sha256(snapshot_path.read_bytes()).hexdigest(),
        "candidate_universe": {"count": 41, "ordered_hashes_sha256": _sha(candidate_hashes)},
        "evidence_policy": "all grounded fields removed; official_evidence block is empty",
        "provider_calls": len(rows), "label_distribution": dict(sorted(labels.items())),
        "tokens": {"input": tin, "output": tout},
        "latency_ms": {"total": round(sum(r["latency_ms"] for r in rows), 3),
                       "mean": round(sum(r["latency_ms"] for r in rows) / len(rows), 3)},
        "pricing": {"input_usd_per_million": INPUT_USD_PER_MILLION,
                    "output_usd_per_million": OUTPUT_USD_PER_MILLION,
                    "status": "estimate_not_invoice"},
        "estimated_cost_usd": round((tin * INPUT_USD_PER_MILLION + tout * OUTPUT_USD_PER_MILLION) / 1_000_000, 9),
        "private_ledger_sha256": hashlib.sha256(private_output.read_bytes()).hexdigest(),
    }
    public_output.write_text(json.dumps(public, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return public


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path); parser.add_argument("--private-output", type=Path, required=True)
    parser.add_argument("--public-output", type=Path, required=True); parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    if not args.execute: raise SystemExit("refusing paid calls without --execute")
    from app.config import settings
    if not settings.GOOGLE_API_KEY: raise SystemExit("GOOGLE_API_KEY is not configured")
    from google import genai
    run(genai.Client(api_key=settings.GOOGLE_API_KEY), args.snapshot, args.private_output, args.public_output)


if __name__ == "__main__": main()
