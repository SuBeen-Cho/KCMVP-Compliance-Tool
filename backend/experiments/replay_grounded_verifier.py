"""Replay grounded decisions through the current verifier without API calls."""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
from typing import Any
import argparse

from app.services.rag_grounding import verify_citation_bound_decision
from experiments.grounded_ai_ready_eval import _sha, select_exact_ai_ready


class ReplayUnavailable(ValueError):
    pass


def replay(snapshot_path: Path, ledger_path: Path) -> dict[str, Any]:
    selected = select_exact_ai_ready(json.loads(snapshot_path.read_text(encoding="utf-8")))
    rows = [json.loads(line) for line in ledger_path.read_text(encoding="utf-8").splitlines() if line]
    if len(rows) != 82 or len({(int(r["index"]), r["condition"]) for r in rows}) != 82:
        raise ReplayUnavailable("ledger is not an exact 82-slot paired execution")
    run_ids = {row.get("run_id") for row in rows}
    if len(run_ids) != 1 or None in run_ids:
        raise ReplayUnavailable("ledger rows do not share one sealed run ID")
    unique: dict[int, dict[str, Any]] = {}
    for row in rows:
        if row.get("condition") == "grounded":
            unique.setdefault(int(row["index"]), row)
    if set(unique) != set(range(len(selected))):
        raise ReplayUnavailable("grounded ledger does not cover the sealed universe")
    if any(not isinstance(row.get("decision"), dict) for row in unique.values()):
        raise ReplayUnavailable(
            "ledger lacks canonical decisions; response hashes and labels cannot reconstruct citations"
        )
    for index, (candidate_id, candidate) in enumerate(selected):
        expected_payload = _sha({k: v for k, v in candidate.items() if k not in
                                 {"rag_evidence_bundle", "rag_guideline_text", "rag_route"}})
        expected_binding = _sha({"candidate_id": candidate_id, "payload": candidate})
        for condition in ("no_rag", "grounded"):
            row = next(r for r in rows if int(r["index"]) == index and r["condition"] == condition)
            if row.get("candidate_payload_sha256") != expected_payload or row.get("envelope_binding_sha256") != expected_binding:
                raise ReplayUnavailable("ledger candidate binding differs from the live sealed universe")
        pair = [r for r in rows if int(r["index"]) == index]
        if len({r.get("prompt_core_sha256") for r in pair}) != 1:
            raise ReplayUnavailable("paired prompt cores differ")
    outcomes = []
    for index, (_, candidate) in enumerate(selected):
        outcome = verify_citation_bound_decision(candidate, unique[index]["decision"])
        row = unique[index]
        expected_final = row["raw_label"] if bool(outcome["verified"]) else "abstain"
        if (bool(outcome["verified"]) != bool(row.get("verifier_passed"))
                or str(outcome["reason"]) != str(row.get("verifier_reason"))
                or expected_final != row.get("verified_final")):
            raise ReplayUnavailable(f"stored verifier result differs from live replay at index {index}")
        outcomes.append(outcome)
    reasons = Counter(str(item["reason"]) for item in outcomes)
    backend = Path(__file__).resolve().parents[1]
    runner_sha = hashlib.sha256((backend / "experiments/grounded_ai_ready_eval.py").read_bytes()).hexdigest()
    mapping_sha = hashlib.sha256((backend / "mapping/rule_evidence_audit.json").read_bytes()).hexdigest()
    index_sha = hashlib.sha256((backend / "data/evidence/official_units.local.json").read_bytes()).hexdigest()
    spec = {"model": rows[0].get("model"), "prompt_version": rows[0].get("prompt_version"),
            "generation_config": {"response_mime_type": "application/json", "temperature": 0,
                                  "max_output_tokens": 1024, "thinking_budget": 0},
            "runner_sha256": runner_sha, "mapping_sha256": mapping_sha,
            "official_index_sha256": index_sha}
    result = {
        "schema_version": "1.0",
        "evaluation": "offline_grounded_verifier_replay",
        "api_calls": 0,
        "population": len(selected),
        "verifier_pass_count": sum(bool(item["verified"]) for item in outcomes),
        "verifier_reasons": dict(sorted(reasons.items())),
        "snapshot_sha256": hashlib.sha256(snapshot_path.read_bytes()).hexdigest(),
        "private_ledger_sha256": hashlib.sha256(ledger_path.read_bytes()).hexdigest(),
        "run_instance_sha256": _sha(next(iter(run_ids)).encode()),
        "experiment_spec_sha256": _sha(spec),
        "mapping_sha256": mapping_sha,
        "official_index_sha256": index_sha,
        "runner_sha256": runner_sha,
        "verifier_source_sha256": hashlib.sha256(
            (Path(__file__).resolve().parents[1] / "app/services/rag_grounding.py").read_bytes()
        ).hexdigest(),
        "claim_limit": "Verifier replay only; no independent ground truth or accuracy claim.",
    }
    result["result_sha256"] = _sha(result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("ledger", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = replay(args.snapshot, args.ledger)
    args.output.write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
