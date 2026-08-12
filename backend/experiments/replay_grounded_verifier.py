"""Replay grounded decisions through the current verifier without API calls."""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
from typing import Any

from app.services.rag_grounding import verify_citation_bound_decision
from experiments.grounded_ai_ready_eval import _sha, select_exact_ai_ready


class ReplayUnavailable(ValueError):
    pass


def replay(snapshot_path: Path, ledger_path: Path) -> dict[str, Any]:
    selected = select_exact_ai_ready(json.loads(snapshot_path.read_text(encoding="utf-8")))
    rows = [json.loads(line) for line in ledger_path.read_text(encoding="utf-8").splitlines() if line]
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
    outcomes = []
    for index, (_, candidate) in enumerate(selected):
        outcomes.append(verify_citation_bound_decision(candidate, unique[index]["decision"]))
    reasons = Counter(str(item["reason"]) for item in outcomes)
    result = {
        "schema_version": "1.0",
        "evaluation": "offline_grounded_verifier_replay",
        "api_calls": 0,
        "population": len(selected),
        "verifier_pass_count": sum(bool(item["verified"]) for item in outcomes),
        "verifier_reasons": dict(sorted(reasons.items())),
        "snapshot_sha256": hashlib.sha256(snapshot_path.read_bytes()).hexdigest(),
        "private_ledger_sha256": hashlib.sha256(ledger_path.read_bytes()).hexdigest(),
        "verifier_source_sha256": hashlib.sha256(
            (Path(__file__).resolve().parents[1] / "app/services/rag_grounding.py").read_bytes()
        ).hexdigest(),
        "claim_limit": "Verifier replay only; no independent ground truth or accuracy claim.",
    }
    result["result_sha256"] = _sha(result)
    return result
