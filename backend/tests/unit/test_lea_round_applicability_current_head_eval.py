import hashlib
import json
from pathlib import Path

import pytest

from experiments import lea_round_applicability_current_head_eval as target


def _inputs(tmp_path: Path, target_rules: list[str] | None = None) -> tuple[Path, Path]:
    target_rules = target_rules or []
    content = "void f(void) {}\n"
    snapshot = {
        "sources": [{"source_id": "opaque", "content": content,
                     "sha256": hashlib.sha256(content.encode()).hexdigest()}],
        "candidates": [],
    }
    ledger = tmp_path / "private.jsonl"
    lines = []
    for index in range(41):
        candidate_id = f"candidate-{index}"
        rule_id = target_rules[index] if index < len(target_rules) else "OTHER"
        snapshot["candidates"].append({
            "candidate_id": candidate_id,
            "payload": {"rule_id": rule_id, "source_id": "opaque"},
        })
        lines.append(json.dumps({
            "candidate_id_sha256": hashlib.sha256(candidate_id.encode()).hexdigest()
        }))
    snapshot_path = tmp_path / "snapshot.json"
    snapshot_path.write_text(json.dumps(snapshot), encoding="utf-8")
    ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return snapshot_path, ledger


def test_zero_target_occurrences_is_explicit(tmp_path):
    snapshot, ledger = _inputs(tmp_path)
    result = target.evaluate(snapshot, ledger)
    assert result["population"] == {"sealed_exact_ai_ready": 41, "target_occurrences": 0}
    assert set(result["target_rule_counts"].values()) == {0}
    assert set(result["coverage"].values()) == {0}
    assert result["reason"] == "no_target_occurrence_in_frozen_ai_ready41"
    assert result["api_calls"] == result["production_authorized"] == 0


def test_context_layers_are_not_invented(tmp_path):
    snapshot, ledger = _inputs(tmp_path, ["LEA-027"])
    result = target.evaluate(snapshot, ledger)
    assert result["coverage"] == {
        "complete_source_resolved": 1,
        "trusted_build_or_preprocessing_manifest": 0,
        "trusted_callsite_context": 0,
        "fully_applicability_provable": 0,
    }


def test_rejects_incomplete_membership(tmp_path):
    snapshot, ledger = _inputs(tmp_path)
    ledger.write_text(ledger.read_text().splitlines()[0] + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="membership_invalid"):
        target.evaluate(snapshot, ledger)


def test_rejects_duplicate_snapshot_candidate_substituted_for_missing_member(tmp_path):
    snapshot, ledger = _inputs(tmp_path)
    data = json.loads(snapshot.read_text())
    data["candidates"][-1] = dict(data["candidates"][0])
    snapshot.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="snapshot_join_incomplete"):
        target.evaluate(snapshot, ledger)
