import json

import pytest

from experiments.grounded_ai_ready_eval import _canonicalize, _exclusive_run, build_prompt
from experiments.replay_grounded_verifier import ReplayUnavailable, replay


def test_prompt_pair_differs_only_by_evidence_block():
    candidate = {"rule_id": "CTR-001", "pattern_type": "missing", "scope": "project",
                 "detection_semantics": "required_absence", "snippet": "opaque code"}
    unit = {"unit_id": "u1", "source_id": "s1", "locator": {"page": 1}, "span": "official"}
    empty = build_prompt(candidate, [])
    grounded = build_prompt(candidate, [unit])
    assert empty.split("official_evidence=", 1)[0] == grounded.split("official_evidence=", 1)[0]
    assert json.loads(empty.split("official_evidence=", 1)[1]) == []


def test_canonicalize_resolves_only_known_ids_to_immutable_spans():
    decision = {"evidence_unit_ids": ["u1"], "supporting_spans": ["invented"]}
    value, ok = _canonicalize(decision, [{"unit_id": "u1", "span": "exact official span"}])
    assert ok is True
    assert value["supporting_spans"] == ["exact official span"]
    _, unknown = _canonicalize({"evidence_unit_ids": ["bad"]}, [{"unit_id": "u1", "span": "x"}])
    assert unknown is False


def test_replay_rejects_label_only_legacy_ledger(tmp_path, monkeypatch):
    snapshot = tmp_path / "snapshot.json"
    snapshot.write_text("{}", encoding="utf-8")
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text(json.dumps({"index": 0, "condition": "grounded", "raw_label": "abstain"}) + "\n")
    monkeypatch.setattr("experiments.replay_grounded_verifier.select_exact_ai_ready", lambda _snapshot: [("c", {})])
    with pytest.raises(ReplayUnavailable, match="exact 82-slot"):
        replay(snapshot, ledger)


def test_exact_once_lock_rejects_nonempty_ledger_and_existing_lock(tmp_path):
    ledger = tmp_path / "private.jsonl"
    ledger.write_text("occupied\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="new empty ledger"):
        with _exclusive_run(ledger):
            pass
    ledger.write_text("", encoding="utf-8")
    lock = ledger.with_suffix(ledger.suffix + ".lock")
    lock.write_text("active", encoding="utf-8")
    with pytest.raises(RuntimeError, match="run lock"):
        with _exclusive_run(ledger):
            pass


def test_replay_rejects_incomplete_paired_ledger_before_verification(tmp_path, monkeypatch):
    snapshot = tmp_path / "snapshot.json"
    snapshot.write_text("{}", encoding="utf-8")
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text(json.dumps({"index": 0, "condition": "grounded", "run_id": "r"}) + "\n")
    monkeypatch.setattr("experiments.replay_grounded_verifier.select_exact_ai_ready", lambda _snapshot: [("c", {})])
    with pytest.raises(ReplayUnavailable, match="exact 82-slot"):
        replay(snapshot, ledger)
