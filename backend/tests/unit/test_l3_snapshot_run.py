import copy
import importlib.util
import json
from pathlib import Path

import pytest

from experiments.l1_snapshot import SnapshotError, build_snapshot
from app.services.llm.request_ledger import record_request


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "l3_snapshot_run.py"
SPEC = importlib.util.spec_from_file_location("l3_snapshot_run", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)

PROVENANCE = {
    "git_commit": "a" * 40,
    "workspace_sha256": "b" * 64,
    "rules_sha256": "c" * 64,
    "prompts_sha256": "d" * 64,
}


def _snapshot(tmp_path: Path):
    sources = tmp_path / "sources"
    (sources / "src").mkdir(parents=True)
    (sources / "src" / "a.c").write_text("int a(void) { return 0; }\n", encoding="utf-8")
    return build_snapshot(
        sources,
        [
            {
                "file": "src/a.c", "rule_id": "AES-001", "line": 1,
                "pattern_type": "ast", "severity": "high", "message": "first",
            },
            {
                "file": "src/a.c", "rule_id": "AES-002", "line": 1,
                "pattern_type": "ast", "severity": "high", "message": "second",
            },
        ],
        set_id="set-1", provenance=PROVENANCE,
    )


def test_rehydrates_one_condition_without_api_and_joins_ledger(tmp_path, monkeypatch):
    snapshot = _snapshot(tmp_path)
    ledger = tmp_path / "requests.jsonl"
    observed = {}

    def fake_rag(items):
        observed["rag_env"] = MODULE.os.environ["ABLATION_NO_RAG"]
        return [{**item, "rag_guideline_text": ""} for item in items]

    def fake_l3(*, preprocess_result, l1_violations, _rejected_tracker, _decision_records, **kwargs):
        observed["paths"] = [item["path"] for item in preprocess_result["files"]]
        observed["content"] = preprocess_result["files"][0]["content"]
        observed["ids"] = [item["candidate_id"] for item in l1_violations]
        record_request(
            candidate_ids=observed["ids"], phase="l3_batch", prompt="p", response="[]",
            attempt=1, status="response_received", input_tokens=1, output_tokens=1,
            provider="gemini", model="fake-model",
        )
        _decision_records.extend({
            "candidate_id": item["candidate_id"],
            "initial_violation_probability": 80,
            "rejudge_violation_probability": None,
            "score_provenance": "prompt_contract_confidence_proxy_not_calibrated_probability",
            "rejudge_applied": False,
            "decision": "retained",
        } for item in l1_violations)
        return [
            {"candidate_id": item["candidate_id"], "file": item["file"], "rule_id": item["rule_id"]}
            for item in l1_violations
        ]

    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    result = MODULE.run_condition(
        snapshot, no_rag=True, ledger_path=ledger,
        l3_runner=fake_l3, rag_runner=fake_rag,
    )
    assert observed["rag_env"] == "1"
    assert observed["paths"] == ["src/a.c"]
    assert "위반" not in observed["content"]
    assert observed["ids"] == result["selected_candidate_ids"]
    assert result["candidate_ids"] == snapshot["l3_candidate_ids"]
    assert result["l3_result_candidate_ids"] == observed["ids"]
    assert result["unresolved_candidate_ids"] == []
    assert result["snapshot_id"] == snapshot["snapshot_id"]
    assert result["request_ledger"]["record_count"] == 1
    assert result["request_covered_candidate_ids"] == observed["ids"]
    assert all(item["status"] == "retained" for item in result["candidate_dispositions"])
    assert len(result["l3_decision_records"]) == 2
    assert all(item["initial_violation_probability"] == 80 for item in result["l3_decision_records"])
    assert len(result["request_ledger"]["jsonl_sha256"]) == 64
    line = json.loads(ledger.read_text(encoding="utf-8"))
    assert line["snapshot_id"] == snapshot["snapshot_id"]
    assert line["run_id"] == result["run_id"]


def test_tampered_snapshot_fails_before_rag_or_l3(tmp_path):
    snapshot = copy.deepcopy(_snapshot(tmp_path))
    snapshot["sources"][0]["content"] = "tampered\n"
    called = {"rag": False, "l3": False}

    def fake_rag(items):
        called["rag"] = True
        return items

    def fake_l3(**kwargs):
        called["l3"] = True
        return []

    with pytest.raises(SnapshotError, match="source hash"):
        MODULE.run_condition(
            snapshot, no_rag=False, ledger_path=None,
            l3_runner=fake_l3, rag_runner=fake_rag,
        )
    assert called == {"rag": False, "l3": False}


def test_l2_identity_or_order_change_fails_fast(tmp_path):
    snapshot = _snapshot(tmp_path)

    def reversing_rag(items):
        return list(reversed(items))

    with pytest.raises(SnapshotError, match="L2 changed"):
        MODULE.run_condition(
            snapshot, no_rag=False, ledger_path=None,
            l3_runner=lambda **kwargs: [], rag_runner=reversing_rag,
        )


def test_l2_same_id_payload_mutation_fails_fast(tmp_path):
    snapshot = _snapshot(tmp_path)

    def mutating_rag(items):
        changed = [dict(item) for item in items]
        changed[0]["rule_id"] = "FORGED-001"
        return changed

    with pytest.raises(SnapshotError, match="immutable candidate payload"):
        MODULE.run_condition(
            snapshot, no_rag=False, ledger_path=None,
            l3_runner=lambda **kwargs: [], rag_runner=mutating_rag,
        )


def test_l2_in_place_payload_mutation_fails_fast(tmp_path):
    snapshot = _snapshot(tmp_path)

    def mutating_rag(items):
        items[0]["rule_id"] = "FORGED-001"
        return items

    with pytest.raises(SnapshotError, match="immutable candidate payload"):
        MODULE.run_condition(
            snapshot, no_rag=False, ledger_path=None,
            l3_runner=lambda **kwargs: [], rag_runner=mutating_rag,
        )


def test_occurrence_rejection_does_not_reject_sibling(tmp_path):
    snapshot = _snapshot(tmp_path)

    def fake_l3(*, l1_violations, _rejected_tracker, **kwargs):
        _rejected_tracker.add(l1_violations[0]["candidate_id"])
        return [{"candidate_id": l1_violations[1]["candidate_id"]}]

    result = MODULE.run_condition(
        snapshot, no_rag=True, ledger_path=None,
        l3_runner=fake_l3, rag_runner=lambda items: items,
    )
    assert result["rejected_candidate_ids"] == [result["selected_candidate_ids"][0]]
    assert result["l3_result_candidate_ids"] == [result["selected_candidate_ids"][1]]
    assert result["unresolved_candidate_ids"] == []


def test_main_writes_atomic_result_with_fake_l3(tmp_path, monkeypatch):
    snapshot = _snapshot(tmp_path)
    snapshot_path = tmp_path / "snapshot.json"
    snapshot_path.write_text(json.dumps(snapshot), encoding="utf-8")
    output = tmp_path / "result.json"
    ledger = tmp_path / "ledger.jsonl"

    monkeypatch.setattr(
        MODULE, "run_l3_contextualizer",
        lambda *, l1_violations, **kwargs: [
            {"candidate_id": item["candidate_id"]} for item in l1_violations
        ],
    )
    monkeypatch.setattr(MODULE, "run_l2_rag_context", lambda items: items)
    assert MODULE.main([
        str(snapshot_path), "--no-rag", "--ledger", str(ledger),
        "--output", str(output),
    ]) == 0
    result = json.loads(output.read_text(encoding="utf-8"))
    assert result["snapshot_id"] == snapshot["snapshot_id"]
    assert result["condition"] == {"no_rag": True}
    assert len(result["request_ledger"]["jsonl_sha256"]) == 64
    assert not list(tmp_path.glob(".result.json.*.tmp"))
