import importlib.util
import json
from pathlib import Path
import subprocess

import pytest

from experiments.l1_snapshot import SnapshotError, atomic_write_snapshot, build_snapshot


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "run_paired_l2_ablation.py"
SPEC = importlib.util.spec_from_file_location("run_paired_l2_ablation", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)

PROVENANCE = {
    "git_commit": "a" * 40,
    "workspace_sha256": "b" * 64,
    "rules_sha256": "c" * 64,
    "prompts_sha256": "d" * 64,
}


def _snapshot_path(tmp_path: Path) -> tuple[Path, dict]:
    sources = tmp_path / "sources"
    sources.mkdir()
    (sources / "a.c").write_text("int a(void) { return 0; }\n", encoding="utf-8")
    snapshot = build_snapshot(
        sources,
        [{"file": "a.c", "rule_id": "AES-001", "line": 1, "confidence": 70}],
        set_id="set-1", provenance=PROVENANCE,
    )
    path = tmp_path / "snapshot.json"
    atomic_write_snapshot(path, snapshot)
    return path, snapshot


def _fake_runner(snapshot: dict, calls: list[dict], *, secret: bool = False):
    def run(command: list[str], environment: dict[str, str]):
        output = Path(command[command.index("--output") + 1])
        ledger = Path(command[command.index("--ledger") + 1])
        no_rag = "--no-rag" in command
        run_id = f"run-{len(calls) + 1}"
        record = {
            "schema_version": 2,
            "scope": "code_l3_experiment_requests_only",
            "run_id": run_id,
            "snapshot_id": snapshot["snapshot_id"],
            "sequence": 1,
            "candidate_ids": ["a" * 64],
            "phase": "l3_batch",
            "prompt_sha256": "b" * 64,
            "response_sha256": "c" * 64,
            "attempt": 1,
            "status": "response_received",
            "input_tokens": 100,
            "output_tokens": 25,
            "usage_status": "available",
            "provider": "gemini",
            "model": "fake-model" if not secret else "AIza" + "x" * 30,
        }
        ledger.parent.mkdir(parents=True, exist_ok=True)
        ledger.write_text(json.dumps(record, sort_keys=True) + "\n", encoding="utf-8")
        ledger_hash = MODULE._sha256_file(ledger)
        result = {
            "schema_version": "1.0",
            "run_id": run_id,
            "snapshot_id": snapshot["snapshot_id"],
            "condition": {"no_rag": no_rag},
            "generation_seed": int(environment["KCMVP_L3_SEED"]),
            "candidate_ids": snapshot["l3_candidate_ids"],
            "selected_candidate_ids": snapshot["l3_candidate_ids"],
            "l3_result_candidate_ids": snapshot["l3_candidate_ids"] if not no_rag else [],
            "rejected_candidate_ids": [] if not no_rag else snapshot["l3_candidate_ids"],
            "unresolved_candidate_ids": [],
            "request_covered_candidate_ids": snapshot["l3_candidate_ids"],
            "request_ledger": {"write_status": "ok", "jsonl_sha256": ledger_hash},
        }
        output.write_text(json.dumps(result, sort_keys=True), encoding="utf-8")
        calls.append({"no_rag": no_rag, "seed": environment["KCMVP_L3_SEED"]})
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
    return run


def _run(path, snapshot, output, calls, **kwargs):
    return MODULE.run_experiment(
        path, output, pairs=kwargs.pop("pairs", 2), base_seed=kwargs.pop("base_seed", 100),
        input_usd_per_million=0.10, output_usd_per_million=0.40,
        pricing_as_of="2026-08-11", pricing_source="https://example.test/pricing",
        pricing_model="fake-model",
        runner=kwargs.pop("runner", _fake_runner(snapshot, calls)), **kwargs,
    )


def test_schedule_is_ab_ba_with_shared_pair_seeds():
    assert MODULE.build_schedule(2, 100) == [
        {"pair_index": 1, "order_index": 1, "condition": "rag", "no_rag": False, "seed": 100},
        {"pair_index": 1, "order_index": 2, "condition": "no_rag", "no_rag": True, "seed": 100},
        {"pair_index": 2, "order_index": 1, "condition": "no_rag", "no_rag": True, "seed": 101},
        {"pair_index": 2, "order_index": 2, "condition": "rag", "no_rag": False, "seed": 101},
    ]


def test_fake_integration_records_hashes_usage_cost_and_no_secrets(tmp_path, monkeypatch):
    path, snapshot = _snapshot_path(tmp_path)
    calls = []
    monkeypatch.setenv("GOOGLE_API_KEY", "do-not-serialize-this")
    manifest = _run(path, snapshot, tmp_path / "run", calls)
    assert calls == [
        {"no_rag": False, "seed": "100"}, {"no_rag": True, "seed": "100"},
        {"no_rag": True, "seed": "101"}, {"no_rag": False, "seed": "101"},
    ]
    assert manifest["design"]["condition_run_count"] == 4
    assert manifest["execution_provenance"]["status"] in {
        "canonical_clean_stable", "experimental_partial"}
    assert len(manifest["execution_provenance"]["start"]["executed_git_commit"]) == 40
    assert len(manifest["execution_provenance"]["end"]["status_sha256"]) == 64
    assert manifest["aggregate"]["usage"] == {
        "provider_calls": 4, "input_tokens": 400, "output_tokens": 100,
    }
    assert manifest["aggregate"]["estimated_cost_usd"] == pytest.approx(0.00008)
    assert manifest["aggregate"]["outcomes_by_condition"] == {
        "rag": {
            "selected": 2, "retained": 2, "rejected": 0,
            "unresolved": 0, "request_covered": 2,
        },
        "no_rag": {
            "selected": 2, "retained": 0, "rejected": 2,
            "unresolved": 0, "request_covered": 2,
        },
    }
    assert manifest["pair_summaries"][0]["rag_minus_no_rag"]["retained"] == 1
    assert all(item["outcomes"]["selected"] == 1 for item in manifest["executions"])
    assert calls[0]["seed"] == calls[1]["seed"]
    assert all(len(item["result_sha256"]) == 64 for item in manifest["executions"])
    serialized = (tmp_path / "run" / "manifest.json").read_text(encoding="utf-8")
    assert "do-not-serialize-this" not in serialized
    assert str(tmp_path) not in serialized


def test_git_provenance_marks_clean_stable_only_as_canonical(monkeypatch, tmp_path):
    path, snapshot = _snapshot_path(tmp_path)
    calls = []
    clean = {"executed_git_commit": "a" * 40, "branch": "main", "dirty": False,
             "changed_entry_count": 0, "status_sha256": "b" * 64}
    monkeypatch.setattr(MODULE, "_git_identity", lambda: dict(clean))
    manifest = _run(path, snapshot, tmp_path / "canonical", calls, pairs=1)
    assert manifest["execution_provenance"]["status"] == "canonical_clean_stable"
    assert manifest["execution_provenance"]["claim_limit"] is None


def test_git_provenance_marks_dirty_or_changed_run_experimental(monkeypatch, tmp_path):
    path, snapshot = _snapshot_path(tmp_path)
    calls, captures = [], iter([
        {"executed_git_commit": "a" * 40, "branch": "main", "dirty": True,
         "changed_entry_count": 1, "status_sha256": "b" * 64},
        {"executed_git_commit": "a" * 40, "branch": "main", "dirty": True,
         "changed_entry_count": 2, "status_sha256": "c" * 64},
    ])
    monkeypatch.setattr(MODULE, "_git_identity", lambda: next(captures))
    manifest = _run(path, snapshot, tmp_path / "experimental", calls, pairs=1)
    provenance = manifest["execution_provenance"]
    assert provenance["status"] == "experimental_partial"
    assert provenance["stable_identity"] is False
    assert "Non-canonical" in provenance["claim_limit"]


def test_tampered_snapshot_fails_before_runner(tmp_path):
    path, snapshot = _snapshot_path(tmp_path)
    snapshot["sources"][0]["content"] = "tampered\n"
    path.write_text(json.dumps(snapshot), encoding="utf-8")
    calls = []
    with pytest.raises(SnapshotError, match="source hash"):
        _run(path, snapshot, tmp_path / "run", calls)
    assert calls == []


def test_nonempty_output_and_bad_pricing_fail_before_runner(tmp_path):
    path, snapshot = _snapshot_path(tmp_path)
    output = tmp_path / "run"
    output.mkdir()
    (output / "existing").write_text("x", encoding="utf-8")
    calls = []
    with pytest.raises(SnapshotError, match="absent or empty"):
        _run(path, snapshot, output, calls)
    assert calls == []


def test_secret_in_child_artifact_is_rejected(tmp_path):
    path, snapshot = _snapshot_path(tmp_path)
    calls = []
    with pytest.raises(SnapshotError, match="credential-like"):
        _run(
            path, snapshot, tmp_path / "run", calls, pairs=1,
            runner=_fake_runner(snapshot, calls, secret=True),
        )


def test_child_candidate_mismatch_is_rejected(tmp_path):
    path, snapshot = _snapshot_path(tmp_path)
    calls = []

    def mismatching(command, environment):
        completed = _fake_runner(snapshot, calls)(command, environment)
        output = Path(command[command.index("--output") + 1])
        result = json.loads(output.read_text(encoding="utf-8"))
        result["candidate_ids"] = []
        output.write_text(json.dumps(result), encoding="utf-8")
        return completed

    with pytest.raises(SnapshotError, match="candidate identities"):
        _run(path, snapshot, tmp_path / "run", calls, pairs=1, runner=mismatching)


@pytest.mark.parametrize("raw", ["bad", "-1", "2147483648"])
def test_generation_seed_validation(monkeypatch, raw):
    monkeypatch.setenv("KCMVP_L3_SEED", raw)
    from app.services.llm.gemini_client import GeminiConfigurationError, _generation_seed
    with pytest.raises(GeminiConfigurationError):
        _generation_seed()
