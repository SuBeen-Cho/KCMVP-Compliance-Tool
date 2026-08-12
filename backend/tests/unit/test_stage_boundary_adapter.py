import json
from pathlib import Path

import pytest

from experiments.stage_boundary_adapter import BoundaryInputError, export


BACKEND = Path(__file__).resolve().parents[2]
FIXTURE = BACKEND / "evaluation" / "stage_boundary_candidate_fixtures.json"


def test_exports_real_l2_boundary_without_counting_deferred_ai_as_avoidance(tmp_path):
    result = export(json.loads(FIXTURE.read_text(encoding="utf-8")), tmp_path, BACKEND / "rules")
    rows = {row["case_id"]: row for row in result["cases"]}
    assert rows["literal-gcm-tag-10"]["stage"] == "deterministic"
    assert rows["ast-structural"]["stage"] == "deterministic"
    assert rows["semantic-retrieval"]["stage"] in {"retrieval", "abstain"}
    assert rows["semantic-retrieval"]["actual_llm_calls"] == 0
    assert rows["semantic-retrieval"]["baseline_llm_calls"] == 0
    assert rows["controlled-no-rag"]["stage"] == "abstain"
    assert rows["controlled-no-rag"]["verifier"] == "fail"
    assert all(row["actual_llm_calls"] == 0 for row in rows.values())


def test_fixture_contract_is_closed(tmp_path):
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    payload["cases"][0]["unknown"] = True
    with pytest.raises(BoundaryInputError):
        export(payload, tmp_path, BACKEND / "rules")


def test_restores_ablation_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("ABLATION_NO_RAG", "prior")
    export(json.loads(FIXTURE.read_text(encoding="utf-8")), tmp_path, BACKEND / "rules")
    assert __import__("os").environ["ABLATION_NO_RAG"] == "prior"
