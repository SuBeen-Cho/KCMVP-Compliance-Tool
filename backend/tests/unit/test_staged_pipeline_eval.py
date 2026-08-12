import copy

import pytest

from experiments.staged_pipeline_eval import EvaluationInputError, evaluate


def observations():
    common = {"baseline_llm_calls": 1, "input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0}
    return {
        "schema_version": "1.0",
        "run": {"system": "candidate", "dataset": "frozen-v1", "seed": 7},
        "pricing": {"input_usd_per_million": 1.0, "output_usd_per_million": 2.0},
        "cases": [
            {**common, "case_id": "d", "stage": "deterministic", "route_partition": "selected_deterministic", "integrity_gate": "pass", "evidence_required": False,
             "official_evidence_ids": [], "verifier": "not_applicable", "final_disposition": "reject",
             "actual_llm_calls": 0, "latency_ms": 1.0},
            {**common, "case_id": "r", "stage": "retrieval", "route_partition": "selected_retrieve", "integrity_gate": "pass", "evidence_required": True,
             "official_evidence_ids": ["official:1"], "verifier": "pass", "final_disposition": "accept",
             "actual_llm_calls": 0, "latency_ms": 3.0},
            {**common, "case_id": "a", "stage": "ai", "route_partition": "skip", "integrity_gate": "pass", "evidence_required": True,
             "official_evidence_ids": ["official:2"], "verifier": "pass", "final_disposition": "accept",
             "actual_llm_calls": 1, "input_tokens": 100, "output_tokens": 10, "cost_usd": 0.00012,
             "latency_ms": 10.0},
            {**common, "case_id": "x", "stage": "abstain", "route_partition": "unresolved", "integrity_gate": "route_missing", "evidence_required": True,
             "official_evidence_ids": [], "verifier": "fail", "final_disposition": "abstain",
             "actual_llm_calls": 0, "latency_ms": 2.0},
        ],
    }


def test_aggregates_stage_evidence_verifier_latency_and_cost():
    result = evaluate(observations())
    assert result["stage_distribution"]["ai"] == {"count": 1, "ratio": 0.25}
    assert sum(x["count"] for x in result["universe_partition"].values()) == 4
    assert result["integrity_gate"]["route_missing"]["count"] == 1
    assert result["llm"] == {"baseline_calls": 4, "actual_calls": 1, "calls_avoided": 3, "avoidance_ratio": 0.75}
    assert result["evidence"] == {"required_cases": 3, "covered_cases": 2, "coverage": 2 / 3}
    assert result["verifier"]["pass_ratio_applicable"] == 2 / 3
    assert result["verifier"]["abstain_ratio"] == 0.25
    assert result["latency_ms"] == {"total": 16.0, "mean": 4.0, "p95_nearest_rank": 10.0}
    assert result["cost"]["token_estimated_usd"] == pytest.approx(0.00012)
    assert len(result["result_sha256"]) == 64


def test_result_hash_is_deterministic():
    assert evaluate(observations())["result_sha256"] == evaluate(observations())["result_sha256"]


@pytest.mark.parametrize("mutation", ["unknown", "ai_without_call", "unsupported_accept", "duplicate", "attack_escape"])
def test_rejects_non_closed_or_fail_open_observations(mutation):
    data = observations()
    if mutation == "unknown":
        data["cases"][0]["surprise"] = True
    elif mutation == "ai_without_call":
        data["cases"][2]["actual_llm_calls"] = 0
    elif mutation == "unsupported_accept":
        data["cases"][3]["stage"] = "retrieval"
        data["cases"][3]["final_disposition"] = "accept"
    elif mutation == "duplicate":
        data["cases"][1]["case_id"] = data["cases"][0]["case_id"]
    else:
        data["cases"][0]["integrity_gate"] = "forged"
    with pytest.raises(EvaluationInputError):
        evaluate(data)


def test_does_not_mutate_observations():
    data = observations()
    before = copy.deepcopy(data)
    evaluate(data)
    assert data == before
