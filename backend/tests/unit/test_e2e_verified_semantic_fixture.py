import shutil

import pytest

from experiments.e2e_verified_semantic_fixture import evaluate_once, run_benchmark


pytestmark = pytest.mark.skipif(shutil.which("clang") is None, reason="clang unavailable")


def test_sealed_fixture_reaches_both_structural_proofs_without_authorization():
    result = evaluate_once()
    assert result["preprocessing_binding"] is True
    assert result["reaching_definition_structural_complete"] is True
    assert result["lea001_structural_complete"] is True
    assert result["lea001_rhs_coverage"] == {
        "covered": 16, "total": 16, "structural_complete": True}
    assert result["exact_rhs_ast_coverage"] == {"covered": 2, "total": 2}
    assert all(result["mutation_attacks_blocked"].values())
    assert result["semantic_authorization"] == 0
    assert result["api_calls"] == 0


def test_benchmark_is_repeatable_and_keeps_semantic_gate_closed():
    report = run_benchmark(warm_runs=1)
    assert report["repeat_invariant"] is True
    assert report["result"]["semantic_authorization"] == 0
    assert report["latency_ms"]["cold"] > 0
    assert report["latency_ms"]["warm_mean"] > 0
