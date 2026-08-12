from experiments.lea_round_shadow_chain_benchmark import _capture, GOOD, run_benchmark


def test_all_three_structural_stages_pass_but_semantics_remain_unknown():
    result = _capture(GOOD)
    assert result["stages"] == {"official_evidence": True,
                                "operation_graph": True,
                                "direct_array_callsite": True,
                                "same_preprocessed_occurrence": True}
    assert result["structural_chain_complete"] is True
    assert result["state"] == "unknown"
    assert result["semantic_authorization"] == 0
    assert result["reason"] == "caller_algorithm_applicability_and_ground_truth_unproved"
    assert all(len(result[key]) == 64 for key in (
        "graph_proof_sha256", "callsite_proof_sha256", "chain_sha256"))


def test_mutation_matrix_fails_closed_without_false_accepts():
    report = run_benchmark(latency_samples=1)
    assert report["metrics"] == {"correct": 6, "false_accepts": 0, "false_rejects": 0}
    assert report["fact_state"] == "unknown"
    assert report["semantic_authorization"] == 0
    assert report["api_calls"] == 0


def test_post_capture_change_breaks_the_preprocessing_binding():
    result = _capture(GOOD, analyze_after_capture="\nint changed;\n")
    assert result["structural_chain_complete"] is False
    assert result["stages"] == {"official_evidence": True,
                                "operation_graph": False,
                                "direct_array_callsite": False,
                                "same_preprocessed_occurrence": False}
    assert result["state"] == "unknown"
