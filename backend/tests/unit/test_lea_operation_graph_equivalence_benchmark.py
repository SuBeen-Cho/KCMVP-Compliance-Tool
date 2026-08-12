import pytest

from experiments.lea_operation_graph_equivalence_benchmark import (
    canonicalize, equivalent, fixtures, run_benchmark,
)


def test_closed_fixture_matrix_separates_equivalence_and_mutations():
    results = {row["case"]: equivalent(row["graph"]) for row in fixtures()}
    assert results == {
        "exact": True,
        "commutative_equivalent": True,
        "wrong_order": False,
        "wrong_rotate": False,
        "unrelated_copy": False,
    }


@pytest.mark.parametrize("graph", [
    {"op": "mul", "width": 32, "args": []},
    {"op": "rol", "width": 64, "amount": 9, "args": [{"op": "input", "name": "x"}]},
    {"op": "rol", "width": 32, "amount": True, "args": [{"op": "input", "name": "x"}]},
    {"op": "input", "name": "x", "untrusted": True},
    {"op": "xor", "width": 32, "args": [{"op": "input", "name": "x"},
                                             {"op": "input", "name": "y"}], "untrusted": True},
])
def test_malformed_or_out_of_contract_graphs_fail_closed(graph):
    with pytest.raises(ValueError):
        canonicalize(graph)
    assert equivalent(graph) is False


def test_aggregate_metrics_never_authorize_semantics():
    report = run_benchmark(iterations=5)
    assert report["metrics"] == {
        "tp": 2, "tn": 3, "fp": 0, "fn": 0,
        "accuracy": 1.0, "positive_recall": 1.0, "negative_recall": 1.0,
    }
    assert report["api_calls"] == 0
    assert report["semantic_authorization"] == 0


def test_invalid_iteration_count_is_rejected():
    with pytest.raises(ValueError, match="iterations_must_be_positive"):
        run_benchmark(iterations=0)
