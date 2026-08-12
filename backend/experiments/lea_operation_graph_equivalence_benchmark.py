"""API-free benchmark for a closed LEA operation-graph equivalence contract.

This is an evaluation oracle, not a production authorization path.  It models
one normative LEA round-word expression and deliberately permits only the
commutativity of XOR and modular addition.
"""
from __future__ import annotations

import hashlib
import json
import statistics
import time
from typing import Any

Graph = dict[str, Any]


def leaf(name: str) -> Graph:
    return {"op": "input", "name": name}


def node(op: str, *args: Graph, width: int = 32, amount: int | None = None) -> Graph:
    result: Graph = {"op": op, "width": width, "args": list(args)}
    if amount is not None:
        result["amount"] = amount
    return result


def normative_graph() -> Graph:
    """ROL32_9((x0 XOR rk0) ADD32 (x1 XOR rk1))."""
    return node(
        "rol", node("add", node("xor", leaf("x0"), leaf("rk0")),
                     node("xor", leaf("x1"), leaf("rk1"))), amount=9,
    )


def fixtures() -> list[dict[str, Any]]:
    exact = normative_graph()
    commutative = node(
        "rol", node("add", node("xor", leaf("rk1"), leaf("x1")),
                     node("xor", leaf("rk0"), leaf("x0"))), amount=9,
    )
    wrong_order = node(
        "add", node("rol", node("xor", leaf("x0"), leaf("rk0")), amount=9),
        node("xor", leaf("x1"), leaf("rk1")),
    )
    wrong_rotate = node(
        "rol", node("add", node("xor", leaf("x0"), leaf("rk0")),
                     node("xor", leaf("x1"), leaf("rk1"))), amount=8,
    )
    unrelated_copy = leaf("x0")
    return [
        {"case": "exact", "expected": True, "graph": exact},
        {"case": "commutative_equivalent", "expected": True, "graph": commutative},
        {"case": "wrong_order", "expected": False, "graph": wrong_order},
        {"case": "wrong_rotate", "expected": False, "graph": wrong_rotate},
        {"case": "unrelated_copy", "expected": False, "graph": unrelated_copy},
    ]


def canonicalize(graph: Graph) -> Graph:
    op = graph.get("op")
    if op == "input":
        if set(graph) != {"op", "name"} or not isinstance(graph.get("name"), str):
            raise ValueError("invalid_input_node")
        return {"op": "input", "name": graph["name"]}
    if op not in {"xor", "add", "rol"}:
        raise ValueError("unsupported_operation")
    allowed = {"op", "width", "args", "amount"} if op == "rol" else {"op", "width", "args"}
    if set(graph) != allowed:
        raise ValueError("unexpected_operation_field")
    if graph.get("width") != 32 or not isinstance(graph.get("args"), list):
        raise ValueError("invalid_operation_node")
    expected_arity = 1 if op == "rol" else 2
    if len(graph["args"]) != expected_arity:
        raise ValueError("invalid_arity")
    result: Graph = {"op": op, "width": 32,
                     "args": [canonicalize(arg) for arg in graph["args"]]}
    if op == "rol":
        amount = graph.get("amount")
        if not isinstance(amount, int) or isinstance(amount, bool) or not 0 < amount < 32:
            raise ValueError("invalid_rotate")
        result["amount"] = amount
    if op in {"xor", "add"}:
        result["args"].sort(key=lambda item: json.dumps(item, sort_keys=True,
                                                        separators=(",", ":")))
    return result


def digest(graph: Graph) -> str:
    payload = json.dumps(canonicalize(graph), sort_keys=True,
                         separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def equivalent(candidate: Graph) -> bool:
    try:
        return digest(candidate) == digest(normative_graph())
    except (TypeError, ValueError):
        return False


def run_benchmark(*, iterations: int = 10_000) -> dict[str, Any]:
    if iterations < 1:
        raise ValueError("iterations_must_be_positive")
    cases = fixtures()
    rows = []
    for case in cases:
        observed = equivalent(case["graph"])
        rows.append({"case": case["case"], "expected_equivalent": case["expected"],
                     "observed_equivalent": observed, "correct": observed == case["expected"]})
    samples: list[float] = []
    for _ in range(5):
        started = time.perf_counter_ns()
        for index in range(iterations):
            equivalent(cases[index % len(cases)]["graph"])
        samples.append((time.perf_counter_ns() - started) / iterations / 1_000)
    tp = sum(r["expected_equivalent"] and r["observed_equivalent"] for r in rows)
    tn = sum(not r["expected_equivalent"] and not r["observed_equivalent"] for r in rows)
    fp = sum(not r["expected_equivalent"] and r["observed_equivalent"] for r in rows)
    fn = sum(r["expected_equivalent"] and not r["observed_equivalent"] for r in rows)
    return {
        "schema_version": "1.0",
        "benchmark": "lea-closed-operation-graph-equivalence-synthetic",
        "population": {"synthetic_cases": len(rows), "iterations_per_sample": iterations,
                       "latency_samples": len(samples)},
        "cases": rows,
        "metrics": {"tp": tp, "tn": tn, "fp": fp, "fn": fn,
                    "accuracy": (tp + tn) / len(rows),
                    "positive_recall": tp / (tp + fn),
                    "negative_recall": tn / (tn + fp)},
        "latency_us_per_comparison": {
            "mean": round(statistics.mean(samples), 3),
            "median": round(statistics.median(samples), 3),
            "max": round(max(samples), 3),
        },
        "api_calls": 0,
        "semantic_authorization": 0,
        "interpretation": "synthetic_oracle_only_pending_independent_semantic_audit",
    }


if __name__ == "__main__":
    print(json.dumps(run_benchmark(), ensure_ascii=False, indent=2, sort_keys=True))
