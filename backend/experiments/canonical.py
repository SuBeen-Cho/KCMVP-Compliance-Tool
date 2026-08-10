"""Validate legacy evaluation summaries before promoting them to canonical results."""
from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any


def metrics(tp: int, fp: int, fn: int) -> dict[str, float]:
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"precision": precision, "recall": recall, "f1": f1}


def audit_legacy_result(payload: dict[str, Any]) -> dict[str, Any]:
    aggregate = payload["aggregate_all"]
    computed = metrics(int(aggregate["TP"]), int(aggregate["FP"]), int(aggregate["FN"]))
    blind = payload.get("blind_kcmvp", {})
    final_count = int(blind.get("final_count", 0))
    kloc = float(blind.get("kloc", 0))
    blind_rate = final_count / kloc if kloc else None
    checks = {
        key: math.isclose(computed[key], float(aggregate[key.capitalize()]), rel_tol=1e-9)
        for key in ("precision", "recall")
    }
    checks["f1"] = math.isclose(computed["f1"], float(aggregate["F1"]), rel_tol=1e-9)
    return {
        "schema_version": "1.0",
        "status": "legacy_unverified",
        "reason": (
            "The source result has no immutable code/input/prompt manifest; "
            "its arithmetic can be audited but it cannot be promoted to a canonical paper run."
        ),
        "source_timestamp": payload.get("timestamp"),
        "aggregate": {
            "counts": {key: int(aggregate[key]) for key in ("GT", "TP", "FN", "FP")},
            "computed": computed,
            "reported_consistent": checks,
        },
        "blind": {
            "c_files": blind.get("c_files"),
            "kloc_reported": kloc,
            "final_candidates": final_count,
            "computed_candidates_per_kloc": blind_rate,
            "paper_claim_7_over_14_5": 7 / 14.5,
            "incompatible_with_paper_claim": (final_count, kloc) != (7, 14.5),
        },
        "usage": {
            "tokens": payload.get("total_tokens"),
            "cost_usd": payload.get("total_cost_usd"),
            "elapsed_s": payload.get("total_elapsed_s"),
        },
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("result", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    audited = audit_legacy_result(json.loads(args.result.read_text(encoding="utf-8")))
    text = json.dumps(audited, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    else:
        print(text, end="")


if __name__ == "__main__":
    main()
