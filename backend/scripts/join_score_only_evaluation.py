#!/usr/bin/env python3
"""Join sealed labels with score-only outputs, then calibrate entirely offline."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from experiments.calibration import CalibrationDataError, calibrate  # noqa: E402
from experiments.score_only_evaluation import (  # noqa: E402
    EvaluationJoinError, build_calibration_proxy, paired_binary_report,
)


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, value) -> None:
    if path.exists():
        raise EvaluationJoinError("output already exists; immutable evaluation artifacts are not overwritten")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
                    encoding="utf-8")
    os.chmod(path, 0o600)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sidecar", type=Path, required=True)
    parser.add_argument("--gt", type=Path, required=True)
    parser.add_argument("--score", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--threshold", type=int, action="append", required=True)
    parser.add_argument("--heldout-fraction", type=float, default=.3)
    parser.add_argument("--minimum-recall", type=float, default=1.0)
    parser.add_argument("--bootstrap-iterations", type=int, default=500)
    args = parser.parse_args(argv)
    inputs = {path.resolve() for path in [args.sidecar, args.gt, *args.score]}
    if args.output.resolve() in inputs:
        raise EvaluationJoinError("output must not overwrite an input artifact")
    dataset = build_calibration_proxy(_load(args.sidecar), _load(args.gt),
                                      [_load(path) for path in args.score])
    result = {
        "claim_limit": dataset["claim_limit"],
        "paired_binary": paired_binary_report(dataset),
        "calibration": calibrate(
            dataset, thresholds=args.threshold, windows=[None],
            minimum_recall=args.minimum_recall, heldout_fraction=args.heldout_fraction,
            bootstrap_iterations=args.bootstrap_iterations,
        ),
    }
    _write(args.output, result)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (EvaluationJoinError, CalibrationDataError, OSError, json.JSONDecodeError,
            ValueError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False),
              file=sys.stderr)
        raise SystemExit(2)
