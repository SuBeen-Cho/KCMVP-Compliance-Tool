#!/usr/bin/env python3
"""Calibrate a violation-probability policy from a closed JSON dataset.

This command is offline: it neither imports provider clients nor accepts an API
credential.  Threshold/window selection occurs only on development groups.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from experiments.calibration import CalibrationDataError, calibrate  # noqa: E402


def _window(value: str) -> tuple[int, int] | None:
    if value.lower() == "none":
        return None
    try:
        low, high = (int(part) for part in value.split(":", 1))
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError("window must be none or LOW:HIGH") from exc
    if not 0 <= low <= high <= 100:
        raise argparse.ArgumentTypeError("window must satisfy 0 <= LOW <= HIGH <= 100")
    return low, high


def _atomic_write(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--threshold", action="append", type=int, required=True)
    parser.add_argument("--window", action="append", type=_window, required=True)
    parser.add_argument("--minimum-recall", type=float, default=1.0)
    parser.add_argument("--heldout-fraction", type=float, default=0.3)
    parser.add_argument("--bootstrap-iterations", type=int, default=500)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args(argv)
    if args.dataset.resolve() == args.output.resolve():
        raise CalibrationDataError("output must differ from the immutable input dataset")
    dataset = json.loads(args.dataset.read_text(encoding="utf-8"))
    report = calibrate(
        dataset, thresholds=args.threshold, windows=args.window,
        minimum_recall=args.minimum_recall, heldout_fraction=args.heldout_fraction,
        bootstrap_iterations=args.bootstrap_iterations, seed=args.seed,
    )
    _atomic_write(args.output, report)
    print(json.dumps({
        "status": "ok", "selected_threshold": report["selected_policy_dev_metrics"]["threshold"],
        "heldout_n": report["heldout_n"],
    }, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (CalibrationDataError, json.JSONDecodeError, OSError, ValueError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        raise SystemExit(2)
