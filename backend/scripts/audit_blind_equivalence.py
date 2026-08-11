#!/usr/bin/env python3
"""Audit semantic preservation before releasing a blind-label packet."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from app.services.rule_engine_service import run_rule_engine  # noqa: E402
from experiments.blind_equivalence import run_equivalence_gate  # noqa: E402
from experiments.l1_snapshot import canonical_bytes  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--compiler", default="clang")
    args = parser.parse_args(argv)
    salt_hex = os.environ.get("KCMVP_BLIND_SALT", "")
    if len(salt_hex) < 32:
        parser.error("KCMVP_BLIND_SALT must be at least 32 hexadecimal characters")
    try:
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        parser.error("KCMVP_BLIND_SALT must be hexadecimal")
    snapshot = json.loads(args.snapshot.read_text(encoding="utf-8"))
    report = run_equivalence_gate(
        snapshot, salt=salt, rules_dir=BACKEND / "rules",
        engine=run_rule_engine, compiler=args.compiler,
    )
    args.output.write_bytes(canonical_bytes(report) + b"\n")
    print(json.dumps({
        "passed": report["passed"], "source_count": report["source_count"],
        "expected": report["candidate_count_expected"],
        "observed": report["candidate_count_observed"], "output": str(args.output),
    }, ensure_ascii=False, sort_keys=True))
    return 0 if report["passed"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
