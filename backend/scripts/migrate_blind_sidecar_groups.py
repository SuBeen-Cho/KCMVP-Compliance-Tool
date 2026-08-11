#!/usr/bin/env python3
"""Strictly bind public packet group IDs into an existing sealed sidecar."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from experiments.labeling import LabelingError  # noqa: E402
from experiments.score_only_evaluation import (  # noqa: E402
    EvaluationJoinError, migrate_v15_sidecar_group_ids,
)


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sidecar", type=Path, required=True)
    parser.add_argument("--packet", action="append", required=True,
                        help="VIEW=PATH; provide all three registered views")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    packets, input_paths = {}, {args.sidecar.resolve()}
    for value in args.packet:
        if "=" not in value:
            raise EvaluationJoinError("packet inputs must use VIEW=PATH")
        view, raw_path = value.split("=", 1)
        path = Path(raw_path)
        if view in packets:
            raise EvaluationJoinError("packet views must be unique")
        packets[view] = _load(path)
        input_paths.add(path.resolve())
    if args.output.resolve() in input_paths or args.output.exists():
        raise EvaluationJoinError("output must be a new path distinct from immutable inputs")
    result = migrate_v15_sidecar_group_ids(_load(args.sidecar), packets)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{args.output.name}.", dir=args.output.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(result, handle, ensure_ascii=False, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, args.output)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
    print(json.dumps({"status": "ok", "sidecar_id": result["sidecar_id"],
                      "occurrence_count": len(result["occurrences"])}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (EvaluationJoinError, LabelingError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        raise SystemExit(2)
