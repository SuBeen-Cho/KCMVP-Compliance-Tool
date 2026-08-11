#!/usr/bin/env python3
"""Convert a raw frozen-L1 L3 result into a sealed score-only artifact."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from experiments.score_only_evaluation import (  # noqa: E402
    EvaluationJoinError, score_artifact_from_l3_result,
)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("result", type=Path)
    parser.add_argument("--condition", required=True)
    parser.add_argument("--repeat", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.output.resolve() == args.result.resolve() or args.output.exists():
        raise EvaluationJoinError("output must be a new path distinct from the raw result")
    result = json.loads(args.result.read_text(encoding="utf-8"))
    artifact = score_artifact_from_l3_result(
        result, condition=args.condition, repeat=args.repeat,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{args.output.name}.", dir=args.output.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(artifact, handle, ensure_ascii=False, sort_keys=True, indent=2)
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
    print(json.dumps({"status": "ok", "artifact_id": artifact["artifact_id"],
                      "universe": len(artifact["coverage"]["universe_ids"]),
                      "selected": len(artifact["coverage"]["selected_ids"]),
                      "scored": len(artifact["coverage"]["scored_ids"]),
                      "unresolved": len(artifact["coverage"]["unresolved_ids"])}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (EvaluationJoinError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        raise SystemExit(2)
