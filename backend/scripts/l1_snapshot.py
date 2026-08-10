#!/usr/bin/env python3
"""Export or validate a frozen, label-free L1 snapshot."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from experiments.l1_snapshot import (  # noqa: E402
    SnapshotError, atomic_write_snapshot, build_snapshot, validate_snapshot,
)
from experiments.manifest import build_manifest  # noqa: E402


def _candidate_list(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("candidates", "violations", "l1_violations"):
            if isinstance(data.get(key), list):
                return data[key]
    raise SnapshotError("candidate JSON must be a list or contain a candidate list")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    export = subparsers.add_parser("export")
    export.add_argument("--set-id", required=True)
    export.add_argument("--source-root", type=Path, required=True)
    export.add_argument("--candidates", type=Path, required=True)
    export.add_argument("--output", type=Path, required=True)
    export.add_argument("--repo", type=Path, default=BACKEND.parent)
    validate = subparsers.add_parser("validate")
    validate.add_argument("snapshot", type=Path)
    args = parser.parse_args(argv)

    if args.command == "export":
        manifest = build_manifest(args.repo)
        snapshot = build_snapshot(
            args.source_root,
            _candidate_list(args.candidates),
            set_id=args.set_id,
            provenance={
                "git_commit": manifest["code"]["commit"],
                "workspace_sha256": manifest["code"]["workspace_sha256"],
                "rules_sha256": manifest["artifacts"]["rules_tree_sha256"],
                "prompts_sha256": manifest["artifacts"]["prompts_sha256"],
            },
        )
        atomic_write_snapshot(args.output, snapshot)
        report = validate_snapshot(snapshot)
    else:
        report = validate_snapshot(json.loads(args.snapshot.read_text(encoding="utf-8")))
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (SnapshotError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        raise SystemExit(2)
