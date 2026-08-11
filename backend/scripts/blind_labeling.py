#!/usr/bin/env python3
"""Validate blinded labels and produce agreement/adjudication artifacts offline."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))
from experiments.labeling import (LabelingError, agreement_report, validate_label_document,
                                  validate_packet)  # noqa: E402


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(raw); handle.flush(); os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        try: os.unlink(temporary)
        except FileNotFoundError: pass
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    packet_cmd = commands.add_parser("validate-packet")
    packet_cmd.add_argument("packet", type=Path)
    label_cmd = commands.add_parser("validate-label")
    label_cmd.add_argument("packet", type=Path); label_cmd.add_argument("labels", type=Path)
    agree = commands.add_parser("agreement")
    agree.add_argument("packet", type=Path); agree.add_argument("labels_a", type=Path)
    agree.add_argument("labels_b", type=Path); agree.add_argument("--report", required=True, type=Path)
    agree.add_argument("--disagreements", required=True, type=Path)
    args = parser.parse_args(argv)
    packet = load(args.packet)
    if args.command == "validate-packet": result = validate_packet(packet)
    elif args.command == "validate-label": result = validate_label_document(packet, load(args.labels))
    else:
        if args.report.resolve() in {args.packet.resolve(), args.labels_a.resolve(), args.labels_b.resolve()}:
            raise LabelingError("outputs must not overwrite immutable inputs")
        if args.disagreements.resolve() in {args.packet.resolve(), args.labels_a.resolve(), args.labels_b.resolve()}:
            raise LabelingError("outputs must not overwrite immutable inputs")
        if args.report.resolve() == args.disagreements.resolve():
            raise LabelingError("report and disagreement outputs must differ")
        result, queue = agreement_report(packet, load(args.labels_a), load(args.labels_b))
        write(args.report, result); write(args.disagreements, queue)
    print(json.dumps({"status": "ok", **result}, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    try: raise SystemExit(main())
    except (LabelingError, json.JSONDecodeError, OSError, ValueError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        raise SystemExit(2)
