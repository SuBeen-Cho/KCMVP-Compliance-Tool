#!/usr/bin/env python3
"""Explicitly opt in to Gemini labeling of a public blind packet."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))
from experiments.gemini_blind_labeler import run  # noqa: E402
from experiments.labeling import validate_packet  # noqa: E402


def _load_env(path: Path) -> None:
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packet", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--checkpoint", type=Path, required=True)
    parser.add_argument("--annotator-id", required=True)
    parser.add_argument("--reverse", action="store_true")
    parser.add_argument("--execute-api", action="store_true",
                        help="required safety opt-in; sends disclosed packet windows to Google")
    args = parser.parse_args()
    if not args.execute_api:
        parser.error("--execute-api is required")
    packet = json.loads(args.packet.read_text(encoding="utf-8"))
    validate_packet(packet)
    _load_env(BACKEND / ".env")
    key = os.environ.get("GOOGLE_API_KEY", "")
    if not key:
        raise SystemExit("GOOGLE_API_KEY is not configured")
    from google import genai
    from google.genai import types
    # Bound each network attempt; the experiment runner owns the auditable retry loop.
    client = genai.Client(api_key=key, http_options=types.HttpOptions(
        timeout=45_000, retry_options=types.HttpRetryOptions(attempts=1)))
    document = run(packet=packet, client=client, annotator_id=args.annotator_id,
                   reverse=args.reverse, ledger_path=args.ledger,
                   checkpoint_path=args.checkpoint)
    args.output.write_text(json.dumps(document, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
                           encoding="utf-8")
    print(json.dumps({"status": "ok", "packet_id": packet["packet_id"],
                      "label_batch_id": document["label_batch_id"],
                      "annotation_count": len(document["annotations"])}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
