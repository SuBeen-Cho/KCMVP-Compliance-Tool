#!/usr/bin/env python3
"""Build a public blind-label packet and an off-repository private sidecar."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

import yaml

BACKEND = Path(__file__).resolve().parents[1]
REPO = BACKEND.parent
sys.path.insert(0, str(BACKEND))

from experiments.blind_corpus import build_packets, extract_legacy_gt, write_packets  # noqa: E402


def load_catalog() -> dict[str, dict[str, str]]:
    catalog = {}
    guideline_hashes = {}
    for path in sorted((BACKEND / "guidelines").glob("*.md")):
        guideline_hashes[path.stem.split("_")[0]] = hashlib.sha256(path.read_bytes()).hexdigest()
    for path in sorted((BACKEND / "rules").rglob("*.yaml")):
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for rule in raw.get("rules", []):
            rule_id = str(rule.get("id", ""))
            if rule_id:
                catalog[rule_id] = {
                    "description": str(rule.get("description", "")),
                    "kcmvp_ref": str(rule.get("kcmvp_ref", "")),
                    "guideline_sha256": guideline_hashes.get(rule_id, ""),
                }
    return catalog


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--public-output", type=Path, required=True)
    parser.add_argument("--private-output", type=Path, required=True)
    parser.add_argument("--gt-zip", type=Path, action="append", default=[])
    args = parser.parse_args(argv)
    salt_hex = os.environ.get("KCMVP_BLIND_SALT", "")
    if len(salt_hex) < 32:
        parser.error("KCMVP_BLIND_SALT must be at least 32 hexadecimal characters")
    try:
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        parser.error("KCMVP_BLIND_SALT must be hexadecimal")
    snapshot = json.loads(args.snapshot.read_text(encoding="utf-8"))
    legacy_gt = extract_legacy_gt(args.gt_zip) if args.gt_zip else None
    public, private = build_packets(snapshot, load_catalog(), salt=salt, legacy_gt=legacy_gt)
    write_packets(args.public_output, args.private_output, public, private, REPO)
    print(json.dumps({
        "packet_id": public["packet_id"],
        "occurrence_count": len(public["items"]),
        "public_output": str(args.public_output),
        "private_output": str(args.private_output),
    }, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
