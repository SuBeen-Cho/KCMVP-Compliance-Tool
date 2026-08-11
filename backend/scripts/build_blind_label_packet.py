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

from experiments.blind_corpus import _atomic_json, build_packets, extract_legacy_gt, write_packets  # noqa: E402
from experiments.blind_views import build_three_view_packets  # noqa: E402


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
    parser.add_argument("--analysis-snapshot", type=Path, required=True,
                        help="label-free L1 snapshot produced from sanitized analysis sources")
    parser.add_argument("--public-output", type=Path,
                        help="single-view output (not used with --three-view-output-dir)")
    parser.add_argument("--private-output", type=Path, required=True)
    parser.add_argument("--equivalence-report", type=Path, required=True,
                        help="passing strict analysis and detector-blindness report")
    parser.add_argument("--gt-zip", type=Path, action="append", default=[])
    parser.add_argument("--three-view-output-dir", type=Path,
                        help="issue artifact-aware, minimal and opaque joined packets")
    parser.add_argument("--generator-manifest", type=Path,
                        help="required provenance manifest for three-view cue control")
    args = parser.parse_args(argv)
    if args.three_view_output_dir and (args.public_output or not args.generator_manifest):
        parser.error("three-view mode requires --generator-manifest and forbids --public-output")
    if not args.three_view_output_dir and not args.public_output:
        parser.error("single-view mode requires --public-output")
    if args.three_view_output_dir:
        protected = {args.analysis_snapshot.resolve(), args.equivalence_report.resolve(),
                     args.generator_manifest.resolve()}
        outputs = {args.private_output.resolve()} | {
            (args.three_view_output_dir / f"{view}.json").resolve()
            for view in ("analysis_artifact_aware", "minimal_cue_controlled", "fully_opaque")
        }
        if len(protected) != 3 or len(outputs) != 4 or outputs & protected:
            parser.error("three-view private/public outputs and immutable inputs must all be distinct")
    salt_hex = os.environ.get("KCMVP_BLIND_SALT", "")
    if len(salt_hex) < 32:
        parser.error("KCMVP_BLIND_SALT must be at least 32 hexadecimal characters")
    try:
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        parser.error("KCMVP_BLIND_SALT must be hexadecimal")
    snapshot = json.loads(args.analysis_snapshot.read_text(encoding="utf-8"))
    equivalence_report = json.loads(args.equivalence_report.read_text(encoding="utf-8"))
    legacy_gt = extract_legacy_gt(args.gt_zip) if args.gt_zip else None
    if args.three_view_output_dir:
        manifest = json.loads(args.generator_manifest.read_text(encoding="utf-8"))
        packets, private = build_three_view_packets(
            snapshot, load_catalog(), salt=salt, equivalence_report=equivalence_report,
            generator_manifest=manifest,
        )
        try:
            args.private_output.resolve().relative_to(REPO.resolve())
        except ValueError:
            pass
        else:
            parser.error("private sidecar must be written outside the Git repository")
        _atomic_json(args.private_output, private, 0o600)
        for view, packet in packets.items():
            _atomic_json(args.three_view_output_dir / f"{view}.json", packet, 0o644)
        public = packets["fully_opaque"]
    else:
        public, private = build_packets(
            snapshot, load_catalog(), salt=salt, equivalence_report=equivalence_report,
            legacy_gt=legacy_gt,
        )
        write_packets(args.public_output, args.private_output, public, private, REPO)
    print(json.dumps({
        "packet_id": public["packet_id"],
        "occurrence_count": len(public["items"]),
        "public_output": None if args.three_view_output_dir else str(args.public_output),
        "private_output": str(args.private_output),
        "views": sorted(packets) if args.three_view_output_dir else ["fully_opaque"],
    }, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
