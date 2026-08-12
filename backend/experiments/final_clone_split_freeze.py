"""Freeze a label-independent clone-group split before independent GT review."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from experiments.workspace_guard import guarded_output_path


SALT_ID = "kcmvp-final-confirmatory-split-v1"


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def freeze(sidecar: dict[str, Any], *, heldout_fraction: float = 0.3) -> tuple[dict[str, Any], dict[str, Any]]:
    rows = sidecar.get("occurrences")
    if not isinstance(rows, list) or len(rows) != 265 or not 0 < heldout_fraction < 1:
        raise ValueError("sealed_265_occurrences_required")
    occurrence_ids = [row.get("occurrence_id") for row in rows]
    frozen_ids = [row.get("frozen_candidate_id") for row in rows]
    group_ids = [row.get("group_id") for row in rows]
    if any(not isinstance(x, str) or not x for x in occurrence_ids + frozen_ids + group_ids):
        raise ValueError("complete_identity_required")
    if len(set(occurrence_ids)) != 265 or len(set(frozen_ids)) != 265:
        raise ValueError("duplicate_occurrence_identity")
    groups = sorted(set(group_ids))
    ranked = sorted(groups, key=lambda group: hashlib.sha256(f"{SALT_ID}:{group}".encode()).hexdigest())
    heldout_count = min(len(groups) - 1, max(1, round(len(groups) * heldout_fraction)))
    heldout_groups = set(ranked[:heldout_count])
    assignments = [{"occurrence_id": row["occurrence_id"], "frozen_candidate_id": row["frozen_candidate_id"],
                    "group_id": row["group_id"], "partition": "heldout" if row["group_id"] in heldout_groups else "development"}
                   for row in rows]
    private = {"schema_version": "1.0", "split_id": "", "snapshot_id": sidecar.get("snapshot_id"),
               "sidecar_id": sidecar.get("sidecar_id"), "salt_id": SALT_ID,
               "heldout_fraction": heldout_fraction, "assignments": assignments}
    private["split_id"] = _sha({k: v for k, v in private.items() if k != "split_id"})
    dev = [row for row in assignments if row["partition"] == "development"]
    heldout = [row for row in assignments if row["partition"] == "heldout"]
    public = {"schema_version": "1.0", "evaluation": "label_independent_clone_split_freeze",
              "split_id": private["split_id"], "snapshot_id": private["snapshot_id"], "sidecar_id": private["sidecar_id"],
              "salt_id": SALT_ID, "heldout_fraction": heldout_fraction,
              "counts": {"occurrences": 265, "clone_groups": len(groups), "development_occurrences": len(dev),
                         "development_groups": len({x["group_id"] for x in dev}), "heldout_occurrences": len(heldout),
                         "heldout_groups": len({x["group_id"] for x in heldout})},
              "assignment_digest_sha256": _sha(assignments), "labels_accessed": False, "api_calls": 0,
              "claim_limit": "Split preregistration only; held-out labels and performance remain unopened."}
    return private, public


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--sidecar", required=True, type=Path)
    parser.add_argument("--private-output", required=True, type=Path)
    parser.add_argument("--public-output", required=True, type=Path)
    args = parser.parse_args()
    private, public = freeze(json.loads(args.sidecar.read_text()))
    private_path = guarded_output_path(args.private_output, private=True)
    public_path = guarded_output_path(args.public_output)
    if private_path == public_path:
        raise ValueError("private_and_public_outputs_must_differ")
    private_path.write_text(json.dumps(private, sort_keys=True, indent=2) + "\n")
    os.chmod(private_path, 0o600)
    public_path.write_text(json.dumps(public, sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    main()
