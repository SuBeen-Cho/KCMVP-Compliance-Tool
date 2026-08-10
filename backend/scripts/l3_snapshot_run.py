#!/usr/bin/env python3
"""Run one L2+L3 condition from an immutable, label-free L1 snapshot.

The command intentionally executes one condition per process.  API credentials
are accepted only through the provider's environment configuration; no CLI key
option exists and no credential value is serialized.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import sys
import tempfile
import uuid
from typing import Any, Callable

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from experiments.l1_snapshot import SnapshotError, canonical_bytes, validate_snapshot  # noqa: E402
from app.services.llm.candidate_selector import _select_l3_candidates  # noqa: E402
from app.services.llm.l3_judge import run_l3_contextualizer  # noqa: E402
from app.services.rag_service import run_l2_rag_context  # noqa: E402
from app.services.llm.request_ledger import (  # noqa: E402
    disable_request_ledger, enable_request_ledger, get_request_ledger,
    get_request_ledger_status,
    request_ledger_file_sha256,
)


def _load_snapshot(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    validate_snapshot(value)
    return value


def _materialize_sources(snapshot: dict[str, Any], root: Path) -> dict[str, dict[str, Any]]:
    """Materialize validated sources while retaining logical paths in payloads."""
    files: dict[str, dict[str, Any]] = {}
    for source in snapshot["sources"]:
        source_id = source["source_id"]
        # validate_snapshot already rejects absolute/traversing IDs; retain this
        # local assertion at the filesystem boundary as defense in depth.
        logical = PurePosixPath(source_id)
        if logical.is_absolute() or ".." in logical.parts:
            raise SnapshotError("unsafe source id at materialization boundary")
        target = root.joinpath(*logical.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source["content"], encoding="utf-8")
        files[source_id] = {
            "path": source_id,
            "display": source_id,
            "content": source["content"],
            "lines": source["content"].splitlines(),
            "ast": {},
        }
    return files


def _rehydrate_candidates(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    restored = []
    for frozen in snapshot["candidates"]:
        payload = dict(frozen["payload"])
        source_id = payload.pop("source_id")
        payload["file"] = source_id
        payload["candidate_id"] = frozen["candidate_id"]
        restored.append(payload)
    if [item["candidate_id"] for item in restored] != snapshot["l3_candidate_ids"]:
        raise SnapshotError("rehydrated candidate order differs from snapshot")
    return restored


def _atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
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


def run_condition(
    snapshot: dict[str, Any], *, no_rag: bool, ledger_path: Path | None,
    l3_runner: Callable[..., list[dict[str, Any]]] | None = None,
    rag_runner: Callable[[list[dict[str, Any]]], list[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    """Validate, rehydrate and execute exactly one frozen experimental condition."""
    validate_snapshot(snapshot)
    l3_runner = l3_runner or run_l3_contextualizer
    rag_runner = rag_runner or run_l2_rag_context
    run_id = uuid.uuid4().hex
    if ledger_path is not None:
        enable_request_ledger(
            ledger_path, run_id=run_id, snapshot_id=snapshot["snapshot_id"], truncate=True,
        )
    previous_ablation = os.environ.get("ABLATION_NO_RAG")
    os.environ["ABLATION_NO_RAG"] = "1" if no_rag else "0"
    try:
        with tempfile.TemporaryDirectory(prefix="kcmvp-l3-snapshot-") as temporary:
            files = _materialize_sources(snapshot, Path(temporary))
            candidates = _rehydrate_candidates(snapshot)
            immutable_candidate_bytes = [canonical_bytes(item) for item in candidates]
            enriched = rag_runner(candidates)
            if [item.get("candidate_id") for item in enriched] != snapshot["l3_candidate_ids"]:
                raise SnapshotError("L2 changed frozen candidate order or identity")
            rag_only_fields = {"rag_guideline_text", "rag_ablation"}
            for original_bytes, after_l2 in zip(immutable_candidate_bytes, enriched):
                base_after_l2 = {
                    key: value for key, value in after_l2.items()
                    if key not in rag_only_fields
                }
                if canonical_bytes(base_after_l2) != original_bytes:
                    raise SnapshotError("L2 changed immutable candidate payload")
            # Freeze selection once before entering L3.  The production runner may
            # defensively select again, but it receives this exact ordered subset.
            selected = _select_l3_candidates(enriched)
            selected_ids = [item["candidate_id"] for item in selected]
            rejected: set[tuple[str, str, int | None]] = set()
            l3_results = l3_runner(
                preprocess_result={"files": list(files.values())},
                l1_violations=selected,
                _rejected_tracker=rejected,
                _preselected=True,
                _rejected_candidate_ids=True,
            )
        result_ids = [str(item["candidate_id"]) for item in l3_results if item.get("candidate_id")]
        selected_set = set(selected_ids)
        if len(result_ids) != len(set(result_ids)) or not set(result_ids) <= selected_set:
            raise SnapshotError("L3 returned unknown or duplicate candidate identities")
        rejected_ids = [item["candidate_id"] for item in selected if item["candidate_id"] in rejected]
        unresolved_ids = [
            candidate_id for candidate_id in selected_ids
            if candidate_id not in set(result_ids) and candidate_id not in set(rejected_ids)
        ]
        ledger = get_request_ledger_status() if ledger_path is not None else {
            "scope": "code_l3_experiment_requests_only", "status": "disabled",
        }
        if ledger_path is not None:
            ledger["jsonl_sha256"] = request_ledger_file_sha256()
        ledger_hashes = {
            candidate_hash
            for record in get_request_ledger()
            for candidate_hash in record.get("candidate_ids", [])
        } if ledger_path is not None else set()
        requested_ids = [
            candidate_id for candidate_id in selected_ids
            if hashlib.sha256(candidate_id.encode("utf-8")).hexdigest() in ledger_hashes
        ]
        result_id_set, rejected_id_set = set(result_ids), set(rejected_ids)
        requested_id_set = set(requested_ids)
        dispositions = [
            {
                "candidate_id": candidate_id,
                "status": (
                    "retained" if candidate_id in result_id_set else
                    "rejected" if candidate_id in rejected_id_set else "unresolved"
                ),
                "provider_request_recorded": candidate_id in requested_id_set,
            }
            for candidate_id in selected_ids
        ]
        return {
            "schema_version": "1.0",
            "scope": "single_l2_l3_condition_from_frozen_l1",
            "run_id": run_id,
            "snapshot_id": snapshot["snapshot_id"],
            "condition": {"no_rag": no_rag},
            "candidate_ids": list(snapshot["l3_candidate_ids"]),
            "selected_candidate_ids": selected_ids,
            "l3_result_candidate_ids": result_ids,
            "rejected_candidate_ids": rejected_ids,
            "unresolved_candidate_ids": unresolved_ids,
            "request_covered_candidate_ids": requested_ids,
            "candidate_dispositions": dispositions,
            "l3_results": l3_results,
            "request_ledger": ledger,
        }
    finally:
        disable_request_ledger()
        if previous_ablation is None:
            os.environ.pop("ABLATION_NO_RAG", None)
        else:
            os.environ["ABLATION_NO_RAG"] = previous_ablation


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("--no-rag", action="store_true")
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.output.resolve() == args.snapshot.resolve():
        raise SnapshotError("output must differ from immutable snapshot")
    if args.ledger is not None and args.ledger.resolve() in {
        args.snapshot.resolve(), args.output.resolve(),
    }:
        raise SnapshotError("ledger must differ from snapshot and result paths")
    snapshot = _load_snapshot(args.snapshot)
    result = run_condition(snapshot, no_rag=args.no_rag, ledger_path=args.ledger)
    _atomic_write_json(args.output, result)
    print(json.dumps({
        "status": "ok", "snapshot_id": result["snapshot_id"],
        "selected_count": len(result["selected_candidate_ids"]),
    }, ensure_ascii=False, sort_keys=True))
    return 0


def _safe_cli_error(exc: BaseException) -> str:
    if isinstance(exc, SnapshotError):
        return str(exc)
    if isinstance(exc, json.JSONDecodeError):
        return "snapshot is not valid JSON"
    return f"filesystem operation failed ({type(exc).__name__})"


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (SnapshotError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "error", "error": _safe_cli_error(exc)}, ensure_ascii=False), file=sys.stderr)
        raise SystemExit(2)
