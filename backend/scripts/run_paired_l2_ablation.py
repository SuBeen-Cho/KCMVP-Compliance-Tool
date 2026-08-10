#!/usr/bin/env python3
"""Run reproducible AB/BA RAG ablations from one immutable L1 snapshot.

Each condition runs in a fresh Python process. Credentials are inherited only
through the provider environment and are never accepted as arguments or stored.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import uuid
from typing import Any, Callable

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from experiments.l1_snapshot import SnapshotError, canonical_bytes, validate_snapshot  # noqa: E402


SCHEMA_VERSION = "1.0"
SECRET_RE = re.compile(r"AIza[0-9A-Za-z_-]{20,}")
LOCAL_PATH_RE = re.compile(
    r"(?:/Users/|/home/|/tmp/|/private/|/var/folders/|(?<![A-Za-z])[A-Za-z]:[\\/])"
)
CONDITIONS = {"rag": False, "no_rag": True}
CONTROLLED_ENV = {
    "ABLATION_NO_COT": "0", "ABLATION_NO_REJUDGE": "0", "ABLATION_NO_GCFS": "0",
    "ABLATION_NO_DUAL_VERIFY": "0", "ABLATION_NO_MISSING_PROTECT": "0",
    "L3_EXPERIMENTAL_MISSING_RELAX": "0", "L3_EXPERIMENTAL_AST_RELAX": "0",
    "L3_HYBRID_SAFE_RELAX": "0", "L3_GROUNDED_RELAX": "0",
    "L3_GROUNDED_ARTIFACT_RELAX": "0", "LLM_ALLOW_PROVIDER_FALLBACK": "0",
}
Runner = Callable[[list[str], dict[str, str]], subprocess.CompletedProcess[str]]


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def build_schedule(pairs: int, base_seed: int) -> list[dict[str, Any]]:
    if isinstance(pairs, bool) or pairs < 1:
        raise SnapshotError("pairs must be a positive integer")
    if isinstance(base_seed, bool) or not 0 <= base_seed <= 2_147_483_647:
        raise SnapshotError("base seed must be between 0 and 2147483647")
    schedule = []
    for pair_index in range(pairs):
        order = ["rag", "no_rag"] if pair_index % 2 == 0 else ["no_rag", "rag"]
        seed = base_seed + pair_index
        if seed > 2_147_483_647:
            raise SnapshotError("derived seed exceeds 2147483647")
        for order_index, condition in enumerate(order):
            schedule.append({
                "pair_index": pair_index + 1,
                "order_index": order_index + 1,
                "condition": condition,
                "no_rag": CONDITIONS[condition],
                "seed": seed,
            })
    return schedule


def _load_and_validate_snapshot(path: Path) -> dict[str, Any]:
    try:
        snapshot = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SnapshotError("snapshot is not valid JSON") from exc
    validate_snapshot(snapshot)
    return snapshot


def _assert_safe_serialized(value: Any) -> None:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True)
    if SECRET_RE.search(encoded):
        raise SnapshotError("credential-like value found in experiment artifact")
    if LOCAL_PATH_RE.search(encoded):
        raise SnapshotError("workstation path found in experiment artifact")


def _read_ledger(path: Path, *, run_id: str, snapshot_id: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    records = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SnapshotError(f"ledger line {line_number} is not valid JSON") from exc
        if record.get("run_id") != run_id or record.get("snapshot_id") != snapshot_id:
            raise SnapshotError("ledger identity differs from condition result")
        if record.get("sequence") != line_number:
            raise SnapshotError("ledger sequence is not contiguous")
        for field in ("input_tokens", "output_tokens"):
            value = record.get(field)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise SnapshotError(f"ledger {field} must be a non-negative integer")
        records.append(record)
    _assert_safe_serialized(records)
    usage = {
        "provider_calls": len(records),
        "input_tokens": sum(item["input_tokens"] for item in records),
        "output_tokens": sum(item["output_tokens"] for item in records),
        "providers": sorted({str(item.get("provider")) for item in records}),
        "models": sorted({str(item.get("model")) for item in records}),
        "usage_statuses": sorted({str(item.get("usage_status")) for item in records}),
    }
    return records, usage


def _default_runner(command: list[str], environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, env=environment, text=True, capture_output=True, check=False)


def run_experiment(
    snapshot_path: Path, output_dir: Path, *, pairs: int, base_seed: int,
    input_usd_per_million: float, output_usd_per_million: float,
    pricing_as_of: str, pricing_source: str, pricing_model: str,
    runner: Runner = _default_runner,
) -> dict[str, Any]:
    """Validate all inputs before launching, then execute the fixed schedule."""
    snapshot = _load_and_validate_snapshot(snapshot_path)
    schedule = build_schedule(pairs, base_seed)
    if input_usd_per_million < 0 or output_usd_per_million < 0:
        raise SnapshotError("token prices must be non-negative")
    if not pricing_as_of or not pricing_source.startswith("https://") or not pricing_model:
        raise SnapshotError("pricing provenance requires a date and HTTPS source")
    if output_dir.exists() and any(output_dir.iterdir()):
        raise SnapshotError("output directory must be absent or empty")
    if output_dir.resolve() == snapshot_path.resolve() or output_dir in snapshot_path.resolve().parents:
        raise SnapshotError("output directory overlaps immutable snapshot")
    output_dir.mkdir(parents=True, exist_ok=True)

    experiment_run_id = uuid.uuid4().hex
    executions = []
    expected_candidates = snapshot["l3_candidate_ids"]
    for execution_index, planned in enumerate(schedule, 1):
        stem = f"{execution_index:03d}_p{planned['pair_index']}_{planned['condition']}"
        result_path = output_dir / f"{stem}.result.json"
        ledger_path = output_dir / f"{stem}.ledger.jsonl"
        command = [
            sys.executable, str(BACKEND / "scripts" / "l3_snapshot_run.py"),
            str(snapshot_path), "--ledger", str(ledger_path), "--output", str(result_path),
        ]
        if planned["no_rag"]:
            command.append("--no-rag")
        environment = dict(os.environ)
        environment.update(CONTROLLED_ENV)
        environment["KCMVP_L3_SEED"] = str(planned["seed"])
        environment["PYTHONHASHSEED"] = str(planned["seed"])
        completed = runner(command, environment)
        if completed.returncode != 0:
            raise SnapshotError(
                f"condition process failed at execution {execution_index} (exit {completed.returncode})"
            )
        if not result_path.is_file() or not ledger_path.is_file():
            raise SnapshotError("condition process did not produce required artifacts")
        result = json.loads(result_path.read_text(encoding="utf-8"))
        if result.get("snapshot_id") != snapshot["snapshot_id"]:
            raise SnapshotError("condition result references a different snapshot")
        if result.get("condition") != {"no_rag": planned["no_rag"]}:
            raise SnapshotError("condition result does not match scheduled condition")
        if result.get("generation_seed") != planned["seed"]:
            raise SnapshotError("condition result seed does not match scheduled seed")
        if result.get("candidate_ids") != expected_candidates:
            raise SnapshotError("condition result candidate identities differ from frozen snapshot")
        selected_ids = result.get("selected_candidate_ids")
        outcome_lists = [
            result.get("l3_result_candidate_ids"), result.get("rejected_candidate_ids"),
            result.get("unresolved_candidate_ids"),
        ]
        if not isinstance(selected_ids, list) or any(not isinstance(item, list) for item in outcome_lists):
            raise SnapshotError("condition result outcome identities are malformed")
        flattened = [candidate_id for item in outcome_lists for candidate_id in item]
        if (
            len(selected_ids) != len(set(selected_ids))
            or len(flattened) != len(set(flattened))
            or set(flattened) != set(selected_ids)
            or not set(selected_ids) <= set(expected_candidates)
        ):
            raise SnapshotError("condition outcomes do not partition the selected candidates")
        if result.get("request_ledger", {}).get("write_status") != "ok":
            raise SnapshotError("request ledger write was degraded")
        ledger_hash = _sha256_file(ledger_path)
        if result.get("request_ledger", {}).get("jsonl_sha256") != ledger_hash:
            raise SnapshotError("request ledger hash differs from condition result")
        _assert_safe_serialized(result)
        _, usage = _read_ledger(
            ledger_path, run_id=result["run_id"], snapshot_id=snapshot["snapshot_id"],
        )
        if usage["provider_calls"] and (
            usage["providers"] != ["gemini"]
            or usage["models"] != [pricing_model]
            or usage["usage_statuses"] != ["available"]
        ):
            raise SnapshotError("ledger usage does not match the versioned Gemini pricing model")
        cost = (
            usage["input_tokens"] * input_usd_per_million
            + usage["output_tokens"] * output_usd_per_million
        ) / 1_000_000
        executions.append({
            **planned,
            "execution_index": execution_index,
            "condition_run_id": result["run_id"],
            "result_sha256": _sha256_file(result_path),
            "ledger_sha256": ledger_hash,
            "usage": usage,
            "estimated_cost_usd": round(cost, 10),
            "outcomes": {
                "selected": len(result.get("selected_candidate_ids", [])),
                "retained": len(result.get("l3_result_candidate_ids", [])),
                "rejected": len(result.get("rejected_candidate_ids", [])),
                "unresolved": len(result.get("unresolved_candidate_ids", [])),
                "request_covered": len(result.get("request_covered_candidate_ids", [])),
            },
        })

    total_usage = {
        key: sum(item["usage"][key] for item in executions)
        for key in ("provider_calls", "input_tokens", "output_tokens")
    }
    aggregate_cost = (
        total_usage["input_tokens"] * input_usd_per_million
        + total_usage["output_tokens"] * output_usd_per_million
    ) / 1_000_000
    condition_totals = {}
    for condition in CONDITIONS:
        members = [item for item in executions if item["condition"] == condition]
        condition_totals[condition] = {
            key: sum(item["outcomes"][key] for item in members)
            for key in ("selected", "retained", "rejected", "unresolved", "request_covered")
        }
    pair_summaries = []
    for pair_index in range(1, pairs + 1):
        pair_members = {
            item["condition"]: item for item in executions if item["pair_index"] == pair_index
        }
        rag_outcomes = pair_members["rag"]["outcomes"]
        no_rag_outcomes = pair_members["no_rag"]["outcomes"]
        pair_summaries.append({
            "pair_index": pair_index,
            "seed": pair_members["rag"]["seed"],
            "rag_minus_no_rag": {
                key: rag_outcomes[key] - no_rag_outcomes[key]
                for key in ("retained", "rejected", "unresolved", "request_covered")
            },
        })
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "scope": "paired_ab_ba_l2_context_ablation_from_frozen_l1",
        "experiment_run_id": experiment_run_id,
        "snapshot_id": snapshot["snapshot_id"],
        "snapshot_file_sha256": _sha256_file(snapshot_path),
        "design": {
            "pairs": pairs,
            "condition_run_count": len(schedule),
            "base_seed": base_seed,
            "order": "AB/BA alternating by pair; conditions within a pair share a seed",
            "controlled_environment": CONTROLLED_ENV,
        },
        "pricing": {
            "currency": "USD",
            "unit": "per_1m_tokens",
            "input": input_usd_per_million,
            "output": output_usd_per_million,
            "as_of": pricing_as_of,
            "source": pricing_source,
            "provider": "gemini",
            "model": pricing_model,
            "status": "estimate_not_invoice",
        },
        "executions": executions,
        "pair_summaries": pair_summaries,
        "aggregate": {
            "usage": total_usage,
            "estimated_cost_usd": round(aggregate_cost, 10),
            "outcomes_by_condition": condition_totals,
        },
    }
    _assert_safe_serialized(manifest)
    _atomic_write_json(output_dir / "manifest.json", manifest)
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--pairs", type=int, default=3)
    parser.add_argument("--base-seed", type=int, default=42)
    parser.add_argument("--input-usd-per-million", type=float, default=0.10)
    parser.add_argument("--output-usd-per-million", type=float, default=0.40)
    parser.add_argument("--pricing-as-of", default="2026-08-11")
    parser.add_argument("--pricing-source", default="https://ai.google.dev/gemini-api/docs/pricing")
    parser.add_argument("--pricing-model", default="gemini-2.5-flash-lite")
    args = parser.parse_args(argv)
    manifest = run_experiment(
        args.snapshot, args.output_dir, pairs=args.pairs, base_seed=args.base_seed,
        input_usd_per_million=args.input_usd_per_million,
        output_usd_per_million=args.output_usd_per_million,
        pricing_as_of=args.pricing_as_of, pricing_source=args.pricing_source,
        pricing_model=args.pricing_model,
    )
    print(json.dumps({
        "status": "ok", "experiment_run_id": manifest["experiment_run_id"],
        "condition_run_count": manifest["design"]["condition_run_count"],
    }, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (SnapshotError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        raise SystemExit(2)
