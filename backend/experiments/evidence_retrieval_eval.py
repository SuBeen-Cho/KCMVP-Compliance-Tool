"""Offline evaluation of the citation-bound official-evidence retrieval path."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import statistics
import time
from pathlib import Path
from typing import Any, Callable

from app.services import rag_service
from app.services.rag_grounding import verify_citation_bound_decision

SCHEMA_VERSION = "1.0"
CONDITIONS = ("relevant", "irrelevant", "conflicting", "oracle")
_GT_ROOT_KEYS = {"schema_version", "collection", "scope", "queries"}
_QUERY_KEYS = {"query_id", "rule_id", "query", "relevant_unit_ids", "allowed_source_ids"}


def load_ground_truth(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if set(data) != _GT_ROOT_KEYS or data.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("invalid or open ground-truth root schema")
    if data.get("collection") != "evidence_query_ground_truth" or data.get("scope") != "human_reviewed_semantic_seed" or not isinstance(data.get("queries"), list):
        raise ValueError("invalid ground-truth collection")
    seen: set[str] = set()
    for row in data["queries"]:
        if not isinstance(row, dict) or set(row) != _QUERY_KEYS:
            raise ValueError("invalid or open query schema")
        scalar = (row["query_id"], row["rule_id"], row["query"])
        if not all(isinstance(v, str) and v.strip() for v in scalar):
            raise ValueError("query identifiers and text must be non-empty strings")
        if row["query_id"] in seen:
            raise ValueError("duplicate query_id")
        seen.add(row["query_id"])
        for key in ("relevant_unit_ids", "allowed_source_ids"):
            values = row[key]
            if not isinstance(values, list) or not values or len(values) != len(set(values)):
                raise ValueError(f"{key} must be a non-empty unique list")
            if not all(isinstance(v, str) and v.strip() for v in values):
                raise ValueError(f"invalid {key}")
    return data


def evaluate_mapping_integrity(
    audit_path: Path, by_id: dict[str, dict[str, Any]], *, repeats: int = 3,
    search: Callable[..., list[dict[str, Any]]] = rag_service.search_evidence,
) -> dict[str, Any]:
    """Check every audited mapping without claiming semantic retrieval quality."""
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    rules = audit.get("rules")
    if not isinstance(rules, dict):
        raise ValueError("invalid evidence audit")
    verified_rows: list[dict[str, Any]] = []
    unverified_rows: list[dict[str, Any]] = []
    latencies: list[float] = []
    for rule_id, row in sorted(rules.items()):
        if not isinstance(row, dict):
            raise ValueError("invalid evidence audit rule")
        if row.get("status") != "verified":
            returned = search(rule_id, query=rule_id, top_k=3)
            unverified_rows.append({"rule_id": rule_id, "fail_closed": returned == [], "returned_count": len(returned)})
            continue
        expected = set(str(uid) for uid in row.get("evidence_unit_ids") or [])
        source_id = str((row.get("source_locator") or {}).get("source_id") or "")
        returned: list[dict[str, Any]] = []
        samples: list[float] = []
        for _ in range(repeats):
            started = time.perf_counter_ns()
            returned = search(rule_id, query=rule_id, top_k=3)
            samples.append((time.perf_counter_ns() - started) / 1_000_000)
        latencies.extend(samples)
        actual = [str(unit.get("unit_id")) for unit in returned]
        missing_index = sorted(uid for uid in expected if uid not in by_id)
        verified_rows.append({
            "rule_id": rule_id, "expected_count": len(expected), "returned_count": len(actual),
            "exact_unit_set": set(actual) == expected,
            "source_binding_valid": bool(source_id) and all(str(unit.get("source_id")) == source_id for unit in returned),
            "bundle_recall": len(expected.intersection(actual)) / len(expected) if expected else 0.0,
            "missing_index_unit_ids": missing_index,
        })
    def rate(rows: list[dict[str, Any]], key: str) -> float:
        return sum(float(row[key]) for row in rows) / len(rows) if rows else 1.0
    return {
        "interpretation": "mapping_integrity_not_semantic_retrieval_quality",
        "verified_rule_count": len(verified_rows), "unverified_rule_count": len(unverified_rows),
        "verified_rule_coverage": len(verified_rows) / len(rules) if rules else 0.0,
        "exact_unit_set_rate": rate(verified_rows, "exact_unit_set"),
        "source_binding_rate": rate(verified_rows, "source_binding_valid"),
        "mean_bundle_recall": rate(verified_rows, "bundle_recall"),
        "fail_closed_unverified_rate": rate(unverified_rows, "fail_closed"),
        "latency_ms": {"median": statistics.median(latencies) if latencies else 0.0, "p95": _percentile(latencies, .95)},
        "verified_rows": verified_rows, "unverified_failures": [row for row in unverified_rows if not row["fail_closed"]],
    }


def load_index(path: Path) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    units = payload.get("units")
    sources = payload.get("sources")
    if payload.get("schema_version") != "1.0" or payload.get("collection") != "official_source" or not isinstance(units, list) or not isinstance(sources, list):
        raise ValueError("invalid official evidence index")
    source_hashes = {str(source.get("source_id")): str(source.get("sha256")) for source in sources}
    by_id: dict[str, dict[str, Any]] = {}
    trusted_units: list[dict[str, Any]] = []
    for unit in units:
        text = unit.get("text")
        if not isinstance(text, str) or hashlib.sha256(text.encode()).hexdigest() != unit.get("text_sha256"):
            raise ValueError("evidence text hash mismatch")
        trusted = dict(unit, status="verified", source_sha256=source_hashes.get(str(unit.get("source_id"))))
        by_id[str(unit["unit_id"])] = trusted
        trusted_units.append(trusted)
    return by_id, trusted_units


def _distractor(row: dict[str, Any], units: list[dict[str, Any]]) -> dict[str, Any]:
    relevant = set(row["relevant_unit_ids"])
    allowed = set(row["allowed_source_ids"])
    choices = [u for u in units if u.get("unit_id") not in relevant and u.get("source_id") not in allowed]
    if not choices:
        choices = [u for u in units if u.get("unit_id") not in relevant]
    if not choices:
        raise ValueError("index has no distractor evidence")
    return dict(sorted(choices, key=lambda u: str(u.get("unit_id")))[0], status="verified")


def _decision(unit: dict[str, Any]) -> dict[str, Any]:
    span = str(unit["text"]).strip()
    return {
        "is_real_issue": True,
        "evidence_unit_ids": [unit["unit_id"]],
        "supporting_spans": [span[: min(80, len(span))]],
        "evidence_entails_verdict": True,
        "applicability": True,
        "exceptions_checked": [],
        "counterevidence": [],
    }


def _percentile(values: list[float], q: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, max(0, int((len(ordered) - 1) * q)))] if ordered else 0.0


def evaluate(
    gt: dict[str, Any], by_id: dict[str, dict[str, Any]], units: list[dict[str, Any]],
    *, top_k: int = 3, repeats: int = 5,
    search: Callable[..., list[dict[str, Any]]] = rag_service.search_evidence,
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for query in gt["queries"]:
        missing = set(query["relevant_unit_ids"]) - set(by_id)
        if missing:
            raise ValueError(f"GT units absent from index: {sorted(missing)}")
        oracle = [by_id[u] for u in query["relevant_unit_ids"]]
        distractor = _distractor(query, units)
        latencies: list[float] = []
        retrieved: list[dict[str, Any]] = []
        for _ in range(repeats):
            started = time.perf_counter_ns()
            retrieved = search(query["rule_id"], query=query["query"], top_k=top_k)
            latencies.append((time.perf_counter_ns() - started) / 1_000_000)
        bundles = {
            "relevant": retrieved,
            "irrelevant": [distractor],
            "conflicting": oracle + [dict(distractor, status="conflict")],
            "oracle": oracle,
        }
        relevant_ids = set(query["relevant_unit_ids"])
        for condition, bundle in bundles.items():
            ids = [str(u.get("unit_id")) for u in bundle]
            hits = [i for i, uid in enumerate(ids[:top_k], 1) if uid in relevant_ids]
            wrong = sum(
                u.get("collection") != "official_source"
                or u.get("source_id") not in query["allowed_source_ids"]
                for u in bundle
            )
            cited = next((u for u in bundle if u.get("unit_id") in relevant_ids), bundle[0] if bundle else None)
            candidate = {"rule_id": query["rule_id"], "rag_route": {"decision": "retrieve"}, "rag_evidence_bundle": bundle}
            verdict = verify_citation_bound_decision(candidate, _decision(cited)) if cited else {"verified": False, "reason": "evidence_absent"}
            expected_accept = condition in {"relevant", "oracle"}
            rows.append({
                "query_id": query["query_id"], "condition": condition,
                "recall_at_k": len(hits) / len(relevant_ids),
                "reciprocal_rank": 1 / hits[0] if hits else 0.0,
                "bundle_recall": len(relevant_ids.intersection(ids)) / len(relevant_ids),
                "wrong_authority_rate": wrong / len(bundle) if bundle else 0.0,
                "citation_verified": bool(verdict["verified"]),
                "citation_expected_accept": expected_accept,
                "citation_verifier_correct": bool(verdict["verified"]) is expected_accept,
                "abstained": not bool(verdict["verified"]), "verifier_reason": verdict["reason"],
                "returned_unit_ids": ids,
            })
        rows[-4]["latency_ms"] = {"median": statistics.median(latencies), "p95": _percentile(latencies, .95), "samples": repeats}
    summaries: dict[str, Any] = {}
    for condition in CONDITIONS:
        selected = [r for r in rows if r["condition"] == condition]
        summaries[condition] = {
            name: sum(float(r[name]) for r in selected) / len(selected)
            for name in ("recall_at_k", "reciprocal_rank", "bundle_recall", "wrong_authority_rate", "citation_verified", "citation_verifier_correct", "abstained")
        }
    latency = [r["latency_ms"]["median"] for r in rows if "latency_ms" in r]
    return {
        "schema_version": SCHEMA_VERSION, "evaluation": "official_evidence_retrieval",
        "query_count": len(gt["queries"]), "top_k": top_k, "repeats": repeats,
        "conditions": list(CONDITIONS), "summary": summaries,
        "latency_ms": {"median_of_query_medians": statistics.median(latency) if latency else 0.0},
        "rows": rows,
    }


def main() -> int:
    backend = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ground-truth", type=Path, default=backend / "rag/evidence_query_gt.json")
    parser.add_argument("--index", type=Path, default=backend / "data/evidence/official_units.local.json")
    parser.add_argument("--audit", type=Path, default=backend / "mapping/rule_evidence_audit.json")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--top-k", type=int, default=3)
    parser.add_argument("--repeats", type=int, default=5)
    args = parser.parse_args()
    if args.top_k < 1 or args.repeats < 1:
        parser.error("top-k and repeats must be positive")
    os.environ["KCMVP_OFFICIAL_EVIDENCE_INDEX"] = str(args.index.resolve())
    rag_service._official_index_cache.clear()
    by_id, units = load_index(args.index)
    result = evaluate(load_ground_truth(args.ground_truth), by_id, units, top_k=args.top_k, repeats=args.repeats)
    result["semantic_scope"] = "human_reviewed_seed_only"
    result["mapping_integrity"] = evaluate_mapping_integrity(args.audit, by_id, repeats=args.repeats)
    rendered = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
