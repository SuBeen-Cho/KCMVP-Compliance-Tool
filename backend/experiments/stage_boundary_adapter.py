"""Offline exporter for the production L2 to L3 boundary."""
from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path
from typing import Any

from app.services.analysis_stage_contract import ai_is_authorized, close_for_l3
from app.services.llm.candidate_selector import _select_l3_candidates
from app.services.rag_grounding import is_deterministic_verified_bypass, route_rag
from app.services.rag_service import run_l2_rag_context
from app.services.rule_engine_service import _apply_rule_to_file, load_ruleset
from experiments.staged_pipeline_eval import validate


class BoundaryInputError(ValueError):
    pass


def _candidate(spec: dict[str, Any], root: Path, rules_root: Path) -> dict[str, Any]:
    allowed = {"case_id", "mode", "candidate", "scanner_fixture"}
    if not isinstance(spec, dict) or set(spec) - allowed:
        raise BoundaryInputError("case has unknown fields")
    if not isinstance(spec.get("case_id"), str) or not spec["case_id"]:
        raise BoundaryInputError("case_id is required")
    if spec.get("mode", "production") not in {"production", "controlled_ablation"}:
        raise BoundaryInputError("unsupported mode")
    if ("candidate" in spec) == ("scanner_fixture" in spec):
        raise BoundaryInputError("exactly one candidate source is required")
    if "candidate" in spec:
        if not isinstance(spec["candidate"], dict):
            raise BoundaryInputError("candidate must be an object")
        return dict(spec["candidate"])
    fixture = spec["scanner_fixture"]
    required = {"group", "filename", "rule_id", "source"}
    if not isinstance(fixture, dict) or set(fixture) != required or not all(
        isinstance(fixture[key], str) and fixture[key] for key in required
    ):
        raise BoundaryInputError("invalid scanner_fixture")
    rule = next((row for row in load_ruleset(rules_root, "mode", fixture["group"])
                 if row["id"] == fixture["rule_id"]), None)
    if rule is None:
        raise BoundaryInputError("scanner fixture rule not found")
    path = root / fixture["filename"]
    path.write_text(fixture["source"], encoding="utf-8")
    rows = _apply_rule_to_file(path, fixture["source"], rule, root)
    if len(rows) != 1:
        raise BoundaryInputError("scanner fixture must produce exactly one candidate")
    rows[0]["detection_semantics"] = "prohibited_presence"
    return rows[0]


def _boundary_state(candidate: dict[str, Any]) -> tuple[str, str]:
    closed = close_for_l3(candidate)
    if closed.get("disposition") == "deterministic" and closed.get("ai_need") == "not_required":
        return "deterministic", "selected_deterministic"
    if not _select_l3_candidates([closed]):
        return "deterministic", "selected_deterministic"
    claimed = closed.get("rag_route") or {}
    recomputed = route_rag({key: value for key, value in closed.items() if key != "rag_route"})
    authorized = (ai_is_authorized(closed)
                  and claimed.get("decision") == recomputed.get("decision") == "retrieve"
                  and not is_deterministic_verified_bypass(closed))
    return ("retrieval", "selected_retrieve") if authorized else ("abstain", "unresolved")


def export(payload: Any, work_dir: Path, rules_root: Path) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != {"schema_version", "dataset", "cases"}:
        raise BoundaryInputError("closed root object required")
    if payload["schema_version"] != "1.0" or not isinstance(payload["dataset"], str) or not payload["dataset"]:
        raise BoundaryInputError("invalid fixture metadata")
    cases = payload["cases"]
    if not isinstance(cases, list) or not cases:
        raise BoundaryInputError("non-empty cases required")
    output, seen = [], set()
    prior_ablation = os.environ.get("ABLATION_NO_RAG")
    try:
        for spec in cases:
            if not isinstance(spec, dict) or spec.get("case_id") in seen:
                raise BoundaryInputError("invalid or duplicate case_id")
            seen.add(spec.get("case_id"))
            candidate = _candidate(spec, work_dir, rules_root)
            if spec.get("mode", "production") == "controlled_ablation":
                os.environ["ABLATION_NO_RAG"] = "1"
            else:
                os.environ.pop("ABLATION_NO_RAG", None)
            started = time.perf_counter()
            routed = run_l2_rag_context([candidate])[0]
            stage, partition = _boundary_state(routed)
            elapsed = (time.perf_counter() - started) * 1000
            ids = [str(unit["unit_id"]) for unit in routed.get("rag_evidence_bundle", [])]
            verified = bool(ids)
            output.append({
                "case_id": spec["case_id"], "stage": stage, "route_partition": partition,
                "integrity_gate": "pass", "evidence_required": stage != "deterministic",
                "official_evidence_ids": ids,
                "verifier": "pass" if verified else ("not_applicable" if stage == "deterministic" else "fail"),
                "final_disposition": "reject" if stage == "deterministic" else "abstain",
                # Only a completed deterministic bypass is an avoided call.  A
                # retrieval-ready case is deferred, not an avoidance success.
                "baseline_llm_calls": 1 if stage == "deterministic" else 0,
                "actual_llm_calls": 0, "input_tokens": 0, "output_tokens": 0,
                "latency_ms": elapsed, "cost_usd": 0.0,
            })
    finally:
        if prior_ablation is None:
            os.environ.pop("ABLATION_NO_RAG", None)
        else:
            os.environ["ABLATION_NO_RAG"] = prior_ablation
    result = {
        "schema_version": "1.0",
        "run": {"system": "production-l2-l3-boundary", "dataset": payload["dataset"],
                "notes": "offline probe; retrieval=AI authorized but not invoked"},
        "pricing": {"input_usd_per_million": 0.0, "output_usd_per_million": 0.0},
        "cases": output,
    }
    return validate(result)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("fixture", type=Path)
    parser.add_argument("-o", "--output", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--rules-root", type=Path, default=Path(__file__).resolve().parents[1] / "rules")
    args = parser.parse_args()
    args.work_dir.mkdir(parents=True, exist_ok=True)
    result = export(json.loads(args.fixture.read_text(encoding="utf-8")), args.work_dir, args.rules_root)
    args.output.write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
