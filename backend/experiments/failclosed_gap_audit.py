"""Build a closed, reproducible taxonomy for fail-closed active rules."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

GAPS = {"authority_gap", "detector_scope", "applicability_gap", "exact_locator_gap"}


def _rules(rule_root: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for path in sorted(rule_root.rglob("*.yaml")):
        payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        rows = payload.get("rules", []) if isinstance(payload, dict) else payload
        for row in rows:
            if isinstance(row, dict) and row.get("id"):
                result[str(row["id"])] = row
    return result


def _classify(rule_id: str, rule: dict[str, Any]) -> tuple[str, str]:
    name = str(rule.get("name") or "")
    ref = str(rule.get("kcmvp_ref") or "")
    pattern_type = str(rule.get("pattern_type") or "unknown")
    if any(token in name.upper() for token in ("MCT", "MMT", "KAT", "REQUEST", "RESPONSE", "MOVS")):
        return "applicability_gap", "validation/test artifact applicability must be established per occurrence"
    if any(token in ref for token in ("논문", "소스코드 사용 매뉴얼", "KS X ISO/IEC")):
        return "authority_gap", "the seven-source index lacks a directly bound normative source for the complete claim"
    if pattern_type in {"missing", "regex", "semantic"}:
        return "detector_scope", "absence or lexical evidence cannot prove all equivalent implementations and project boundaries"
    return "exact_locator_gap", "related official material exists but complete claim-to-unit entailment is not yet sealed"


def build(rule_root: Path, audit_path: Path) -> dict[str, Any]:
    rules = _rules(rule_root)
    audit_bytes = audit_path.read_bytes()
    audit = json.loads(audit_bytes)["rules"]
    rows: list[dict[str, Any]] = []
    for rule_id, state in sorted(audit.items()):
        if state.get("status") == "verified":
            continue
        rule = rules[rule_id]
        gap, reason = _classify(rule_id, rule)
        rows.append({
            "rule_id": rule_id, "category": str(rule.get("category") or "unspecified"),
            "pattern_type": str(rule.get("pattern_type") or "unknown"),
            "authority_gap": gap == "authority_gap", "detector_scope": gap == "detector_scope",
            "applicability_gap": gap == "applicability_gap", "exact_locator_gap": gap == "exact_locator_gap",
            "primary_gap": gap, "decision": "remain_fail_closed", "reason": reason,
        })
    counts = Counter(row["primary_gap"] for row in rows)
    return {
        "schema_version": "1.0", "collection": "failclosed_gap_audit",
        "source_audit_sha256": hashlib.sha256(audit_bytes).hexdigest(),
        "failclosed_rule_count": len(rows), "gap_counts": {key: counts.get(key, 0) for key in sorted(GAPS)},
        "rules": rows,
    }


def validate(payload: dict[str, Any]) -> None:
    if set(payload) != {"schema_version", "collection", "source_audit_sha256", "failclosed_rule_count", "gap_counts", "rules"}:
        raise ValueError("open failclosed audit root schema")
    if payload.get("schema_version") != "1.0" or payload.get("collection") != "failclosed_gap_audit":
        raise ValueError("invalid failclosed audit")
    for row in payload["rules"]:
        flags = [key for key in GAPS if row.get(key) is True]
        if len(flags) != 1 or flags[0] != row.get("primary_gap") or row.get("decision") != "remain_fail_closed":
            raise ValueError("each rule must have exactly one fail-closed primary gap")


def main() -> int:
    backend = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules", type=Path, default=backend / "rules")
    parser.add_argument("--audit", type=Path, default=backend / "mapping/rule_evidence_audit.json")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    payload = build(args.rules, args.audit)
    validate(payload)
    rendered = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
