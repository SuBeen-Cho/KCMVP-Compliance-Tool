"""활성 규칙과 원문 evidence-unit 감사 레지스트리의 정합성을 검사한다."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml


_BACKEND = Path(__file__).resolve().parents[2]
_RULES = _BACKEND / "rules"
_AUDIT = _BACKEND / "mapping" / "rule_evidence_audit.json"
_ALLOWED = {"verified", "review_required", "unmapped", "retired"}
_NORMATIVE_AUTHORITIES = {
    "normative_standard", "normative_guidance", "normative_test_interface"
}


class EvidenceMappingValidationError(RuntimeError):
    """근거 레지스트리가 fail-closed 정책을 만족하지 못할 때 발생한다."""


def _active_rule_ids() -> set[str]:
    result: set[str] = set()
    for path in _RULES.rglob("*.yaml"):
        payload = yaml.safe_load(path.read_text(encoding="utf-8")) or []
        rows = payload.get("rules", []) if isinstance(payload, dict) else payload
        for row in rows:
            if isinstance(row, dict) and row.get("id"):
                result.add(str(row["id"]))
    return result


def validate_evidence_mapping_registry() -> dict[str, Any]:
    """
    활성 규칙 100%가 명시적 상태를 갖는지 검사한다.

    ``review_required``와 ``unmapped``는 허용하되 RAG 근거로 승격하지
    않는다. ``verified``는 권위·역할·locator·hash·evidence unit이 모두
    있어야 한다.
    """
    try:
        payload = json.loads(_AUDIT.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise EvidenceMappingValidationError(f"evidence audit load failed: {exc}") from exc
    rows = payload.get("rules")
    if payload.get("policy") != "fail_closed" or not isinstance(rows, dict):
        raise EvidenceMappingValidationError("evidence audit must declare fail_closed policy")

    active = _active_rule_ids()
    recorded = set(rows)
    if active != recorded:
        raise EvidenceMappingValidationError(
            f"active/audit mismatch missing={sorted(active-recorded)} extra={sorted(recorded-active)}"
        )

    for rule_id, row in rows.items():
        if not isinstance(row, dict):
            raise EvidenceMappingValidationError(f"{rule_id}: audit row must be an object")
        status = row.get("status")
        if status not in _ALLOWED:
            raise EvidenceMappingValidationError(f"{rule_id}: invalid status {status!r}")
        units = row.get("evidence_unit_ids")
        if not isinstance(units, list):
            raise EvidenceMappingValidationError(f"{rule_id}: evidence_unit_ids must be a list")
        if status == "verified":
            required = ("source_locator", "source_sha256", "applicability")
            if any(not row.get(field) for field in required) or not units:
                raise EvidenceMappingValidationError(
                    f"{rule_id}: verified mapping lacks locator/hash/applicability/evidence units"
                )
            if row.get("authority_class") not in _NORMATIVE_AUTHORITIES:
                raise EvidenceMappingValidationError(f"{rule_id}: authority is not normative")
            if row.get("evidence_role") != "normative_requirement":
                raise EvidenceMappingValidationError(f"{rule_id}: evidence role is not normative")
            if row.get("review_required"):
                raise EvidenceMappingValidationError(f"{rule_id}: verified mapping still needs review")
            locator = row.get("source_locator")
            applicability = row.get("applicability")
            source_hash = row.get("source_sha256")
            if not isinstance(locator, dict) or not locator.get("source_id"):
                raise EvidenceMappingValidationError(f"{rule_id}: verified locator lacks source_id")
            if not isinstance(applicability, dict):
                raise EvidenceMappingValidationError(f"{rule_id}: applicability must be an object")
            if not isinstance(source_hash, str) or re.fullmatch(r"[0-9a-f]{64}", source_hash) is None:
                raise EvidenceMappingValidationError(f"{rule_id}: invalid source_sha256")
            if len(units) != len(set(units)) or any(
                not isinstance(unit, str) or not unit.startswith(f"{locator['source_id']}:")
                for unit in units
            ):
                raise EvidenceMappingValidationError(
                    f"{rule_id}: evidence units must be unique and match locator source_id"
                )
        elif units:
            raise EvidenceMappingValidationError(
                f"{rule_id}: unverified mapping must not expose evidence units"
            )
    return {
        "active_rule_count": len(active),
        "verified_count": sum(row["status"] == "verified" for row in rows.values()),
        "review_required_count": sum(row["status"] != "verified" for row in rows.values()),
    }
