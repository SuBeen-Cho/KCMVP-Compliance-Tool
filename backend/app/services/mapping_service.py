"""
MappingService: rule_id → KCMVP 가이드라인 조항 매핑.

Direct-RAG 방식의 핵심 Bridge:
  rule_id → { item_ids, kcmvp_ref, l3_search_query, guideline_file }

매핑 파일: backend/mapping/rule_to_guideline.json
"""

import json
from pathlib import Path
from typing import Dict, Any, List, Optional

_MAPPING_PATH = Path(__file__).resolve().parent.parent.parent / "mapping" / "rule_to_guideline.json"
_EVIDENCE_AUDIT_PATH = _MAPPING_PATH.with_name("rule_evidence_audit.json")

# 로드 캐시 (싱글턴)
_mapping: Dict[str, Any] = {}
_evidence_audit: Dict[str, Any] = {}


def _load() -> None:
    global _mapping
    if _mapping:
        return
    if not _MAPPING_PATH.exists():
        _mapping = {}
        return
    try:
        data = json.loads(_MAPPING_PATH.read_text(encoding="utf-8"))
        # _comment 키 제거
        _mapping = {k: v for k, v in data.items() if not k.startswith("_")}
    except Exception as e:
        print(f"[Mapping] rule_to_guideline.json 로드 실패: {e}")
        _mapping = {}


def lookup(rule_id: str) -> Dict[str, Any]:
    """
    rule_id → 매핑 정보 반환.
    없으면 빈 dict 반환.

    반환 형식:
    {
        "item_ids": ["AS09.29"],
        "kcmvp_ref": "KS X ISO/IEC 19790:2015 §7.9",
        "l3_search_query": "잔존 정보 제거 제로화 SSP",
        "l3_required": false,
        "guideline_file": "guidelines/COM-001_zeroization.md"
    }
    """
    _load()
    return _mapping.get(rule_id, {})


def lookup_many(rule_ids: List[str]) -> Dict[str, Dict[str, Any]]:
    """복수 rule_id 일괄 조회."""
    _load()
    return {rid: _mapping.get(rid, {}) for rid in rule_ids}


def get_guideline_path(
    rule_id: str,
    *,
    include_retired: bool = False,
    allow_unverified_legacy: bool = False,
) -> Optional[Path]:
    """
    rule_id에 대응하는 guideline MD 파일의 절대경로 반환.

    guideline_file에 기록된 명시적 경로만 조회한다. item_id를 파일명에
    부분 대입하여 첫 번째 파일을 선택하던 legacy heuristic은 잘못된 근거를
    주입할 수 있어 사용하지 않는다.
    """
    info = lookup(rule_id)
    provenance = info.get("provenance") or {}
    if provenance.get("status") == "retired" and not include_retired:
        return None
    # A verified official evidence mapping does not promote the legacy Markdown
    # into an official source. Author commentary always needs an explicit opt-in.
    if provenance.get("status") != "retired" and not allow_unverified_legacy:
        return None
    project_root = _MAPPING_PATH.parent.parent.parent  # Kcmvp_main/

    # guideline_file 상대경로를 정확히 조회
    rel = info.get("guideline_file")
    if rel:
        candidates = (
            project_root / rel,
            _MAPPING_PATH.parent.parent / rel,
        )
        for path in candidates:
            if path.exists():
                return path

    return None


def get_search_query(rule_id: str) -> str:
    """L3 RAG 검색에 사용할 쿼리 문자열 반환. 없으면 rule_id 반환."""
    info = lookup(rule_id)
    return info.get("l3_search_query") or rule_id


def is_l3_required(rule_id: str) -> bool:
    """해당 rule_id가 L3 판정을 필요로 하는지 여부."""
    info = lookup(rule_id)
    return bool(info.get("l3_required", False))


def get_provenance(rule_id: str) -> Dict[str, Any]:
    """규칙 근거의 권위, 적용 범위 및 비추론 한계를 반환한다."""
    value = lookup(rule_id).get("provenance", {})
    return dict(value) if isinstance(value, dict) else {}


def _load_evidence_audit() -> None:
    global _evidence_audit
    if _evidence_audit:
        return
    try:
        payload = json.loads(_EVIDENCE_AUDIT_PATH.read_text(encoding="utf-8"))
        _evidence_audit = dict(payload.get("rules") or {})
    except (OSError, ValueError, TypeError):
        _evidence_audit = {}


def get_evidence_audit(rule_id: str) -> Dict[str, Any]:
    """rule→원문 감사 상태를 반환한다. 미확인은 암묵적 승인하지 않는다."""
    _load_evidence_audit()
    value = _evidence_audit.get(rule_id)
    if not isinstance(value, dict):
        return {
            "status": "unmapped",
            "review_required": True,
            "evidence_unit_ids": [],
        }
    return dict(value)


def has_verified_normative_evidence(rule_id: str) -> bool:
    """실제 원문 evidence unit에 규범적으로 연결된 활성 규칙만 True다."""
    audit = get_evidence_audit(rule_id)
    return (
        audit.get("status") == "verified"
        and audit.get("authority_class") in {
            "normative_standard", "normative_guidance", "normative_test_interface"
        }
        and audit.get("evidence_role") == "normative_requirement"
        and bool(audit.get("evidence_unit_ids"))
        and not audit.get("review_required", False)
    )


def is_audited_active_normative_rule(rule_id: str) -> bool:
    """원문 evidence unit까지 검증된 활성 규범 규칙인지 판단한다."""
    provenance = get_provenance(rule_id)
    return (
        provenance.get("status") == "active"
        and provenance.get("evidence_role") == "normative_requirement"
        and has_verified_normative_evidence(rule_id)
    )


def list_all_rule_ids() -> List[str]:
    """매핑된 모든 rule_id 목록 반환."""
    _load()
    return list(_mapping.keys())


def reload() -> None:
    """매핑 캐시 강제 재로드 (테스트/개발용)."""
    global _mapping, _evidence_audit
    _mapping = {}
    _evidence_audit = {}
    _load()
