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

# 로드 캐시 (싱글턴)
_mapping: Dict[str, Any] = {}


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


def get_guideline_path(rule_id: str, *, include_retired: bool = False) -> Optional[Path]:
    """
    rule_id에 대응하는 guideline MD 파일의 절대경로 반환.

    탐색 순서:
      1. mapping의 item_ids → 실제 ruleset/ 폴더에서 item_id 패턴 검색
      2. mapping의 guideline_file → backend/ 기준 상대경로 직접 조회
    """
    info = lookup(rule_id)
    provenance = info.get("provenance") or {}
    if provenance.get("status") == "retired" and not include_retired:
        return None
    project_root = _MAPPING_PATH.parent.parent.parent  # Kcmvp_main/

    # 1. item_ids 기반으로 실제 DB에서 파일 탐색
    item_ids = info.get("item_ids", [])
    db_dirs = [
        project_root / "ruleset" / "docs",
        project_root / "ruleset" / "LEA",
    ]
    for item_id in item_ids:
        # item_id 형식: "AS02.09" → 파일명에 "AS02_09" 포함 패턴으로 검색
        pattern = item_id.replace(".", "_")
        for db_dir in db_dirs:
            if not db_dir.exists():
                continue
            matches = list(db_dir.rglob(f"*{pattern}*.md")) + list(db_dir.rglob(f"*{pattern}*.MD"))
            if matches:
                return matches[0]  # 첫 번째 매칭 파일 반환

    # 2. guideline_file 상대경로 직접 조회 (기존 방식, fallback)
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


def is_audited_active_normative_rule(rule_id: str) -> bool:
    """provenance 감사가 완료된 부분집합의 활성 규범 규칙인지 판단한다."""
    provenance = get_provenance(rule_id)
    return (
        provenance.get("status") == "active"
        and provenance.get("evidence_role") == "normative_requirement"
    )


def list_all_rule_ids() -> List[str]:
    """매핑된 모든 rule_id 목록 반환."""
    _load()
    return list(_mapping.keys())


def reload() -> None:
    """매핑 캐시 강제 재로드 (테스트/개발용)."""
    global _mapping
    _mapping = {}
    _load()
