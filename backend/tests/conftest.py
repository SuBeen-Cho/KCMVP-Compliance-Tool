"""
KCMVP 테스트 공통 fixture.

사용법:
    pytest tests/ -v          # 전체 실행
    pytest tests/ -m tier1    # Tier 1만 실행
"""

import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

# backend/ 를 sys.path에 추가하여 app.services 임포트 가능
_BACKEND = Path(__file__).resolve().parent.parent
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
RULES_DIR = _BACKEND / "rules"


# ──────────────────────────────────────────────────────────────
# AST 체커 직접 호출 fixture
# ──────────────────────────────────────────────────────────────

@pytest.fixture
def check_rule():
    """rule_id + C 코드 문자열 → 위반 리스트 반환.

    Returns:
        callable(rule_id, code, filename, symbol_graph) -> Optional[List[Dict]]
        - None: 파싱 실패 또는 미구현 규칙
        - []: 위반 없음 (정상)
        - [{line, message, ...}, ...]: 위반 목록
    """
    from app.services.ast_checker_service import check_rule as _check

    def _wrapper(
        rule_id: str,
        code: str,
        filename: str = "test.c",
        symbol_graph: Optional[Dict[str, Any]] = None,
    ) -> Optional[List[Dict[str, Any]]]:
        return _check(
            rule_id=rule_id,
            content=code,
            filename=filename,
            symbol_graph=symbol_graph or {},
        )

    return _wrapper


# ──────────────────────────────────────────────────────────────
# C fixture 파일 로더
# ──────────────────────────────────────────────────────────────

@pytest.fixture
def load_fixture():
    """fixtures/ 디렉토리에서 C 파일 내용을 읽어 반환."""

    def _load(name: str) -> str:
        path = FIXTURES_DIR / name
        assert path.exists(), f"fixture 파일 없음: {path}"
        return path.read_text(encoding="utf-8")

    return _load


# ──────────────────────────────────────────────────────────────
# YAML 룰 로더
# ──────────────────────────────────────────────────────────────

@pytest.fixture
def load_rule():
    """rule_id로 YAML 룰 dict를 찾아 반환."""
    import yaml

    _cache: Dict[str, Dict] = {}

    def _load(rule_id: str) -> Dict[str, Any]:
        if rule_id in _cache:
            return _cache[rule_id]

        for yaml_file in RULES_DIR.rglob("*.yaml"):
            with open(yaml_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            for rule in (data or {}).get("rules", []):
                rid = rule.get("id", "")
                _cache[rid] = rule
                if rid == rule_id:
                    return rule

        raise KeyError(f"규칙 {rule_id} 을(를) YAML에서 찾을 수 없음")

    return _load


# ──────────────────────────────────────────────────────────────
# 룰 엔진 regex 매칭 헬퍼
# ──────────────────────────────────────────────────────────────

@pytest.fixture
def match_fallback():
    """fallback_pattern regex를 코드에 적용하여 매칭 결과 반환."""
    import re

    def _match(pattern: str, code: str) -> List[re.Match]:
        return list(re.finditer(pattern, code))

    return _match
