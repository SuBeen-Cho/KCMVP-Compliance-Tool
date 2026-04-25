"""
위반(Violation) 모델.
- L1/L3에서 탐지된 항목 + L3 근거가 붙은 최종 형태.
"""
from typing import Optional
from enum import Enum


class Severity(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# 예시 필드
# rule_id: str
# file: str
# line: int
# message: str
# severity: Severity
# snippet: Optional[str]
# evidence: Optional[str]   # L3 RAG 근거
# patch_ref: Optional[str]  # 패치 .md 경로
# source: str  # "l1" | "l3"
