"""
보고서·위반·패치 스키마.
"""
from pydantic import BaseModel
from typing import Optional, List


class ViolationItem(BaseModel):
    """단일 위반 항목."""
    rule_id: str
    file: str
    line: int
    message: str
    severity: str
    snippet: Optional[str] = None
    evidence: Optional[str] = None
    patch_ref: Optional[str] = None
    source: Optional[str] = None  # l1 | l3


class ReportSummary(BaseModel):
    """보고서 요약."""
    total: int
    high: int
    medium: int
    low: int


class ReportResponse(BaseModel):
    """최종 분석 보고서."""
    job_id: str
    summary: ReportSummary
    violations: List[ViolationItem]


class PatchItem(BaseModel):
    """패치 파일 한 건."""
    rule_id: str
    file: str
    line: int
    content: str  # .md 본문
