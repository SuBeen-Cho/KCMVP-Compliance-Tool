"""
분석 API 요청/응답 스키마.
"""
from pydantic import BaseModel
from typing import Optional, List


class AnalyzeCreate(BaseModel):
    """분석 생성 요청 (JSON body 대안)."""
    source: Optional[str] = None
    algorithm: Optional[str] = None
    mode: Optional[str] = None


class AnalyzeResponse(BaseModel):
    """분석 생성 응답."""
    job_id: str
    status: str


class AnalyzeStatusResponse(BaseModel):
    """분석 상태 응답."""
    job_id: str
    status: str
    progress: int
    current_step: Optional[str] = None
    error_message: Optional[str] = None
