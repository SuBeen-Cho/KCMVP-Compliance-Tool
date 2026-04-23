"""
애플리케이션 공통 예외.
- 분석 실패, 룰 로드 실패 등.
"""
from fastapi import HTTPException


class KCMVPBaseException(Exception):
    """KCMVP 도구 기본 예외."""
    pass


class AnalysisNotFoundError(KCMVPBaseException):
    """분석 job을 찾을 수 없음."""
    pass


class RuleLoadError(KCMVPBaseException):
    """룰셋 로드 실패."""
    pass


class PreprocessError(KCMVPBaseException):
    """전처리(AST 등) 실패."""
    pass


def raise_404_job(job_id: str):
    raise HTTPException(status_code=404, detail=f"Job not found: {job_id}")
