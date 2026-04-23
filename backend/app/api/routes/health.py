"""
헬스 체크 엔드포인트.
"""
from fastapi import APIRouter

router = APIRouter()


@router.get("/health")
def health():
    """서비스 상태 확인."""
    return {"status": "ok", "service": "kcmvp-precheck"}
