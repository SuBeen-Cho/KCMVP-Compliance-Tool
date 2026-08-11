"""
FastAPI 앱 진입점.
- CORS, 라우터 등록, 분석 API 마운트.
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import analyze, health
from app.config import settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    """서버 시작 시 RAG 인덱스 사전 로딩 — 첫 분석 요청 지연 제거."""
    from app.services.evidence_mapping_validator import validate_evidence_mapping_registry
    from app.services.rag_service import preload as rag_preload
    validate_evidence_mapping_registry()
    rag_preload()
    yield


app = FastAPI(
    title="KCMVP 사전 적합성 검증 API",
    description="AI 기반 KCMVP 사전 점검 도구 백엔드",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router, prefix="/api", tags=["health"])
app.include_router(analyze.router, prefix="/api/analyze", tags=["analyze"])
