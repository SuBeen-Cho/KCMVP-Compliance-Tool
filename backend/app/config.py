"""
애플리케이션 설정.
- 환경 변수 기반 (pydantic-settings).
- .env 는 backend/.env 를 사용 (실행 경로와 무관).
"""
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List

# backend/.env 를 항상 사용 (uvicorn 실행 디렉터리와 무관)
_BACKEND_DIR = Path(__file__).resolve().parent.parent
_ENV_FILE = _BACKEND_DIR / ".env"


class Settings(BaseSettings):
    """앱 전역 설정."""

    # API
    API_V1_PREFIX: str = "/api"

    # CORS
    CORS_ORIGINS: List[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]

    # 스토리지: job별 소스/AST/보고서 저장 경로
    STORAGE_ROOT: str = "./storage"
    JOB_DATA_DIR: str = "jobs"

    # Redis / Celery
    REDIS_URL: str = "redis://localhost:6379/0"
    CELERY_BROKER_URL: str = "redis://localhost:6379/0"

    # LLM (OpenAI - 사용 시 .env에 OPENAI_API_KEY 설정)
    OPENAI_API_KEY: str = ""
    LLM_MODEL_L3: str = "gpt-4o"
    LLM_MODEL_PATCH: str = "gpt-4o"

    # Google Gemini (AI Studio) - L3용, .env에 GOOGLE_API_KEY 설정
    GOOGLE_API_KEY: str = ""
    GEMINI_L3_MODEL: str = "gemini-2.5-flash-lite"

    # L3 제공자 선택: "gemini" (기본) 또는 "local"
    # local 선택 시 LOCAL_LLM_BASE_URL의 OpenAI 호환 서버 사용
    L3_PROVIDER: str = "gemini"

    # 로컬 LLM (llama.cpp 서버 또는 OpenAI 호환 API)
    # Pattern A: llama-server -m model.gguf --port 8080 --host 0.0.0.0
    LOCAL_LLM_BASE_URL: str = "http://localhost:8080/v1"
    LOCAL_LLM_MODEL: str = "kcmvp-judge"
    LOCAL_LLM_MAX_TOKENS: int = 1024
    LOCAL_LLM_TEMPERATURE: float = 0.1
    LOCAL_LLM_TIMEOUT: int = 120

    # HuggingFace 로컬 모델 (Pattern B: transformers)
    # LOCAL_LLM_HF_MODEL=./models/kcmvp-judge  설정 시 transformers로 직접 로드
    LOCAL_LLM_HF_MODEL: str = ""

    # RAG
    RAG_USE_CHROMA: bool = False          # true → ChromaDB 벡터 검색 활성화
    RAG_EMBEDDING_MODEL: str = "BAAI/bge-m3"
    RAG_TOP_K: int = 5
    CHROMA_PERSIST_DIR: str = "./data/chroma"

    model_config = SettingsConfigDict(env_file=str(_ENV_FILE), extra="ignore")


settings = Settings()
