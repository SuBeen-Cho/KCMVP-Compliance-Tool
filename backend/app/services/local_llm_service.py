"""
LocalLLMService: 로컬 LLM 추론 서비스.

두 가지 패턴 지원:

Pattern A (기본): llama.cpp HTTP 서버 (OpenAI 호환 API)
  - 별도 서버 실행 필요:
      llama-server -m /path/to/model.gguf --port 8080 --host 0.0.0.0
  - 환경 변수: LOCAL_LLM_BASE_URL=http://localhost:8080/v1
               LOCAL_LLM_MODEL=kcmvp-judge (서버에 로드된 모델명)

Pattern B (선택): HuggingFace transformers (MPS/CUDA/CPU)
  - 환경 변수: LOCAL_LLM_HF_MODEL=/path/to/hf-model (또는 HF Hub 모델 ID)
  - pip install transformers torch accelerate

사용 조건:
  - config.L2_PROVIDER = "local" 시 llm_service에서 이 모듈 사용
  - Pattern A 우선; HF_MODEL 설정 시 Pattern B 활성화
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from app.config import settings

# ─────────────────────────────────────────────────────────────────
# Pattern B: transformers 로컬 모델 (지연 초기화)
# ─────────────────────────────────────────────────────────────────
_hf_pipe = None
_hf_loaded = False


def _load_hf_pipeline():
    """HuggingFace pipeline 지연 로드. 실패 시 None 반환."""
    global _hf_pipe, _hf_loaded
    if _hf_loaded:
        return _hf_pipe
    _hf_loaded = True

    model_id = settings.LOCAL_LLM_HF_MODEL
    if not model_id:
        return None

    try:
        import torch
        from transformers import pipeline, AutoTokenizer, AutoModelForCausalLM

        # 디바이스 자동 선택: MPS(Apple Silicon) > CUDA > CPU
        if torch.backends.mps.is_available():
            device = "mps"
        elif torch.cuda.is_available():
            device = "cuda"
        else:
            device = "cpu"

        print(f"[LocalLLM] HF 모델 로드 중: {model_id} (device={device})")
        tokenizer = AutoTokenizer.from_pretrained(model_id)
        model = AutoModelForCausalLM.from_pretrained(
            model_id,
            torch_dtype=torch.float16 if device != "cpu" else torch.float32,
            device_map=device if device != "cpu" else None,
        )
        _hf_pipe = pipeline(
            "text-generation",
            model=model,
            tokenizer=tokenizer,
            device=None if device != "cpu" else -1,
            max_new_tokens=settings.LOCAL_LLM_MAX_TOKENS,
            temperature=settings.LOCAL_LLM_TEMPERATURE,
            do_sample=settings.LOCAL_LLM_TEMPERATURE > 0,
        )
        print(f"[LocalLLM] HF 모델 로드 완료: {model_id}")
        return _hf_pipe
    except ImportError:
        print("[LocalLLM] transformers/torch 미설치 → Pattern A (HTTP) 사용")
        return None
    except Exception as e:
        print(f"[LocalLLM] HF 모델 로드 실패: {e}")
        return None


# ─────────────────────────────────────────────────────────────────
# Pattern A: llama.cpp HTTP 서버 호출
# ─────────────────────────────────────────────────────────────────
def _call_local_http(prompt: str) -> Optional[str]:
    """
    OpenAI 호환 /v1/chat/completions 엔드포인트 호출.
    llama-server, ollama, LM Studio 등 모두 지원.
    """
    try:
        import urllib.request

        url = f"{settings.LOCAL_LLM_BASE_URL.rstrip('/')}/chat/completions"
        payload = json.dumps({
            "model": settings.LOCAL_LLM_MODEL,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": settings.LOCAL_LLM_MAX_TOKENS,
            "temperature": settings.LOCAL_LLM_TEMPERATURE,
            "stream": False,
        }).encode("utf-8")

        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=settings.LOCAL_LLM_TIMEOUT) as resp:
            body = json.loads(resp.read().decode("utf-8"))

        # OpenAI 응답 형식
        choices = body.get("choices") or []
        if choices:
            msg = choices[0].get("message") or {}
            content = msg.get("content") or ""
            if content:
                return content

        print(f"[LocalLLM] HTTP 응답 파싱 실패: {body}")
        return None

    except Exception as e:
        print(f"[LocalLLM] HTTP 호출 실패: {e}")
        return None


# ─────────────────────────────────────────────────────────────────
# Pattern B: transformers pipeline 호출
# ─────────────────────────────────────────────────────────────────
def _call_local_hf(prompt: str) -> Optional[str]:
    """HuggingFace pipeline 호출."""
    pipe = _load_hf_pipeline()
    if pipe is None:
        return None
    try:
        outputs = pipe(prompt)
        if outputs and isinstance(outputs, list):
            gen_text = outputs[0].get("generated_text", "")
            # 입력 프롬프트 이후 생성된 텍스트만 추출
            if gen_text.startswith(prompt):
                gen_text = gen_text[len(prompt):]
            return gen_text.strip() if gen_text.strip() else None
        return None
    except Exception as e:
        print(f"[LocalLLM] HF 추론 실패: {e}")
        return None


# ─────────────────────────────────────────────────────────────────
# 통합 진입점
# ─────────────────────────────────────────────────────────────────
def call_local(prompt: str) -> Optional[str]:
    """
    로컬 LLM 호출 통합 함수.

    우선순위:
      1. Pattern B (HF_MODEL 설정 시) — transformers 직접 추론
      2. Pattern A (기본) — llama.cpp HTTP 서버

    Returns
    -------
    str | None : 생성된 텍스트, 실패 시 None
    """
    # Pattern B 우선 (HF 모델 경로 설정된 경우)
    if settings.LOCAL_LLM_HF_MODEL:
        result = _call_local_hf(prompt)
        if result is not None:
            return result
        # HF 실패 시 Pattern A로 fallback
        print("[LocalLLM] HF 실패 → HTTP 서버로 fallback")

    # Pattern A: HTTP 서버
    return _call_local_http(prompt)


def is_available() -> bool:
    """
    로컬 LLM 서버 가용성 확인.
    HF 모델 또는 HTTP 서버가 응답하는지 ping 테스트.
    """
    if settings.LOCAL_LLM_HF_MODEL:
        return True  # HF 모델은 설정만 있으면 가용 (로드 실패 시 HTTP fallback)

    try:
        import urllib.request
        url = f"{settings.LOCAL_LLM_BASE_URL.rstrip('/')}/models"
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status == 200
    except Exception:
        return False


def get_provider_info() -> Dict[str, Any]:
    """현재 로컬 LLM 설정 정보 반환."""
    return {
        "provider": "local",
        "pattern": "B (HuggingFace)" if settings.LOCAL_LLM_HF_MODEL else "A (llama.cpp HTTP)",
        "base_url": settings.LOCAL_LLM_BASE_URL if not settings.LOCAL_LLM_HF_MODEL else None,
        "model": settings.LOCAL_LLM_HF_MODEL or settings.LOCAL_LLM_MODEL,
        "available": is_available(),
    }
