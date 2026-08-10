"""Gemini/OpenAI/Local LLM 호출 + JSON 파싱 + 재시도 로직."""

import json
import os
import re
import time
from typing import Any, Dict, List, Optional, Union

try:
    import google.genai as genai
    _HAS_GOOGLE_GENAI = True
except ImportError:
    genai = None  # type: ignore
    _HAS_GOOGLE_GENAI = False

from app.config import settings

GEMINI_L3_MODEL = settings.GEMINI_L3_MODEL
GOOGLE_API_KEY = settings.GOOGLE_API_KEY
L3_PROVIDER = settings.L3_PROVIDER  # "gemini" | "openai" | "local"

# OpenAI provider (Phase 3)
OPENAI_API_KEY = settings.OPENAI_API_KEY
OPENAI_L3_MODEL = settings.LLM_MODEL_L3      # default: "gpt-4o"
OPENAI_PATCH_MODEL = settings.LLM_MODEL_PATCH # default: "gpt-4o"


# ─────────────────────────────────────────────────────────────────
# 토큰 사용량 추적 (평가 전용)
# ─────────────────────────────────────────────────────────────────
_token_counter: Dict[str, int] = {"input": 0, "output": 0, "calls": 0}


def reset_token_usage() -> None:
    """토큰 카운터를 초기화한다 (평가 루프 반복 시 사용)."""
    global _token_counter
    _token_counter = {"input": 0, "output": 0, "calls": 0}


def get_token_usage() -> Dict[str, int]:
    """현재 누적 토큰 사용량을 반환한다."""
    return dict(_token_counter)


# Ablation 플래그 — os.environ에서 매 호출 시 읽음 (평가 루프 중 동적 전환 가능)
def _ablation_no_cot()          -> bool: return os.environ.get("ABLATION_NO_COT",          "0") == "1"
def _ablation_no_rejudge()      -> bool: return os.environ.get("ABLATION_NO_REJUDGE",      "0") == "1"
def _ablation_no_gcfs()         -> bool: return os.environ.get("ABLATION_NO_GCFS",         "0") == "1"
def _ablation_no_dual_verify()  -> bool: return os.environ.get("ABLATION_NO_DUAL_VERIFY",  "0") == "1"
def _ablation_no_missing_protect() -> bool: return os.environ.get("ABLATION_NO_MISSING_PROTECT", "0") == "1"
def _ablation_no_rag()          -> bool: return os.environ.get("ABLATION_NO_RAG",          "0") == "1"
def _experimental_missing_relax() -> bool: return os.environ.get("L3_EXPERIMENTAL_MISSING_RELAX", "0") == "1"
def _experimental_ast_relax() -> bool: return os.environ.get("L3_EXPERIMENTAL_AST_RELAX", "0") == "1"
def _hybrid_safe_relax() -> bool: return os.environ.get("L3_HYBRID_SAFE_RELAX", "0") == "1"
def _grounded_relax() -> bool: return os.environ.get("L3_GROUNDED_RELAX", "0") == "1"
def _grounded_artifact_relax() -> bool: return os.environ.get("L3_GROUNDED_ARTIFACT_RELAX", "0") == "1"
def _allow_provider_fallback() -> bool: return os.environ.get("LLM_ALLOW_PROVIDER_FALLBACK", "0") == "1"


def _extract_json_from_text(raw: str) -> Optional[Dict[str, Any]]:
    """Gemini 응답에서 JSON 객체 하나 추출."""
    if not raw or not raw.strip():
        return None
    raw = raw.strip()
    code_block = re.search(r"```(?:json)?\s*([\s\S]*?)```", raw)
    if code_block:
        raw = code_block.group(1).strip()
    start = raw.find("{")
    if start == -1:
        return None
    depth = 0
    end = -1
    for i in range(start, len(raw)):
        if raw[i] == "{":
            depth += 1
        elif raw[i] == "}":
            depth -= 1
            if depth == 0:
                end = i
                break
    if end == -1:
        return None
    try:
        return json.loads(raw[start : end + 1])
    except json.JSONDecodeError:
        return None


def _extract_json_array_from_text(raw: str) -> Optional[List[Any]]:
    """Gemini 응답에서 JSON 배열 추출 (배치 처리용)."""
    if not raw or not raw.strip():
        return None
    raw = raw.strip()
    code_block = re.search(r"```(?:json)?\s*([\s\S]*?)```", raw)
    if code_block:
        raw = code_block.group(1).strip()
    start = raw.find("[")
    if start == -1:
        return None
    depth = 0
    end = -1
    for i in range(start, len(raw)):
        if raw[i] == "[":
            depth += 1
        elif raw[i] == "]":
            depth -= 1
            if depth == 0:
                end = i
                break
    if end == -1:
        return None
    try:
        return json.loads(raw[start : end + 1])
    except json.JSONDecodeError:
        return None


# ─────────────────────────────────────────────────────────────────
# Gemini 호출 헬퍼
# ─────────────────────────────────────────────────────────────────
def _call_openai(prompt: str, model: Optional[str] = None) -> Optional[str]:
    """OpenAI ChatCompletion API 호출. API 키 없으면 None 반환."""
    if not OPENAI_API_KEY:
        return None
    try:
        from openai import OpenAI
        client = OpenAI(api_key=OPENAI_API_KEY)
        resp = client.chat.completions.create(
            model=model or OPENAI_L3_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0,
        )
        text = resp.choices[0].message.content if resp.choices else None
        return text if isinstance(text, str) else None
    except Exception as e:
        print(f"[L3][OpenAI] 호출 실패: {e}")
        return None


def _call_llm(
    prompt: str,
    model: Optional[str] = None,
    response_mime_type: Optional[str] = None,
) -> Optional[str]:
    """
    L3_PROVIDER 설정에 따라 LLM 호출.
    - L3_PROVIDER=gemini (기본): Gemini API
    - L3_PROVIDER=openai: OpenAI ChatCompletion
    - L3_PROVIDER=local: local_llm_service.call_local()
    """
    if L3_PROVIDER == "local":
        try:
            from app.services.local_llm_service import call_local
            return call_local(prompt)
        except Exception as e:
            if _allow_provider_fallback():
                print(f"[LLM] local 호출 실패, 명시적으로 허용된 Gemini fallback 수행: {e}")
                return _call_gemini(prompt, response_mime_type=response_mime_type)
            raise LLMProviderError("Local LLM failed; cross-provider fallback is disabled") from e
    if L3_PROVIDER == "openai":
        result = _call_openai(prompt, model=model)
        if result is not None:
            return result
        if _allow_provider_fallback():
            print("[LLM] OpenAI 실패, 명시적으로 허용된 Gemini fallback 수행")
            return _call_gemini(prompt, response_mime_type=response_mime_type)
        raise LLMProviderError("OpenAI returned no result; cross-provider fallback is disabled")
    return _call_gemini(prompt, response_mime_type=response_mime_type)


class _Gemini503Error(Exception):
    """Gemini 503 UNAVAILABLE — 프롬프트 과부하 또는 일시적 오류."""


class GeminiTransientError(RuntimeError):
    """Retryable rate-limit, timeout, or server failure."""


class GeminiConfigurationError(RuntimeError):
    """Non-retryable authentication or model-configuration failure."""


class LLMProviderError(RuntimeError):
    """Selected LLM provider failed without an explicitly allowed fallback."""


def _strip_gcfs_from_prompt(prompt: str) -> str:
    """프롬프트에서 GCFS 블록 제거 (503 오류 시 폴백용)."""
    return re.sub(
        r"=== 코드베이스 전체 구조 요약.*?={3,}\n\n",
        "",
        prompt,
        flags=re.DOTALL,
    )


def _call_gemini(
    prompt: str,
    response_mime_type: Optional[str] = None,
) -> Optional[str]:
    """Google Gemini API 호출. 키 없으면 None 반환. 503 시 _Gemini503Error 발생."""
    if not GOOGLE_API_KEY:
        raise GeminiConfigurationError("GOOGLE_API_KEY is required for the Gemini provider")
    if not _HAS_GOOGLE_GENAI:
        raise GeminiConfigurationError("google-genai is required for the Gemini provider")
    try:
        from google.genai import types

        config = types.GenerateContentConfig(
            temperature=0,
            seed=42,
        )
        if response_mime_type:
            config.response_mime_type = response_mime_type

        from google.genai import types as _types_http
        client = genai.Client(
            api_key=GOOGLE_API_KEY,
            http_options=_types_http.HttpOptions(timeout=60000),  # 60s timeout
        )
        response = client.models.generate_content(
            model=GEMINI_L3_MODEL,
            contents=prompt,
            config=config,
        )
        usage = getattr(response, "usage_metadata", None)
        if usage is not None:
            _token_counter["input"]  += getattr(usage, "prompt_token_count",     0) or 0
            _token_counter["output"] += getattr(usage, "candidates_token_count", 0) or 0
        _token_counter["calls"] += 1
        text = getattr(response, "text", None)
        if text and isinstance(text, str):
            return text
        cands = getattr(response, "candidates", None) or []
        if cands:
            content = getattr(cands[0], "content", None)
            if content:
                parts = getattr(content, "parts", None) or []
                if parts:
                    pt = getattr(parts[0], "text", None)
                    if pt and isinstance(pt, str):
                        return pt
        print("[L3][Gemini] 응답에 텍스트가 없습니다.")
        return None
    except Exception as e:
        err_str = str(e)
        permanent_markers = (
            "API_KEY_INVALID", "API key not valid", "PERMISSION_DENIED",
            "permission denied", "MODEL_NOT_FOUND", "model not found",
        )
        if any(marker in err_str for marker in permanent_markers):
            raise GeminiConfigurationError(
                "Gemini authentication, permission, or model configuration is invalid"
            ) from e
        if "503" in err_str or "UNAVAILABLE" in err_str:
            print(f"[L3][Gemini] 503 오류 (프롬프트 과부하): {err_str[:120]}")
            raise _Gemini503Error(err_str)
        transient_markers = (
            "408", "429", "500", "502", "504", "RESOURCE_EXHAUSTED",
            "DEADLINE_EXCEEDED", "timeout", "timed out", "connection reset",
        )
        if any(marker.lower() in err_str.lower() for marker in transient_markers):
            raise GeminiTransientError(err_str) from e
        raise LLMProviderError("Gemini request failed without a usable response") from e


_RETRY_SUFFIX_OBJ = "\n\n위 JSON 객체 형식만 출력하라. 다른 텍스트는 일절 포함하지 말 것."
_RETRY_SUFFIX_ARR = "\n\n위 JSON 배열 형식만 출력하라. 다른 텍스트는 일절 포함하지 말 것."


def _call_gemini_with_retry(prompt: str, max_retries: int = 2) -> Optional[Dict[str, Any]]:
    """재시도 포함 LLM 호출 → 단일 JSON 객체 반환. 503 시 GCFS 제거 후 재시도."""
    _mime = "application/json"
    for attempt in range(max_retries + 1):
        try:
            raw = _call_llm(
                prompt if attempt == 0 else prompt + _RETRY_SUFFIX_OBJ,
                response_mime_type=_mime,
            )
        except GeminiTransientError:
            if attempt >= max_retries:
                raise
            time.sleep(min(2 ** attempt, 2))
            continue
        except _Gemini503Error:
            stripped = _strip_gcfs_from_prompt(prompt)
            if stripped != prompt:
                print("[L3] 503 → GCFS 제거 후 재시도")
                try:
                    raw = _call_llm(stripped, response_mime_type=_mime)
                except (_Gemini503Error, GeminiTransientError) as exc:
                    if attempt >= max_retries:
                        raise GeminiTransientError("Gemini retry exhausted after GCFS removal") from exc
                    time.sleep(min(2 ** attempt, 2))
                    continue
            else:
                if attempt >= max_retries:
                    raise GeminiTransientError("Gemini retry exhausted")
                time.sleep(min(2 ** attempt, 2))
                continue
            if not raw:
                return None
            obj = _extract_json_from_text(raw)
            return obj  # 성공이든 실패든 한 번만
        if not raw:
            break
        obj = _extract_json_from_text(raw)
        if obj is not None:
            return obj
    return None


def _call_gemini_batch_with_retry(prompt: str, max_retries: int = 2) -> Optional[List[Any]]:
    """재시도 포함 LLM 호출 → JSON 배열 반환 (배치용). 503 시 GCFS 제거 후 재시도."""
    _mime = "application/json"
    for attempt in range(max_retries + 1):
        try:
            raw = _call_llm(
                prompt if attempt == 0 else prompt + _RETRY_SUFFIX_ARR,
                response_mime_type=_mime,
            )
        except GeminiTransientError:
            if attempt >= max_retries:
                raise
            time.sleep(min(2 ** attempt, 2))
            continue
        except _Gemini503Error:
            stripped = _strip_gcfs_from_prompt(prompt)
            if stripped != prompt:
                print("[L3] 503 → GCFS 제거 후 배치 재시도")
                try:
                    raw = _call_llm(stripped, response_mime_type=_mime)
                except (_Gemini503Error, GeminiTransientError) as exc:
                    if attempt >= max_retries:
                        raise GeminiTransientError("Gemini batch retry exhausted after GCFS removal") from exc
                    time.sleep(min(2 ** attempt, 2))
                    continue
            else:
                if attempt >= max_retries:
                    raise GeminiTransientError("Gemini batch retry exhausted")
                time.sleep(min(2 ** attempt, 2))
                continue
            if not raw:
                return None
            arr = _extract_json_array_from_text(raw)
            return arr
        if not raw:
            break
        arr = _extract_json_array_from_text(raw)
        if arr is not None:
            return arr
    return None
