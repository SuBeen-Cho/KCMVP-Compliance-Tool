import pytest

from app.services.llm import gemini_client


def test_invalid_api_key_is_non_retryable(monkeypatch):
    class Models:
        def generate_content(self, **kwargs):
            raise RuntimeError("400 API_KEY_INVALID: API key not valid")

    class Client:
        models = Models()

    monkeypatch.setattr(gemini_client, "GOOGLE_API_KEY", "invalid")
    monkeypatch.setattr(gemini_client, "_HAS_GOOGLE_GENAI", True)
    monkeypatch.setattr(gemini_client.genai, "Client", lambda **kwargs: Client())
    with pytest.raises(gemini_client.GeminiConfigurationError):
        gemini_client._call_gemini("test")


def test_missing_api_key_fails_fast(monkeypatch):
    monkeypatch.setattr(gemini_client, "GOOGLE_API_KEY", "")
    with pytest.raises(gemini_client.GeminiConfigurationError):
        gemini_client._call_gemini("test")


def test_openai_does_not_silently_fallback(monkeypatch):
    monkeypatch.setattr(gemini_client, "L3_PROVIDER", "openai")
    monkeypatch.setattr(gemini_client, "_call_openai", lambda *a, **k: None)
    monkeypatch.setattr(
        gemini_client,
        "_call_gemini",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("unexpected fallback")),
    )
    monkeypatch.delenv("LLM_ALLOW_PROVIDER_FALLBACK", raising=False)
    with pytest.raises(gemini_client.LLMProviderError):
        gemini_client._call_llm("test")


def test_timeout_is_explicit_transient_error(monkeypatch):
    class Models:
        def generate_content(self, **kwargs):
            raise RuntimeError("504 DEADLINE_EXCEEDED: request timed out")

    class Client:
        models = Models()

    monkeypatch.setattr(gemini_client, "GOOGLE_API_KEY", "configured")
    monkeypatch.setattr(gemini_client, "_HAS_GOOGLE_GENAI", True)
    monkeypatch.setattr(gemini_client.genai, "Client", lambda **kwargs: Client())
    with pytest.raises(gemini_client.GeminiTransientError):
        gemini_client._call_gemini("test")


def test_transient_error_retries_then_propagates(monkeypatch):
    calls = {"count": 0}

    def fail(*args, **kwargs):
        calls["count"] += 1
        raise gemini_client.GeminiTransientError("504")

    monkeypatch.setattr(gemini_client, "_call_llm", fail)
    monkeypatch.setattr(gemini_client.time, "sleep", lambda _: None)
    with pytest.raises(gemini_client.GeminiTransientError):
        gemini_client._call_gemini_with_retry("test", max_retries=2)
    assert calls["count"] == 3
