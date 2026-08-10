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
