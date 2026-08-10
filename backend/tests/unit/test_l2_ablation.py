from app.services.llm import prompt_builder
from app.services import rag_service


def test_no_rag_skips_prompt_retrieval(monkeypatch):
    monkeypatch.setenv("ABLATION_NO_RAG", "1")
    monkeypatch.setattr(prompt_builder, "search_evidence", lambda *a, **k: (_ for _ in ()).throw(AssertionError()))
    assert prompt_builder._fetch_guideline_text("LEA-001") == ""


def test_no_rag_clears_context_without_search(monkeypatch):
    monkeypatch.setenv("ABLATION_NO_RAG", "1")
    monkeypatch.setattr(rag_service, "search_evidence", lambda *a, **k: (_ for _ in ()).throw(AssertionError()))
    rows = [{"rule_id": "LEA-001", "rag_guideline_text": "stale"}]
    result = rag_service.run_l2_rag_context(rows)
    assert result[0]["rag_guideline_text"] == ""
    assert result[0]["rag_ablation"] is True
    assert rows == [{"rule_id": "LEA-001", "rag_guideline_text": "stale"}]


def test_rag_enabled_fetches_context(monkeypatch):
    monkeypatch.delenv("ABLATION_NO_RAG", raising=False)
    monkeypatch.setattr(rag_service, "search_evidence", lambda *a, **k: [{"title": "T", "content": "evidence"}])
    rows = [{"rule_id": "LEA-001"}]
    result = rag_service.run_l2_rag_context(rows)
    assert "evidence" in result[0]["rag_guideline_text"]
    assert rows == [{"rule_id": "LEA-001"}]
