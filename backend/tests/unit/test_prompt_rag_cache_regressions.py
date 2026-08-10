"""Regression tests for prompt facts, guideline chunking, and L3 cache isolation."""

import pytest

from app.services import rag_service
from app.services.llm import prompt_builder
from app.services.llm.prompt_templates import PROMPT_TEMPLATES


NEW_STANDARD_RULES = ("AES-001", "AES-002", "AES-003", "ARIA-001", "SEED-001")


def test_lea_010_prompt_uses_standard_delta_constants():
    prompt = PROMPT_TEMPLATES["LEA-010"].lower()
    expected = ("715ea49e", "c785da0a", "e04ef22a", "e5c40957")
    obsolete = ("edeab813", "0f23b0d3", "5ab40b6d", "3e6b9ae6")
    assert all(value in prompt for value in expected)
    assert all(value not in prompt for value in obsolete)


def test_markdown_parser_keeps_top_level_body_without_h2():
    sections = rag_service._extract_sections_from_md(
        "---\nrule_id: X-001\n---\n# X title\n\nTop-level evidence.\n"
    )
    assert sections == [{"title": "X title", "content": "Top-level evidence."}]


@pytest.mark.parametrize("rule_id", NEW_STANDARD_RULES)
def test_new_standard_guidelines_are_available_to_direct_rag(rule_id):
    chunks = rag_service.search_evidence(rule_id, top_k=2)
    assert chunks
    assert all(chunk["rule_id"] == rule_id for chunk in chunks)
    assert any(chunk["content"].strip() for chunk in chunks)


def test_new_standard_guidelines_are_present_in_keyword_index(monkeypatch):
    monkeypatch.setattr(rag_service, "_index_built", False)
    monkeypatch.setattr(rag_service, "_keyword_index", [])
    rag_service._build_keyword_index()
    indexed = {doc["rule_id"] for doc in rag_service._keyword_index}
    assert set(NEW_STANDARD_RULES) <= indexed


@pytest.mark.parametrize("rule_id", NEW_STANDARD_RULES)
def test_new_standard_guidelines_are_retrievable_by_keyword(rule_id):
    chunks = rag_service._tfidf_search(rule_id, top_k=100)
    assert any(chunk.get("rule_id") == rule_id for chunk in chunks)


def test_l3_cache_key_isolates_rag_guideline_message_and_model(monkeypatch):
    monkeypatch.delenv("ABLATION_NO_RAG", raising=False)
    monkeypatch.setattr(prompt_builder.settings, "L3_PROVIDER", "gemini")
    monkeypatch.setattr(prompt_builder.settings, "GEMINI_L3_MODEL", "model-a")
    base = prompt_builder._l3_cache_key(
        "LEA-010", "code", guideline_text="guide-a", violation_message="message-a"
    )
    assert base != prompt_builder._l3_cache_key(
        "LEA-010", "code", guideline_text="guide-b", violation_message="message-a"
    )
    assert base != prompt_builder._l3_cache_key(
        "LEA-010", "code", guideline_text="guide-a", violation_message="message-b"
    )
    monkeypatch.setenv("ABLATION_NO_RAG", "1")
    assert base != prompt_builder._l3_cache_key(
        "LEA-010", "code", guideline_text="guide-a", violation_message="message-a"
    )
    monkeypatch.delenv("ABLATION_NO_RAG", raising=False)
    monkeypatch.setattr(prompt_builder.settings, "GEMINI_L3_MODEL", "model-b")
    assert base != prompt_builder._l3_cache_key(
        "LEA-010", "code", guideline_text="guide-a", violation_message="message-a"
    )


def test_l3_cache_key_changes_with_prompt_namespace(monkeypatch):
    first = prompt_builder._l3_cache_key("LEA-010", "code")
    monkeypatch.setattr(prompt_builder, "_L3_PROMPT_CACHE_VERSION", "next-version")
    assert first != prompt_builder._l3_cache_key("LEA-010", "code")
