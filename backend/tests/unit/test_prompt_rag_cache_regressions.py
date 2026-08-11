"""Regression tests for prompt facts, guideline chunking, and L3 cache isolation."""

from pathlib import Path

import pytest

from app.services import rag_service
from app.services.llm import prompt_builder
from app.services.llm.prompt_templates import PROMPT_TEMPLATES


NEW_STANDARD_RULES = ("AES-001", "AES-002", "AES-003", "ARIA-001", "SEED-001")


def test_active_l3_prompts_do_not_encode_synthetic_answer_bearing_filenames():
    llm_dir = Path(prompt_builder.__file__).resolve().parent
    prompt_sources = (
        llm_dir / "prompt_builder.py",
        llm_dir / "prompt_templates.py",
        llm_dir / "triage_memory.py",
    )
    forbidden = ("violations_", "violations.", "위반시험", "위반 시험")

    for source in prompt_sources:
        text = source.read_text(encoding="utf-8").lower()
        assert not any(marker in text for marker in forbidden), source.name


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


@pytest.mark.parametrize(
    "field,value",
    [
        ("detection_semantics", "structural_violation"),
        ("pattern_type", "ast"),
        ("ast_evidence", "round mismatch"),
        ("ai_context", "FIPS table"),
    ],
)
def test_l3_cache_key_isolates_detection_inputs(field, value):
    base = prompt_builder._l3_cache_key("AES-001", "code")
    assert base != prompt_builder._l3_cache_key("AES-001", "code", **{field: value})


def test_semantic_order_violation_is_not_prompted_as_absence():
    candidate = {
        "rule_id": "COM-005", "pattern_type": "semantic",
        "detection_semantics": "structural_violation", "message": "호출 순서 오류",
    }
    prompt = prompt_builder._build_single_prompt("online.c", candidate, "update(); init();")
    assert "탐지 의미: 구조 위반" in prompt
    assert "이 위반은 \"필수 보안 패턴의 부재\"" not in prompt


def test_semantic_absence_keeps_absence_guidance():
    candidate = {
        "rule_id": "LEA-061", "pattern_type": "semantic",
        "detection_semantics": "required_absence", "message": "키 길이 지원 부재",
    }
    prompt = prompt_builder._build_single_prompt("lea.c", candidate, "void f(void) {}")
    assert "탐지 의미: 패턴 부재 위반" in prompt
    assert "confidence ≥ 65" in prompt


def test_ast_contradiction_is_structural_in_single_and_batch_prompts():
    candidate = {
        "rule_id": "AES-001", "pattern_type": "ast",
        "detection_semantics": "structural_violation", "message": "키 길이-라운드 모순",
        "ast_evidence": "16-byte key selects 14 rounds",
    }
    single = prompt_builder._build_single_prompt("aes.c", candidate, "rounds = 14;")
    batch = prompt_builder._build_batch_prompt(
        "aes.c", [{"violation": candidate, "code_block": "rounds = 14;"}],
    )
    assert "탐지 의미: 구조 위반" in single
    assert "탐지 의미: 구조 위반" in batch
    assert "[패턴 부재 위반" not in batch
    assert "[구조 위반 — 명시적 구조 모순이 확인되고 confidence≥75" in batch


def test_ast_fallback_without_evidence_is_not_described_as_ast_fact():
    candidate = {
        "rule_id": "X-AST", "pattern_type": "ast",
        "detection_semantics": "required_absence", "message": "fallback only",
    }
    single = prompt_builder._build_single_prompt("x.c", candidate, "void f(void) {}")
    batch = prompt_builder._build_batch_prompt(
        "x.c", [{"violation": candidate, "code_block": "void f(void) {}"}],
    )
    assert "C&A Phase 1: AST 구조 분석 결과" not in single
    assert "C&A AST 분석 결과" not in batch
    assert "탐지 의미: 패턴 부재 위반" in single


def test_required_absence_rejudge_is_recall_first_and_requests_evidence():
    candidate = {
        "rule_id": "LEA-061", "pattern_type": "semantic",
        "detection_semantics": "required_absence",
    }
    prompt = prompt_builder._build_rejudge_prompt(
        "lea.c", candidate, "code", {"confidence": 70, "description": "first"},
    )
    assert "불확실성만으로 false로 변경하지 말고" in prompt
    assert "insufficient_context=true로 표시하고 후보를 유지" in prompt
    assert '"evidence_type"' in prompt
