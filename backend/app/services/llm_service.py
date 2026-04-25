"""
LLMService: L3 의미적 오류 탐지 + 패치 생성.

SRP 리팩토링: 실제 로직은 app.services.llm 패키지의 서브 모듈에 분리.
이 파일은 하위 호환을 위한 thin facade — 모든 기존 import가 그대로 동작.
"""

# ── prompt_templates ──────────────────────────────────────────
from app.services.llm.prompt_templates import (  # noqa: F401
    PROMPT_TEMPLATES,
    _HIGH_ISOLATION_RULES,
    _DOC_PROMPT_TEMPLATES,
    _get_prompt_template,
)

# ── gemini_client ─────────────────────────────────────────────
from app.services.llm.gemini_client import (  # noqa: F401
    GEMINI_L3_MODEL,
    GOOGLE_API_KEY,
    L3_PROVIDER,
    OPENAI_API_KEY,
    OPENAI_L3_MODEL,
    OPENAI_PATCH_MODEL,
    _HAS_GOOGLE_GENAI,
    _Gemini503Error,
    _call_openai,
    _call_llm,
    _call_gemini,
    _strip_gcfs_from_prompt,
    _call_gemini_with_retry,
    _call_gemini_batch_with_retry,
    _extract_json_from_text,
    _extract_json_array_from_text,
    _RETRY_SUFFIX_OBJ,
    _RETRY_SUFFIX_ARR,
)

# ── candidate_selector ───────────────────────────────────────
from app.services.llm.candidate_selector import (  # noqa: F401
    _L15_FP_NAMES,
    _L15_TP_NAMES,
    _l15_name_filter,
    _select_l3_candidates,
)

# ── code_context ──────────────────────────────────────────────
from app.services.llm.code_context import (  # noqa: F401
    _WINDOW_BY_PATTERN_TYPE,
    _find_func_boundary_from_sg,
    _get_code_context,
)

# ── prompt_builder ────────────────────────────────────────────
from app.services.llm.prompt_builder import (  # noqa: F401
    _fetch_guideline_text,
    _l3_cache,
    _l3_cache_key,
    _build_single_prompt,
    _build_batch_prompt,
    _build_rejudge_prompt,
    _make_l3_result,
    _build_structured_evidence,
    _build_global_flow_summary,
    _build_flow_context,
    _LEA_DELTA_STANDARD_LC,
    _SAFE_CONST_PATTERNS,
)

# ── rag_context (L2) ──────────────────────────────────────────
from app.services.rag_service import run_l2_rag_context  # noqa: F401

# ── l3_judge ──────────────────────────────────────────────────
from app.services.llm.l3_judge import run_l3_contextualizer  # noqa: F401

# ── doc_judge ─────────────────────────────────────────────────
from app.services.llm.doc_judge import run_doc_l3_contextualizer  # noqa: F401

# ── patch_generator ───────────────────────────────────────────
from app.services.llm.patch_generator import (  # noqa: F401
    _build_patch_prompt,
    generate_patch_for_violation,
    generate_doc_patch_for_violation,
)

# ── summary_generator ─────────────────────────────────────────
from app.services.llm.summary_generator import generate_ai_summary  # noqa: F401
