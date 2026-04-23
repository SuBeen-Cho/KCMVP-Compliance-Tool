"""코드/문서 패치 생성."""

from typing import Optional

from app.services.llm.gemini_client import (
    GOOGLE_API_KEY, OPENAI_API_KEY, OPENAI_PATCH_MODEL,
    L2_PROVIDER, _call_llm,
)
from app.services.llm.prompt_builder import _fetch_guideline_text


def _build_patch_prompt(
    file_path: str,
    line: int,
    snippet: str,
    violation_message: str,
    evidence: str,
) -> str:
    """패치 생성 프롬프트 빌드."""
    evidence_section = f"\n📖 참고 가이드라인:\n{evidence}\n" if evidence else ""
    fname = file_path.split("/")[-1] if "/" in file_path else file_path
    return f"""당신은 KCMVP 암호모듈 보안 전문가입니다.
아래 위반 코드를 분석하고 KCMVP 규격에 맞게 수정하십시오.

📍 파일: {fname}  (줄: {line if line else "파일 전체"})
⚠️ 위반: {violation_message}
{evidence_section}
위반 코드:
```c
{snippet}
```

아래 형식을 정확히 지켜서 출력하라. 다른 텍스트는 포함하지 말 것.

### ⚠️ 문제 코드
```diff
{snippet.strip() if snippet else "// (코드 없음)"}
```

### ✅ 수정 코드
```diff
+ // 여기에 KCMVP 규격에 맞는 수정 코드 작성
```

### 📝 수정 이유
한국어로 2~3문장. 왜 문제인지, 무엇으로 바꿔야 하는지 명확히 설명.""".strip()


def generate_patch_for_violation(
    file_path: str,
    line: int,
    snippet: str,
    violation_message: str,
    rule_id: str = "",
    evidence: str = "",
) -> str:
    """
    단일 위반에 대한 수정 예시 마크다운 생성.

    Parameters
    ----------
    rule_id   : KCMVP 룰 ID. evidence가 없으면 RAG에서 자동 로드.
    evidence  : 이미 가져온 가이드라인 텍스트 (없으면 빈 문자열).

    GOOGLE_API_KEY 및 OPENAI_API_KEY 없으면 stub 마크다운 반환.
    """
    no_key = (L2_PROVIDER == "gemini" and not GOOGLE_API_KEY) or \
             (L2_PROVIDER == "openai" and not OPENAI_API_KEY)
    if no_key and L2_PROVIDER not in ("local",):
        return (
            f"## {file_path}:{line}\n\n"
            f"**위반**: {violation_message}\n\n"
            f"**근거**: {evidence or '(가이드라인 없음)'}\n\n"
            f"_(API 키 미설정 — 자동 패치 생성 불가)_"
        )

    # evidence 없으면 RAG에서 직접 로드
    if not evidence and rule_id:
        evidence = _fetch_guideline_text(rule_id, max_chars=600)

    # OpenAI는 패치 전용 모델 사용
    _model = OPENAI_PATCH_MODEL if L2_PROVIDER == "openai" else None
    prompt = _build_patch_prompt(file_path, line, snippet, violation_message, evidence)
    raw = _call_llm(prompt, model=_model)

    if raw and raw.strip():
        return raw.strip()

    # fallback stub
    return (
        f"## {file_path}:{line}\n\n"
        f"**위반**: {violation_message}\n\n"
        f"**근거**: {evidence or '(가이드라인 없음)'}\n\n"
        f"_(LLM 응답 실패 — 수동 수정 필요)_"
    )


def generate_doc_patch_for_violation(
    rule_id: str,
    violation_message: str,
    doc_type: str = "design",
    evidence: str = "",
) -> str:
    """
    문서 위반에 대한 수정 가이드(패치노트) 마크다운 생성.

    코드 패치와 달리 문서 위반은 "어떤 내용을 추가해야 하는가"를 안내함.
    evidence가 없으면 RAG에서 자동 로드.
    API 키 없으면 stub 마크다운 반환.
    """
    doc_type_label = {"design": "기본/상세 설계서", "config_mgmt": "형상관리 계획서", "test": "시험서"}.get(
        doc_type, doc_type
    )

    # evidence 없으면 RAG에서 직접 로드
    if not evidence and rule_id:
        evidence = _fetch_guideline_text(rule_id, max_chars=600)

    evidence_section = f"\n📖 KCMVP 가이드라인 근거:\n{evidence}\n" if evidence else ""

    no_key = (L2_PROVIDER == "gemini" and not GOOGLE_API_KEY) or \
             (L2_PROVIDER == "openai" and not OPENAI_API_KEY)
    stub_md = (
        f"## {rule_id} — {violation_message}\n\n"
        f"**문서 유형**: {doc_type_label}\n\n"
        f"**위반**: {violation_message}\n\n"
        f"{evidence_section if evidence else ''}"
        f"_(API 키 미설정 — 자동 작성 예시 생성 불가)_"
    )

    if no_key and L2_PROVIDER not in ("local",):
        return stub_md

    prompt = f"""당신은 KCMVP 암호모듈 검증 전문가입니다.
아래 문서 위반 항목을 분석하고, {doc_type_label}에 추가해야 할 내용을 구체적으로 작성하십시오.

📋 문서 유형: {doc_type_label}
⚠️ 위반 룰: {rule_id}
⚠️ 위반 내용: {violation_message}
{evidence_section}
아래 형식을 정확히 지켜서 출력하라. 다른 텍스트는 포함하지 말 것.

### ⚠️ 누락/미흡 항목
{violation_message}에 대한 설명 1~2문장.

### ✅ 추가해야 할 내용 (작성 예시)
마크다운 또는 표 형식으로 실제 문서에 삽입 가능한 수준의 예시 작성.
KCMVP 가이드라인 근거를 반영할 것.

### 📝 수정 이유
한국어로 2~3문장. KCMVP 심사 관점에서 왜 필수인지 설명.""".strip()

    raw = _call_llm(prompt)

    if raw and raw.strip():
        return raw.strip()

    return stub_md
