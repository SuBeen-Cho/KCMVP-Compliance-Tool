"""DOC 위반 AI 재판정 — run_doc_l3_contextualizer."""

from typing import Any, Dict, List, Optional

from app.services.llm.gemini_client import (
    GOOGLE_API_KEY, OPENAI_API_KEY, L3_PROVIDER,
    _call_gemini_with_retry,
)
from app.services.llm.prompt_templates import _DOC_PROMPT_TEMPLATES


def run_doc_l3_contextualizer(
    violations_doc: List[Dict[str, Any]],
    doc_preprocess_result: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    DOC 위반 중 semantic + high-severity missing 타입(needs_ai_review=True)을 AI 재판정.

    - regex 타입은 객관적 사실 기반이므로 그대로 통과.
    - semantic 타입은 키워드 미존재만으로 판단했으므로 AI가 실제 위반인지 재검토.
    - missing 타입은 섹션 자체가 없는 경우이지만, AI가 동등 내용 존재 여부를 재검토.
    - AI가 is_real_issue=False로 판정하면 최종 위반 목록에서 제외.
    - API 키 없거나 실패 시 원본 목록 그대로 반환 (안전 fallback).
    """
    has_key = (L3_PROVIDER == "gemini" and GOOGLE_API_KEY) or \
              (L3_PROVIDER == "openai" and OPENAI_API_KEY) or \
              (L3_PROVIDER == "local")
    if not has_key:
        return violations_doc

    # needs_ai_review=True 인 위반 전체를 AI 재판정 대상으로 한다.
    # (pattern_type은 doc_rule_service가 violation dict에 저장하므로 필터로도 활용 가능,
    #  하지만 needs_ai_review 플래그 자체가 AI 판단 필요 여부의 단일 진실 소스)
    semantic_violations = [
        v for v in violations_doc
        if v.get("needs_ai_review") is True
    ]
    if not semantic_violations:
        return violations_doc

    # 표(table) 데이터를 텍스트로 직렬화 (Phase 3: 표 내용 L3에 전달)
    def _serialize_tables(tables: list) -> str:
        parts: List[str] = []
        for tbl in (tables or [])[:6]:
            t_name = str(tbl.get("name") or "").strip()
            hdrs = [str(h).strip() for h in (tbl.get("headers") or []) if str(h).strip()]
            rows_raw = tbl.get("rows") or []
            t_lines: List[str] = []
            if t_name:
                t_lines.append(f"[표 {t_name}]")
            if hdrs:
                t_lines.append(" | ".join(hdrs))
            for row in rows_raw[:20]:
                cells = [str(c).strip() for c in (row or []) if str(c).strip()]
                if cells:
                    t_lines.append(" | ".join(cells))
            if t_lines:
                parts.append("\n".join(t_lines))
        return ("\n\n" + "\n\n".join(parts)) if parts else ""

    # doc_type별 풀텍스트 캐시 (섹션 title + text + 표 데이터 결합)
    # section_keywords: 규칙이 지정한 관련 섹션 제목 키워드 → 해당 섹션만 추출 (옵션)
    # priority_section: 위반 관련 섹션 우선 배치
    def _build_doc_fulltext(
        doc_type: str,
        priority_section: str = "",
        section_keywords: Optional[List[str]] = None,
    ) -> str:
        sections = doc_preprocess_result.get("sections") or []

        # section_keywords가 있으면 해당 섹션만 추출 (표 포함)
        if section_keywords:
            targeted_chunks: List[str] = []
            for s in sections:
                dt = (s.get("doc_type") or "").lower().strip()
                if dt == "scm":
                    dt = "config_mgmt"
                if dt != doc_type:
                    continue
                title = str(s.get("title") or "").strip()
                if any(kw.lower() in title.lower() for kw in section_keywords):
                    text = str(s.get("text") or "").strip()
                    table_text = _serialize_tables(s.get("tables"))
                    header = f"[{title}]" if title else ""
                    full = (text + table_text)[:5000]
                    targeted_chunks.append((header + "\n" + full).strip())
            if targeted_chunks:
                return "\n\n".join(targeted_chunks)[:15000]
            # 매칭 섹션 없으면 fallback → 전체 컨텍스트

        # 전체 섹션 컨텍스트: 텍스트 + 표 데이터 포함
        # priority_section: 해당 섹션 우선 배치 + 더 많은 문자 할당
        priority_chunks: List[str] = []
        other_chunks: List[str] = []
        for s in sections:
            dt = (s.get("doc_type") or "").lower().strip()
            if dt == "scm":
                dt = "config_mgmt"
            if dt != doc_type:
                continue
            title = str(s.get("title") or "").strip()
            text = str(s.get("text") or "").strip()
            table_text = _serialize_tables(s.get("tables"))
            header = f"[{title}]" if title else ""
            full_content = text + table_text
            if priority_section and priority_section.strip() and \
               priority_section.lower() in title.lower():
                chunk = (header + "\n" + full_content[:3500]).strip()
                priority_chunks.append(chunk)
            else:
                chunk = (header + "\n" + full_content[:1200]).strip()
                other_chunks.append(chunk)
        combined = "\n\n".join(priority_chunks + other_chunks)
        return combined[:15000]  # 표 데이터 포함으로 15000자로 확장

    # 캐시 키: (doc_type, priority_section, section_keywords) — 독립 캐시
    fulltext_cache: Dict[str, str] = {}

    # 판정 대상: rule_id별 최대 5건, 전체 최대 50건
    # semantic 규칙이 항상 발동되므로 건수 증가에 대응해 상한 상향
    per_rule: Dict[str, int] = {}
    candidates: List[Dict[str, Any]] = []
    for v in semantic_violations:
        rid = v.get("rule_id") or ""
        per_rule[rid] = per_rule.get(rid, 0) + 1
        if per_rule[rid] <= 5 and len(candidates) < 50:
            candidates.append(v)

    print(f"[DOC-L3] 판정 대상 {len(candidates)}건 (전체 AI검토대상: {len(semantic_violations)}건)")

    # [P3] 판정 결과 저장: 위반 인스턴스별 (id(v) → is_real_issue)
    # 평가된 위반 인스턴스는 독립 판정, 미평가 인스턴스는 같은 rule_id의 결과 전파
    judgment_by_instance: Dict[int, bool] = {}  # id(v) → bool
    judgment_by_rule: Dict[str, bool] = {}       # rule_id → bool (fallback)

    for v in candidates:
        rule_id = v.get("rule_id") or "UNKNOWN"
        doc_type = v.get("doc_type") or "design"
        msg = v.get("message") or ""
        section_title = v.get("section") or v.get("title") or ""
        section_keywords: List[str] = v.get("section_keywords") or []

        kw_key = ",".join(sorted(section_keywords))
        cache_key = f"{doc_type}::{section_title}::{kw_key}"
        if cache_key not in fulltext_cache:
            fulltext_cache[cache_key] = _build_doc_fulltext(
                doc_type, section_title, section_keywords or None
            )
        doc_text = fulltext_cache[cache_key]

        if not doc_text:
            # 문서 텍스트 없으면 판정 불가 → 보수적으로 위반 유지
            judgment_by_instance[id(v)] = True
            judgment_by_rule.setdefault(rule_id, True)
            continue

        section_hint = f"\n[관련 섹션] {section_title}" if section_title else ""
        # rule description: name보다 구체적인 요건 기술 (YAML description 필드)
        rule_desc = v.get("rule_description") or ""
        desc_hint = f"\n[상세 요건] {rule_desc}" if rule_desc else ""
        keyword_found = v.get("keyword_found")  # True/False/None
        if keyword_found is True:
            keyword_hint = "\n[주의] 관련 키워드가 문서에 존재하지만, 다른 섹션/맥락에서 나타남. 해당 키워드가 이 규칙이 요구하는 맥락에서 사용되었는지 반드시 확인하라."
        elif keyword_found is False:
            keyword_hint = "\n[주의] 관련 키워드가 문서 어디에도 존재하지 않음. 요건 자체가 누락된 강한 신호."
        else:
            keyword_hint = ""
        # GPTScan 체크리스트 템플릿 적용 (rule_id가 _DOC_PROMPT_TEMPLATES에 있으면 우선 사용)
        if rule_id in _DOC_PROMPT_TEMPLATES:
            _cl = _DOC_PROMPT_TEMPLATES[rule_id]
            _sec = f"\n[관련 섹션] {section_title}" if section_title else ""
            prompt = (
                "당신은 KCMVP(국가 암호모듈 검증) 문서 심사 전문가입니다.\n\n"
                + _cl + "\n\n"
                + f"[설계서 관련 섹션 내용 (발췌)]\n{doc_text}" + _sec + "\n\n"
                + "반드시 아래 JSON 형식만 출력하라:\n"
                + '{"is_real_issue": true 또는 false, "reason": "판정 근거 한 줄 (한국어)"}'
            )
        else:
            prompt = f"""당신은 KCMVP(국가 암호모듈 검증) 문서 심사 전문가입니다.

아래 KCMVP 설계서 내용을 분석하여, 해당 규칙 요건이 실제로 누락되었는지 판정하세요.

[규칙 ID] {rule_id}
[규칙 내용] {msg}{desc_hint}{section_hint}{keyword_hint}

[설계서 관련 섹션 내용 (발췌)]
{doc_text}

위 설계서에서 [{rule_id}] 요건이 실제로 누락/위반되었습니까?
판정 기준:
- 키워드가 없더라도 동등한 의미의 다른 표현으로 요건을 명확히 충족하면 is_real_issue=false
- 키워드가 있어도 이 규칙이 요구하는 특정 맥락(상세 요건 참조)에서 사용되지 않았다면 요건 미충족으로 판단
- 내용 자체가 없거나 한 문장으로 얼버무린 경우(예: "수행한다" 단독) 불충분 → is_real_issue=true
- 함수명이 테이블에 나열된 것만으로는 동작 기술로 보지 않음

반드시 아래 JSON 형식만 출력하라:
{{"is_real_issue": true 또는 false, "reason": "판정 근거 한 줄 (한국어)"}}"""

        obj = _call_gemini_with_retry(prompt)
        if obj is None:
            print(f"[DOC-L3] {rule_id} 판정 실패 → 위반 유지")
            judgment_by_instance[id(v)] = True
            judgment_by_rule.setdefault(rule_id, True)
            continue

        is_real = bool(obj.get("is_real_issue", True))
        reason = obj.get("reason", "")
        judgment_by_instance[id(v)] = is_real
        # rule_id fallback: 첫 번째 확정 판정을 기준으로 저장
        if rule_id not in judgment_by_rule:
            judgment_by_rule[rule_id] = is_real
        print(f"[DOC-L3] {rule_id}: {'위반 확정' if is_real else '오탐 제거'} — {reason}")

    # 원본 목록에서 AI가 오탐으로 판정한 위반 제거
    # 인스턴스별 판정 우선, 없으면 rule_id 수준 판정 사용
    result = []
    for v in violations_doc:
        rid = v.get("rule_id") or ""
        if v.get("needs_ai_review"):
            vid = id(v)
            if vid in judgment_by_instance:
                is_real = judgment_by_instance[vid]
            elif rid in judgment_by_rule:
                is_real = judgment_by_rule[rid]
            else:
                result.append(v)
                continue

            if not is_real:
                print(f"[DOC-L3] {rid} 제거 (오탐)")
                continue
            # 확정 위반으로 표시
            v = dict(v)
            v["confidence"] = "확정"
            v["needs_ai_review"] = False
        result.append(v)

    return result
