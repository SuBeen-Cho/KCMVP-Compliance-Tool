"""AI 종합 평가 요약 생성."""

from typing import Any, Dict, List

from app.services.llm.gemini_client import GOOGLE_API_KEY, _call_llm


def generate_ai_summary(
    violations: List[Dict[str, Any]],
    summary: Dict[str, Any],
    meta: Dict[str, Any],
) -> str:
    """
    전체 위반 목록을 기반으로 AI가 종합 평가 요약을 생성.
    API 키 없거나 호출 실패 시 None 반환.
    """
    if not GOOGLE_API_KEY:
        return None

    total     = summary.get("total", len(violations))
    confirmed = summary.get("confirmed", 0)
    candidate = summary.get("candidate", 0)
    high      = summary.get("high", 0)
    algo      = meta.get("algorithm") or "미지정"
    mode      = meta.get("mode") or "미지정"

    # 위반 항목 요약 (최대 20건, 중복 rule_id 제거)
    seen_rules: set = set()
    rule_lines: List[str] = []
    for v in violations:
        rid = v.get("rule_id", "")
        if rid in seen_rules:
            continue
        seen_rules.add(rid)
        sev = v.get("severity", "")
        msg = v.get("message", "")[:80]
        rule_lines.append(f"- [{rid}] ({sev}) {msg}")
        if len(rule_lines) >= 20:
            break

    rules_text = "\n".join(rule_lines) if rule_lines else "- 위반 없음"

    prompt = f"""당신은 KCMVP 암호모듈 검증 전문가입니다.
아래 분석 결과를 바탕으로 종합 평가 요약을 작성하십시오.

분석 대상: {algo} / 운영 모드: {mode}
전체 위반: {total}건 (확정 {confirmed}건, 후보 {candidate}건, 심각 {high}건)

주요 위반 목록:
{rules_text}

다음 형식으로 정확히 출력하라. 다른 텍스트 포함 금지.

**종합 판정**: (합격 가능성 / 불합격 위험 / 검토 필요 중 하나)

**핵심 위험 요소**
(가장 심각한 위반 2~3개를 골라 왜 위험한지 한 문장씩)

**우선 수정 권고**
(수정 순서를 1~3순위로 제시, 각 한 문장)

**전반적 평가**
(이 암호모듈의 KCMVP 적합성에 대한 전문가 의견, 3~4문장)""".strip()

    raw = _call_llm(prompt)
    if raw and raw.strip():
        return raw.strip()
    return None
