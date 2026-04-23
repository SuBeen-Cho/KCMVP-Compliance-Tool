"""프롬프트 빌더 — 단일/배치/재판정 + 구조화 증거 + GCFS."""

import hashlib
import re
from typing import Any, Dict, List, Optional

from app.services.rag_service import search_evidence
from app.services.llm.prompt_templates import PROMPT_TEMPLATES, _get_prompt_template


# ─────────────────────────────────────────────────────────────────
# RAG 가이드라인 텍스트 로드
# ─────────────────────────────────────────────────────────────────
def _fetch_guideline_text(rule_id: str, max_chars: int = 800) -> str:
    """search_evidence()로 가이드라인 청크 로드 → 프롬프트 주입용 텍스트 반환."""
    try:
        chunks = search_evidence(rule_id, top_k=2)
        if not chunks:
            return ""
        parts = []
        total = 0
        for c in chunks:
            title = c.get("title", "")
            content = c.get("content", "")
            piece = f"[{title}]\n{content}" if title else content
            parts.append(piece)
            total += len(piece)
            if total >= max_chars:
                break
        return "\n\n".join(parts)[:max_chars]
    except Exception as e:
        print(f"[L2][RAG] guideline fetch 실패 ({rule_id}): {e}")
        return ""


# ─────────────────────────────────────────────────────────────────
# pattern_type별 코드 절삭 범위 (라인 수)
# missing은 위치 정보가 없으므로 절삭 불필요 → L2 호출 자체를 스킵
# ─────────────────────────────────────────────────────────────────
_WINDOW_BY_PATTERN_TYPE: Dict[str, int] = {
    "regex": 30,
    "semantic": 50,
    "ast": 50,
    "missing": 0,
}

# ─────────────────────────────────────────────────────────────────
# L2 결과 캐시 (스니펫 해시 기반, in-memory)
# ─────────────────────────────────────────────────────────────────
_l2_cache: Dict[str, Dict[str, Any]] = {}


def _l2_cache_key(rule_id: str, code_block: str) -> str:
    return hashlib.sha256(f"{rule_id}:{code_block}".encode()).hexdigest()[:16]



# ─────────────────────────────────────────────────────────────────
# L2 결과 캐시 (스니펫 해시 기반, in-memory)
# ─────────────────────────────────────────────────────────────────
_l2_cache: Dict[str, Dict[str, Any]] = {}


def _l2_cache_key(rule_id: str, code_block: str) -> str:
    return hashlib.sha256(f"{rule_id}:{code_block}".encode()).hexdigest()[:16]


# ─────────────────────────────────────────────────────────────────
# 프롬프트 빌더
# ─────────────────────────────────────────────────────────────────
def _build_single_prompt(
    file_path: str,
    v: Dict[str, Any],
    code_block: str,
    guideline_text: str = "",
    use_cot: bool = False,
) -> str:
    """단일 위반 판정 프롬프트 (배치 실패 시 fallback 또는 격리 판정).

    Parameters
    ----------
    guideline_text : RAG로 가져온 KCMVP 가이드라인 텍스트 (없으면 빈 문자열)
    use_cot        : True이면 단계적 추론(CoT) 형식으로 판정 요청

    C&A 2단계 판정 (ISSTA 2025 "Beyond Static Pattern Matching"):
    - pattern_type == "ast": AST 구조 증거를 별도 섹션으로 명시.
      L2는 AST가 확인한 구조적 사실을 검증하는 역할 (재확인 아닌 영향도 판단).
    - ast_evidence 필드가 있으면 해당 근거를 우선 제시.
    """
    rule_id = v.get("rule_id") or "UNKNOWN"
    line = v.get("line") or "N/A"
    l1_msg = v.get("message") or ""
    template = _get_prompt_template(rule_id)
    ai_ctx = v.get("ai_context", "")
    ctx_line = f"\n규격 상세: {ai_ctx}" if ai_ctx else ""

    guideline_section = (
        f"\n📖 KCMVP 가이드라인 (참고):\n{guideline_text}\n"
        if guideline_text
        else ""
    )

    if use_cot:
        reasoning_section = """
판정 단계 (아래 순서로 분석 후 JSON 출력):
STEP 1 [관찰]: 코드에서 실제로 발견한 패턴·함수·값을 구체적으로 기술하라.
STEP 2 [비교]: 판정 기준 및 가이드라인과 비교하여 차이·부재 항목을 명확히 설명하라.
STEP 3 [결론]: 위 분석을 토대로 아래 JSON 객체를 출력하라."""
    else:
        reasoning_section = ""

    pattern_type = v.get("pattern_type", "")
    is_absence = pattern_type in ("semantic", "ast", "missing")

    if is_absence:
        judgment_criteria = """판정 지침 (엄격 적용):
【이 위반은 "필수 보안 패턴의 부재"가 위반 — L1이 특정 패턴이 없음을 감지했음】
【오탐(is_real_issue=false) 판정 조건 — 아래 중 하나라도 해당하면 반드시 false】
  ① 변수명·배열명·주석이 S-box, delta, lookup_table, test_vector, KAT 등 공개 상수를 암시할 때
  ② L1 탐지 메시지의 필수 패턴이 다른 방식(동등한 구현)으로 이미 충족되어 있을 때
  ③ 판정 기준에 명시된 허용 예외에 해당할 때
【위반(is_real_issue=true) 판정 조건】
  ● L1 메시지에서 언급한 필수 패턴이 코드 내에 실제로 없음
  ● 허용 예외에 해당하지 않음
  ● confidence ≥ 65
  ※ "패턴 부재" 확인: 함수 전체가 보이면 부재 여부를 판단할 수 있음
  ※ insufficient_context=true는 코드가 실제로 너무 짧아 판단 자체가 불가한 경우에만 사용"""
    else:
        judgment_criteria = """판정 지침 (엄격 적용):
【오탐(is_real_issue=false) 판정 조건 — 아래 중 하나라도 해당하면 반드시 false】
  ① 변수명·배열명·주석이 S-box, delta, lookup_table, test_vector, KAT 등 공개 알고리즘 상수를 암시할 때
  ② 코드 컨텍스트가 불충분하여 위반 여부를 확신할 수 없을 때 (→ insufficient_context=true 로 표시)
  ③ 판정 기준에 명시된 허용 예외(테스트 목적, KAT, 단일 블록 암호화)에 해당할 때
  ④ 위반이 의심되지만 증거가 약하거나 코드 흐름상 다른 해석이 가능할 때
【위반(is_real_issue=true) 판정 조건 — 모두 충족 시에만 true】
  ● 코드에서 위반 패턴이 명확히 확인됨
  ● 허용 예외에 해당하지 않음
  ● confidence ≥ 75"""

    # C&A Phase 1: AST 구조 증거 섹션 — pattern_type이 "ast"인 위반에 대해
    # AST 체커가 이미 확인한 구조적 사실을 별도 섹션으로 명시하여 L2가
    # "위반인가?" 대신 "이 AST 발견이 실제 보안 문제인가?"에 집중하도록 유도
    pattern_type_val = v.get("pattern_type", "")
    ast_evidence_val = v.get("ast_evidence", "")  # 체커가 직접 설정한 구조 증거 (선택)
    if pattern_type_val == "ast":
        # ast_evidence 필드 우선, 없으면 L1 message에서 추출
        ast_fact = ast_evidence_val if ast_evidence_val else l1_msg
        ast_evidence_section = (
            f"\n【C&A Phase 1: AST 구조 분석 결과 (검증된 사실)】\n"
            f"  정적 AST 분석이 다음 구조적 사실을 확인했습니다:\n"
            f"  → {ast_fact}\n"
            f"  ※ 위 사실은 AST 파싱으로 확인된 것입니다. L2 판정 목표:\n"
            f"  ※ '이 구조적 사실이 실제 보안 취약점인가?' (구조 재확인 불필요)"
        )
    else:
        ast_evidence_section = ""

    return f"""당신은 KCMVP 암호모듈 보안 전문 리뷰어입니다.

파일: {file_path}
라인: {line}
rule_id: {rule_id}
판정 기준: {template}{ctx_line}{guideline_section}
L1 탐지 메시지: {l1_msg}{ast_evidence_section}

코드:
```c
{code_block}
```
{reasoning_section}
{judgment_criteria}
- confidence: 판정 확신도 (0=오탐/불확실, 100=위반 확실)
- insufficient_context: 코드 절삭이 너무 짧아 판단 불가이면 true

반드시 아래 JSON 형식의 객체만 출력하라:
{{"is_real_issue": true 또는 false, "confidence": 0~100 정수, "description": "한글 설명 (2~3문장)", "suggestion": "수정 방향 한 줄", "insufficient_context": false}}""".strip()


def _build_batch_prompt(file_path: str, batch: List[Dict[str, Any]]) -> str:
    """같은 파일의 여러 위반을 한 번에 판정하는 배치 프롬프트.

    각 항목은 독립적으로 판정하며, 앞 항목의 결과가 뒤 항목에 영향을 주지 않도록 주의한다.
    항목별 KCMVP 가이드라인이 있으면 간략히 포함한다 (최대 300자).
    """
    items_text_parts = []
    for i, entry in enumerate(batch):
        v = entry["violation"]
        code_block = entry["code_block"]
        rule_id = v.get("rule_id") or "UNKNOWN"
        template = _get_prompt_template(rule_id)
        ai_ctx = v.get("ai_context", "")
        ctx_part = f"\n  규격 상세: {ai_ctx}" if ai_ctx else ""
        # 항목별 가이드라인 (pre-fetched, 없으면 빈 문자열)
        guide = entry.get("guideline_text", "")
        guide_part = f"\n  가이드라인: {guide[:800]}" if guide else ""
        ptype = v.get("pattern_type", "")
        threshold_note = (
            "  [패턴 부재 위반 — confidence≥65 시 true, insufficient_context는 코드 자체가 너무 짧을 때만]\n"
            if ptype in ("semantic", "ast") else
            "  [패턴 존재 위반 — confidence≥75 시 true]\n"
        )
        # C&A: AST 위반에 구조 증거 섹션 추가
        ast_ev = v.get("ast_evidence", "")
        l1_msg_batch = v.get("message") or ""
        if ptype == "ast":
            ast_fact = ast_ev if ast_ev else l1_msg_batch
            ast_section = f"  【C&A AST 분석 결과】 {ast_fact}\n  ※ 위 구조적 사실 기반으로 보안 영향도를 판단하라.\n"
        else:
            ast_section = ""
        items_text_parts.append(
            f"[위반 {i + 1}]\n"
            f"  rule_id: {rule_id}\n"
            f"  line: {v.get('line') or 'N/A'}\n"
            f"  판정 기준: {template}{ctx_part}{guide_part}\n"
            f"{threshold_note}"
            f"{ast_section}"
            f"  L1 탐지: {l1_msg_batch}\n"
            f"  코드:\n```c\n{code_block}\n```"
        )
    items_text = "\n\n".join(items_text_parts)
    n = len(batch)

    return f"""당신은 KCMVP 암호모듈 보안 전문 리뷰어입니다.

파일: {file_path}

아래 {n}개의 위반 후보를 각각 독립적으로 판정하라.

【오탐(is_real_issue=false) 기준 — 아래 중 하나라도 해당하면 반드시 false】
  ① S-box·delta·lookup_table·test_vector·KAT 등 공개 상수임이 변수명·주석으로 드러날 때
  ② 코드 컨텍스트 불충분으로 확신 불가 시 (→ insufficient_context=true, 단 "패턴 부재 위반"은 함수 전체가 보이면 판단 가능)
  ③ 판정 기준의 허용 예외(테스트 목적, KAT, 단일 블록)에 해당할 때
  ④ 위반 증거가 약하거나 다른 해석이 가능할 때
【위반(is_real_issue=true) 기준】
  - 패턴 존재 위반: 코드에서 명확히 확인되고 confidence≥75일 때만
  - 패턴 부재 위반 ([패턴 부재 위반] 표시된 항목): 필수 패턴이 없음이 확인되고 confidence≥65일 때

{items_text}

반드시 아래 JSON 배열 형식만 출력하라 (입력과 동일한 순서, idx는 1부터):
[
  {{"idx": 1, "is_real_issue": true 또는 false, "confidence": 0~100 정수, "description": "한글 설명", "suggestion": "수정 방향 한 줄", "insufficient_context": false}},
  {{"idx": 2, "is_real_issue": true 또는 false, "confidence": 0~100 정수, "description": "한글 설명", "suggestion": "수정 방향 한 줄", "insufficient_context": false}}
]""".strip()


# ─────────────────────────────────────────────────────────────────
# 신뢰도 재판정 (Direction 4: confidence 65-74 구간 재검토)
# ─────────────────────────────────────────────────────────────────
def _build_rejudge_prompt(
    file_path: str,
    v: Dict[str, Any],
    code_block: str,
    first_obj: Dict[str, Any],
    guideline_text: str = "",
) -> str:
    """신뢰도 65-74 구간 항목에 대한 재판정 프롬프트.

    1차 판정 결과를 명시적으로 보여주고, 더 엄격한 기준으로 재검토하도록 요청.
    """
    rule_id = v.get("rule_id") or "UNKNOWN"
    template = _get_prompt_template(rule_id)
    first_desc = first_obj.get("description", "")
    first_conf = first_obj.get("confidence", "N/A")
    guideline_section = (
        f"\n📖 KCMVP 가이드라인:\n{guideline_text}\n" if guideline_text else ""
    )
    return f"""당신은 KCMVP 암호모듈 보안 수석 심사관입니다.
아래 항목은 1차 AI 판정에서 신뢰도 {first_conf}점(경계값)으로 판정되었습니다.
더 엄격하고 신중하게 재검토하십시오.

파일: {file_path}
rule_id: {rule_id}
판정 기준: {template}{guideline_section}
1차 판정 설명: {first_desc}

코드:
```c
{code_block}
```

재판정 기준:
- 위반이 코드에서 명확히 확인되는 경우에만 is_real_issue=true를 유지하라.
- 코드 전체 컨텍스트가 불명확하거나 위반 여부가 애매하면 is_real_issue=false로 수정하라.
- confidence를 0~100 범위에서 재산정하라 (1차와 다르게 평가해도 무방).

반드시 아래 JSON 형식만 출력하라:
{{"is_real_issue": true 또는 false, "confidence": 0~100 정수, "description": "재판정 한글 설명 (2~3문장)", "suggestion": "수정 방향 한 줄"}}""".strip()


# ─────────────────────────────────────────────────────────────────
# 결과 변환
# ─────────────────────────────────────────────────────────────────
def _make_l2_result(v: Dict[str, Any], obj: Dict[str, Any]) -> Dict[str, Any]:
    """
    L2 판정 결과를 표준 위반 형식으로 변환.

    - confidence_score(0~100): Gemini 확신도. 70 이상이면 "확정", 미만이면 "후보"
    - rule_id는 원본 그대로 유지
    - l2_confirmed=True 로 L2 판정 통과 표시
    """
    raw_score = obj.get("confidence")
    try:
        score = int(raw_score) if raw_score is not None else 80
        score = max(0, min(100, score))
    except (TypeError, ValueError):
        score = 80

    # 70점 이상 → 확정, 미만 → 후보 (is_real_issue=true이지만 확신도 낮음)
    confidence_label = "확정" if score >= 70 else "후보"

    result = {
        "source": "L2",
        "file": v.get("file") or v.get("file_path") or "",
        "line": v.get("line"),
        "rule_id": v.get("rule_id") or "UNKNOWN",
        "message": obj.get("description") or "[L2] 의미적 위반",
        "severity": v.get("severity", "medium"),
        "suggestion": obj.get("suggestion") or "",
        "confidence": confidence_label,
        "confidence_score": score,
        "l2_confirmed": True,
        "pattern_type": v.get("pattern_type", ""),
    }
    # insufficient_context: 코드 절삭 부족 피드백 전달
    if obj.get("insufficient_context"):
        result["insufficient_context"] = True
    return result


# ─────────────────────────────────────────────────────────────────
# Phase 1: Structured Evidence Injection
# ─────────────────────────────────────────────────────────────────

# KS X 3246 LEA 표준 delta 상수 (소문자 hex)
_LEA_DELTA_STANDARD_LC: List[str] = [
    "0xc3efe9db", "0x44626b02", "0x79e27c8a", "0x78df30ec",
    "0x715ea49e", "0xc785da0a", "0xe04ef22a", "0xe5c40957",
]

# 알고리즘 공개 상수 이름 패턴 → COM-003 FP 힌트
_SAFE_CONST_PATTERNS: List[str] = [
    "delta", "sbox", "s_box", "rcon", "round_const", "lookup",
    "lut", "table", "mds", "perm", "mask", "test", "kat", "vector",
]


def _build_global_flow_summary(
    symbol_graph: Dict[str, Any],
    preprocess_result: Optional[Dict[str, Any]] = None,
    max_lines: int = 20,
) -> str:
    """symbol_graph에서 전체 코드베이스 흐름 요약 생성 (Global Code Flow Summary, GCFS).

    모든 L2 프롬프트 앞에 prepend하여 AI가 코드 전체 구조를 이해한 상태에서 판정하도록 함.
    max_lines: 요약 최대 줄 수 (토큰 절약, 503 오류 방지를 위해 20줄로 제한)
    """
    if not symbol_graph:
        return ""

    definitions: Dict[str, Any] = symbol_graph.get("definitions") or {}
    call_graph: List[Dict[str, Any]] = symbol_graph.get("call_graph") or []
    type_aliases: Dict[str, Any] = symbol_graph.get("type_aliases") or {}

    if not definitions:
        return ""

    parts: List[str] = []

    # ── 1. 파일별 함수 그룹핑 ──────────────────────────────────────
    file_funcs: Dict[str, List[str]] = {}
    for fname, entries in definitions.items():
        if not isinstance(entries, list):
            entries = [entries]
        for entry in entries:
            ffile = entry.get("file") or ""
            # job_root prefix 제거 (storage/jobs/UUID/ → 상대 경로만)
            rel = re.sub(r"storage/jobs/[a-f0-9\-]+/", "", ffile)
            file_funcs.setdefault(rel, []).append(fname)

    parts.append("[모듈 구조]")
    for ffile, funcs in sorted(file_funcs.items()):
        # 시스템/벤치마크 파일 제외
        if any(kw in ffile.lower() for kw in ("benchmark", "test", "main_0tv")):
            continue
        shown = funcs[:3]
        suffix = f" ... (+{len(funcs)-3}개)" if len(funcs) > 3 else ""
        parts.append(f"  {ffile}: {', '.join(shown)}{suffix}")

    # ── 2. 공개 API 시그니처 (함수 포인터 typedef) ─────────────────
    api_aliases = {
        k: v for k, v in type_aliases.items()
        if k.endswith("_ptr") and "(*)" in v
    }
    if api_aliases:
        parts.append("\n[공개 API 시그니처]")
        for k, v in list(api_aliases.items())[:5]:
            # lea_cbc_enc_ptr → lea_cbc_enc
            func_name = k[:-4] if k.endswith("_ptr") else k
            # 파라미터 부분만 추출
            m = re.search(r"\(\*\)\s*\(([^)]*)\)", v)
            params = m.group(1)[:80] if m else v[:80]
            ret_m = re.match(r"^(\S+)\s+\(\*\)", v)
            ret = ret_m.group(1) if ret_m else "?"
            parts.append(f"  {ret} {func_name}({params})")

        # ── 4. 키 흐름 요약 ────────────────────────────────────────────
    key_setters = [e for e in call_graph if re.search(r"set_key|key_schedule|keygen", e.get("callee_name") or "", re.I)]
    key_users   = [e for e in call_graph if re.search(r"encrypt|decrypt|cbc|ctr|gcm|cfb|ofb", e.get("callee_name") or "", re.I)]
    key_zeros   = [e for e in call_graph if re.search(r"memset_s|zeroize|explicit_bzero|SecureZeroMemory|bzero", e.get("callee_name") or "", re.I)]
    if key_setters or key_users or key_zeros:
        parts.append("\n[키 생명주기 관련 호출]")
        for e in key_setters[:3]:
            caller = re.sub(r"storage/jobs/[a-f0-9\-]+/", "", e.get("caller_file") or "")
            parts.append(f"  키 생성: {caller} → {e.get('callee_name')}")
        for e in key_users[:3]:
            caller = re.sub(r"storage/jobs/[a-f0-9\-]+/", "", e.get("caller_file") or "")
            parts.append(f"  키 사용: {caller} → {e.get('callee_name')}")
        if key_zeros:
            for e in key_zeros[:2]:
                caller = re.sub(r"storage/jobs/[a-f0-9\-]+/", "", e.get("caller_file") or "")
                parts.append(f"  키 제거: {caller} → {e.get('callee_name')}")
        else:
            parts.append("  키 제거: ❌ 미발견 — 잔존 정보 제거 호출 없음")

    text = "\n".join(parts)
    # 줄 수 제한
    text_lines = text.splitlines()
    if len(text_lines) > max_lines:
        text_lines = text_lines[:max_lines] + [f"  ... (요약 {max_lines}줄 제한)"]
        text = "\n".join(text_lines)

    if not text.strip():
        return ""

    header = "=== 코드베이스 전체 구조 요약 (Global Code Flow Summary) ==="
    footer = "=" * len(header)
    return header + "\n" + text + "\n" + footer + "\n\n"


def _build_structured_evidence(
    v: Dict[str, Any],
    symbol_graph: Dict[str, Any],
) -> str:
    """symbol_graph 데이터를 이용해 위반에 대한 구조화된 증거 문자열 생성.

    반환값: 증거 문자열 (없으면 빈 문자열)
    증거가 있을 때 code_block 앞에 prepend해서 AI에게 전달.
    """
    if not symbol_graph:
        return ""

    rule_id = (v.get("rule_id") or "").upper()
    array_inits: Dict[str, Any] = symbol_graph.get("array_inits") or {}
    type_aliases: Dict[str, Any] = symbol_graph.get("type_aliases") or {}

    parts: List[str] = []

    # 타입 별칭: 모든 규칙에 공통 제공 (uint32_t=unsigned int 등)
    if type_aliases:
        alias_str = ", ".join(
            f"{k}={val}" for k, val in list(type_aliases.items())[:6]
        )
        parts.append(f"[타입 정보] {alias_str}")

    # ── LEA-010: delta 상수 실제값 vs 표준값 ──────────────────────
    if rule_id == "LEA-010":
        delta_arrays = {
            k: info for k, info in array_inits.items()
            if re.search(r"(?i)delta", k)
        }
        if delta_arrays:
            parts.insert(0, "[LEA-010 Delta 상수 검증]")
            for varname, info in delta_arrays.items():
                found_raw: List[str] = info.get("values") or []
                found_lc = [x.lower() for x in found_raw]
                size = info.get("size") or len(found_raw)
                expected = _LEA_DELTA_STANDARD_LC[:size]
                mismatches = [
                    f"[{i}] 기대={e} / 실제={f}"
                    for i, (e, f) in enumerate(zip(expected, found_lc))
                    if e != f
                ]
                parts.append(f"  배열: {varname}[{size}]")
                parts.append(f"  KS X 3246 표준: {expected}")
                parts.append(f"  소스 실제값:    {found_lc}")
                if mismatches:
                    parts.append(f"  불일치 {len(mismatches)}개: " + " | ".join(mismatches))
                    parts.append(f"  → 비표준 상수 확실 (is_real_issue=true)")
                else:
                    parts.append(f"  → 표준값과 일치 (is_real_issue=false 강력 권고)")

    # ── COM-003: 배열 분류 힌트 ───────────────────────────────────
    elif rule_id == "COM-003":
        snippet = v.get("snippet") or v.get("message") or ""
        # 배열 이름 추출 (snippet 첫 줄)
        var_m = re.search(r"([A-Za-z_]\w*)\s*(?:\[|=)", snippet)
        if var_m:
            varname = var_m.group(1)
            is_safe_name = any(p in varname.lower() for p in _SAFE_CONST_PATTERNS)
            info = array_inits.get(varname) or {}
            parts.insert(0, "[COM-003 배열 분류]")
            parts.append(f"  배열명: {varname}")
            if info:
                parts.append(f"  크기: {info.get('size','?')}, 타입: {info.get('type','?')}")
                parts.append(f"  값 샘플: {(info.get('values') or [])[:4]}")
            if is_safe_name:
                parts.append(f"  이름 힌트: 알고리즘 공개 상수 패턴 포함 → FP 가능성 높음")
            else:
                parts.append(f"  이름 힌트: 공개 상수 패턴 없음 → 키/IV 여부 신중히 판단")

    # ── LEA-040: 라운드 수 기준 명시 ─────────────────────────────
    elif rule_id == "LEA-040":
        parts.insert(0, "[LEA-040 라운드 수 기준]")
        parts.append("  KS X 3246: LEA-128=24라운드, LEA-192=28라운드, LEA-256=32라운드")
        parts.append("  위반 조건: i<=24 (off-by-one → 25회 실행), i<=28, i<=32 등")
        parts.append("  정상 조건: i<24 또는 i<ctx->rounds (키 길이별 동적)")

    # ── LEA-031/034/035: 타입 기반 포인터 판별 ───────────────────
    elif rule_id in ("LEA-031", "LEA-034", "LEA-035"):
        if type_aliases:
            parts.insert(0, f"[{rule_id} 피연산자 타입 컨텍스트]")
            parts.append("  포인터 vs 정수 피연산자 구분에 위 타입 정보를 활용하라.")

    # ── 15개 fallback 규칙: 파라미터 타입 + 배열 초기화 맥락 주입 ────────────
    _FALLBACK_RULES = {
        "LEA-005", "LEA-006", "LEA-022", "LEA-023", "LEA-024", "LEA-025",
        "LEA-032", "LEA-039", "LEA-059", "ARIA-002", "CTR-005",
        "OFB-002", "CFB-002", "CBC-005",
    }
    if rule_id in _FALLBACK_RULES and not any(rule_id in p for p in parts):
        # 파라미터 정보: definitions에서 관련 함수 찾기
        file_path_hint = v.get("file") or ""
        definitions = symbol_graph.get("definitions") or {}
        if definitions:
            related_funcs = []
            for fname, entries in list(definitions.items())[:20]:
                if not isinstance(entries, list):
                    entries = [entries]
                for entry in entries:
                    if entry.get("file") and file_path_hint and file_path_hint not in entry.get("file", ""):
                        continue
                    params = entry.get("params") or []
                    if params:
                        param_str = ", ".join(
                            p["type"] + " " + p["name"] if isinstance(p, dict) else str(p)
                            for p in params[:6]
                        )
                        related_funcs.append(f"  {fname}({param_str})")
                        break
            if related_funcs:
                parts.insert(0, f"[{rule_id} 함수 파라미터 정보]")
                parts.extend(related_funcs[:5])

        # 관련 배열 초기화값 (알고리즘 상수 맥락)
        if array_inits:
            algo_arrays = {
                k: info for k, info in array_inits.items()
                if not re.search(r"(?i)delta", k)  # delta는 LEA-010이 처리
            }
            if algo_arrays:
                parts.append(f"[배열 상수 정보]")
                for varname, info in list(algo_arrays.items())[:3]:
                    vals = (info.get("values") or [])[:4]
                    parts.append(f"  {varname}[{info.get('size','?')}]: {vals}")

    if not parts:
        return ""

    header = "=== 구조화된 증거 (Structured Evidence) ==="
    footer = "=" * len(header)
    return header + "\n" + "\n".join(parts) + "\n" + footer + "\n\n"
