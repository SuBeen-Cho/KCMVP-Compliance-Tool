"""프롬프트 빌더 — 단일/배치/재판정 + 구조화 증거 + GCFS."""

import hashlib
import re
from typing import Any, Dict, List, Optional

from app.services.rag_service import rag_ablation_disabled, search_evidence
from app.services.llm.prompt_templates import PROMPT_TEMPLATES, _get_prompt_template
from app.services.llm.triage_memory import get_few_shot_examples
from app.config import settings


# ─────────────────────────────────────────────────────────────────
# 방안 2: 파일명 기반 모드 힌트 (Micro-rubric file-mode awareness)
# ─────────────────────────────────────────────────────────────────
_MODE_KEYWORDS = {
    "cbc": "CBC",
    "ctr": "CTR",
    "gcm": "GCM",
    "ccm": "CCM",
    "cfb": "CFB",
    "ofb": "OFB",
    "ecb": "ECB",
    "cmac": "CMAC",
}

_ROLE_KEYWORDS = {
    "key_schedule": "키 스케줄",
    "keyschedule": "키 스케줄",
    "key_gen": "키 생성",
    "round": "라운드 함수",
    "block": "블록 암호",
    "encrypt": "암호화",
    "decrypt": "복호화",
    "mct": "MCT 테스트",
    "kat": "KAT 테스트",
    "test": "테스트",
}


_KCMVP_CORE_FILES = {"lea.c", "aria.c", "aes.c", "lea.h", "aria.h", "aes.h"}


def _detect_file_mode(file_path: str) -> str:
    """파일명에서 운영 모드 및 역할 힌트를 추출하여 프롬프트 삽입용 문자열 반환."""
    fname = file_path.split("/")[-1].lower() if file_path else ""
    if not fname:
        return ""

    # ── 파일 유형별 특수 힌트 (우선 적용) ──────────────────────
    # 시험/검증 파일: test, verify, kat, mct
    if any(kw in fname for kw in ("test", "verify", "kat", "mct")):
        return (
            f"\n[파일 역할 힌트] {fname}은(는) [시험 / 검증 파일]로 추정됩니다.\n"
            f"  → 시험 파일은 일부 보안 패턴(키 제로화, 에러 반환 등)이 요구사항 범위 밖일 수 있습니다.\n"
            f"  → missing 타입 위반은 실제 구현 파일에 위임된 경우 is_real_issue=false로 처리하십시오."
        )

    # KCMVP 핵심 구현 파일: lea.c, aria.c, aes.c
    if fname in _KCMVP_CORE_FILES:
        return (
            f"\n[파일 역할 힌트] {fname}은(는) [KCMVP 핵심 암호 구현 파일]입니다.\n"
            f"  → 동등한 구현 방식(변수명 변경, sizeof, enum 상수 등)으로 보안 요건을 충족했을 가능성이 높습니다.\n"
            f"  → missing 타입 위반도 코드 전체를 확인하여 동등 구현 여부를 철저히 검토하십시오."
        )

    # ── 운영 모드 + 역할 감지 (기존 로직) ──────────────────────
    parts = []
    for kw, mode in _MODE_KEYWORDS.items():
        if kw in fname:
            parts.append(f"{mode} 모드 구현 파일")
            break

    for kw, role in _ROLE_KEYWORDS.items():
        if kw in fname:
            parts.append(f"{role} 관련 파일")
            break

    if not parts:
        return ""

    role_str = " / ".join(parts)
    return (
        f"\n[파일 역할 힌트] {fname}은(는) [{role_str}]로 추정됩니다.\n"
        f"  → 이 파일에서 해당 모드/역할 관련 규칙 위반은 실제 위반(TP)일 가능성이 높습니다.\n"
        f"  → 오탐(FP)으로 판정하려면 코드에서 해당 구현이 완전히 정상임을 반드시 확인하십시오."
    )


def _missing_rule_review_guidance(rule_id: str) -> str:
    """실제 제출물형 missing 후보에 대한 규칙별 L3 검토 기준."""
    rid = (rule_id or "").upper()
    guidance = {
        # ── 공통 보안 규칙 ──────────────────────────────────────────
        "COM-001": [
            "파일이 실제 CSP/SSP(secret key, round key, private key, password, seed, DRBG state, MAC key)를 생성·보관·사용하는지 먼저 확인하라.",
            "memset(ctx, 0, sizeof(*ctx)) / memset(key, 0, keylen) / volatile 포인터 루프 제로화 패턴이 있으면 동등 구현으로 인정 → is_real_issue=false.",
            "cleanup/free/reset 함수 또는 호출자 영역에서 제로화가 수행되면 is_real_issue=false.",
            "공개 해시/다이제스트, 공개 상수, 테스트 벡터만 처리하고 SSP 증거가 없으면 is_real_issue=false.",
            "memset_s/explicit_bzero가 없어도 memset이 키·컨텍스트 변수에 직접 호출되면 false로 볼 수 있다 (confidence 50~70 검토 권고 수준으로 처리).",
        ],
        "COM-004": [
            "rand/srand/random이 보안 목적 난수인지, 테스트·인덱스·비보안 임시값인지 구분하라.",
            "서명 nonce, 키 생성, seed, IV/nonce 생성에 쓰이면 실제 위반 가능성이 높다.",
            "프로젝트 내 DRBG/OS CSPRNG 래퍼가 호출 경로에 있으면 동등 구현으로 인정할 수 있다.",
        ],
        # ── LEA 키 관리 ────────────────────────────────────────────
        "LEA-002": [
            "keylen/key_len/key_size 변수가 16/24/32 중 하나로 검증되거나, sizeof(key_struct) 등 암묵적 검증이 있으면 is_real_issue=false.",
            "함수 인자로 128/192/256이 직접 전달되거나, KEY_SIZE_128 등 enum/define이 사용되어도 동등 구현으로 인정한다.",
            "이 파일이 모드(CBC/CTR) 래퍼 파일이라면 키 길이 검증은 내부 LEA 구현 파일에 위임되었을 가능성이 높다 → confidence 50~70.",
        ],
        "LEA-013": [
            "T[], T[0..3], ctx->T, rk[], round_key[], key_state 등 어떤 이름이든 4개 워드 초기화 배열이 보이면 동등 구현으로 인정 → is_real_issue=false.",
            "호출 관계와 심볼 구조상 키 스케줄을 다른 구현에 위임하는 모드 래퍼라고 확인되면 T 초기화 부재는 해당 파일의 위반이 아님 → is_real_issue=false.",
        ],
        "LEA-044": [
            "memset(ctx, 0, ...) / memset(key, 0, ...) / volatile 루프 제로화가 cleanup/free/reset 함수 안에 있으면 is_real_issue=false.",
            "호출 관계와 데이터 소유권상 부분 구현·래퍼로 확인되면 키 제로화는 호출자 또는 소유 구현에 위임되었을 수 있다 → confidence 50~70.",
            "파일에 키를 보관하는 구조체/변수 자체가 없으면 is_real_issue=false.",
        ],
        # ── LEA 키 스케줄 회전 ──────────────────────────────────────
        "LEA-018": [
            "ROL6/ROL32(..., 6) 또는 동등한 비트 시프트 (x<<6)|(x>>26) 이 있으면 is_real_issue=false.",
            "이 파일에 ROL 연산 자체가 존재하나 다른 비트 수를 사용하는 경우는 LEA-016 위반에 해당할 수 있으며 LEA-018과는 별개다 → is_real_issue=false (LEA-018 기준).",
            "키 스케줄이 아예 없는 모드 래퍼 파일에서는 ROL6 부재가 당연 → is_real_issue=false.",
        ],
        "LEA-019": [
            "ROL11/ROL32(..., 11) 또는 동등한 비트 시프트 (x<<11)|(x>>21) 이 있으면 is_real_issue=false.",
            "ROL 연산이 다른 비트 수로 존재하는 경우 LEA-017 위반과 중복 탐지된 것일 수 있다 → is_real_issue=false (LEA-019 기준).",
            "키 스케줄 없는 파일에서는 is_real_issue=false.",
        ],
        "LEA-020": [
            "ROL13/ROL17 또는 동등한 비트 시프트가 있으면 is_real_issue=false.",
            "128-bit 전용 키 스케줄 파일이라면 ROL13/17은 불필요하므로 is_real_issue=false.",
            "ROL 배열 {1,3,6,11,13,17} 형태가 있으면 ROL13/17 포함으로 인정한다.",
        ],
        # ── LEA 암/복호화 구조 ──────────────────────────────────────
        "LEA-011": [
            "delta[] / DELTA[] / delta_const 등 이름의 8개 이상 상수 배열이 있으면 is_real_issue=false.",
            "헤더 파일이나 다른 파일에서 delta를 import/extern 참조하는 경우에도 is_real_issue=false.",
        ],
        "LEA-026": [
            "암호화 함수 진입부에서 X[0]=P[0], X[1]=P[1], X[2]=P[2], X[3]=P[3] 또는 memcpy(X, P, ...) 패턴이 있으면 is_real_issue=false.",
            "평문을 다른 변수명(pt, plaintext, block 등)으로 참조하여 초기화해도 동등 구현으로 인정한다.",
        ],
        "LEA-033": [
            "복호화 함수 진입부에서 X[0]=C[0]~X[3]=C[3] 또는 memcpy(X, C, ...) 패턴이 있으면 is_real_issue=false.",
            "암호문을 다른 변수명(ct, ciphertext, block 등)으로 참조하여 초기화해도 동등 구현으로 인정한다.",
        ],
        "LEA-038": [
            "복호화 마지막 단계에서 P[i] = X[Nr][i] 또는 memcpy(P, X_last, ...) 패턴이 있으면 is_real_issue=false.",
            "평문 출력 대입이 다른 변수명으로 수행되어도 동등 구현으로 인정한다.",
            "이 파일이 부분 구현(라운드 함수만 있는 파일)이면 최종 대입은 호출자에서 수행 → is_real_issue=false.",
        ],
        "LEA-045": [
            "uint32_t 연산(덧셈, XOR, ROL)으로 구성된 라운드 함수가 있으면 32비트 원자성을 충족한 것으로 인정한다.",
            "SIMD/벡터 연산을 쓰지 않는 순수 C 구현이면 일반적으로 원자성 위반 위험이 낮다 → confidence 50 이하 검토 권고.",
        ],
        # ── 기타 ───────────────────────────────────────────────────
        "CTR-003": [
            "카운터/nonce가 DRBG, getrandom(), os.urandom(), /dev/urandom 등 안전한 소스에서 생성되면 is_real_issue=false.",
            "clock()/time() 등 예측 가능한 소스로 카운터를 초기화하면 is_real_issue=true.",
            "카운터 초기화가 이 파일에 없으면 호출자에서 주입된 것일 수 있다 → confidence 50~70.",
        ],
        # ── 시험 아티팩트 ───────────────────────────────────────────
        "LEA-048": [
            "KAT/MMT/MCT REQUEST/RESPONSE는 구현 파일 자체보다 시험 도구/제출 패키지 아티팩트 요구사항인지 먼저 구분하라.",
            "일반 암호 라이브러리 구현 파일만 보고 확정 위반으로 단정하지 말고, 시험 파일/벡터/문서가 별도 제출될 가능성이 있으면 confidence 50~70 검토 권고로 낮춰라.",
        ],
        "LEA-062": [
            "Variable Key/Text KAT 처리는 구현 라이브러리 함수가 아니라 시험 도구/자가시험/제출 패키지 구성요소일 수 있다.",
            "시험 아티팩트가 없다는 증거가 프로젝트 전체에서 확인될 때만 위반으로 보고, 불확실하면 confidence 50~70 검토 권고로 낮춰라.",
        ],
        # ── 기타 공통 ──────────────────────────────────────────────
        "LEA-010": [
            "delta 상수가 매크로, enum, 테이블, 전처리 결과, 하드코딩 배열 중 어디에 있는지 확인하라.",
            "KS X 3246 표준 delta 값과 실제 값이 일치하면 false로 판정하라.",
            "이 파일이 키 스케줄 구현 파일이 아니면 확정 위반으로 보지 말라.",
        ],
        "GCM-LEA-002": [
            "PCLMULQDQ/GHASH 가속 부재가 필수 위반인지 성능 권고인지 구분하라.",
            "소프트웨어 GHASH가 정확하고 대상 플랫폼이 PCLMULQDQ를 보장하지 않으면 확정 위반으로 보지 말라.",
        ],
        "CMAC-002": [
            "MAC 검증이 memcmp/strcmp처럼 조기 종료되는 비교인지 확인하라.",
            "상수 시간 비교가 래퍼나 공통 함수에 있으면 false로 판정하라.",
            "검증 실패 반환값과 호출자가 KCMVP 요구에 맞게 실패를 처리하는지도 함께 확인하라.",
        ],
    }
    lines = guidance.get(rid)
    if not lines:
        return ""
    joined = "\n".join(f"  - {line}" for line in lines)
    return f"\n【{rid} missing 후보 전용 검토 기준】\n{joined}\n"


# ─────────────────────────────────────────────────────────────────
# RAG 가이드라인 텍스트 로드
# ─────────────────────────────────────────────────────────────────
def _fetch_guideline_text(rule_id: str, max_chars: int = 800) -> str:
    """search_evidence()로 가이드라인 청크 로드 → 프롬프트 주입용 텍스트 반환."""
    if rag_ablation_disabled():
        return ""
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
        print(f"[L3][RAG] guideline fetch 실패 ({rule_id}): {e}")
        return ""


# ─────────────────────────────────────────────────────────────────
# pattern_type별 코드 절삭 범위 (라인 수)
# missing은 위치 정보가 없으므로 절삭 불필요 → L3 호출 자체를 스킵
# ─────────────────────────────────────────────────────────────────
_WINDOW_BY_PATTERN_TYPE: Dict[str, int] = {
    "regex": 30,
    "semantic": 50,
    "ast": 50,
    "missing": 0,
}

# ─────────────────────────────────────────────────────────────────
# L3 결과 캐시 (스니펫 해시 기반, in-memory)
# ─────────────────────────────────────────────────────────────────
_l3_cache: Dict[str, Dict[str, Any]] = {}


_L3_PROMPT_CACHE_VERSION = "2026-08-11-semantics-v1"

_DETECTION_SEMANTICS = frozenset({
    "prohibited_presence", "required_absence", "structural_violation", "unknown",
})


def _detection_semantics(v: Dict[str, Any]) -> str:
    """Return a closed logical trigger, with legacy candidate compatibility."""
    explicit = str(v.get("detection_semantics") or "").strip().lower()
    if explicit in _DETECTION_SEMANTICS:
        return explicit
    pattern_type = str(v.get("pattern_type") or "").strip().lower()
    if pattern_type == "regex":
        return "prohibited_presence"
    if pattern_type == "ast" or v.get("rule_id") == "COM-005":
        return "structural_violation"
    return "required_absence"


def _semantics_note(v: Dict[str, Any]) -> str:
    semantics = _detection_semantics(v)
    if semantics == "required_absence":
        return "패턴 부재 위반 — 필수 요건의 부재를 검증"
    if semantics == "structural_violation":
        return "구조 위반 — 정적 분석이 확인한 구조적 모순·순서 위반의 영향을 검증"
    if semantics == "unknown":
        return "탐지 의미 불명 — 명시적 근거 없이는 후보를 제거하지 않음"
    return "금지 패턴 존재 위반 — 관찰된 패턴이 실제 금지 행위인지 검증"


def _l3_cache_key(
    rule_id: str,
    code_block: str,
    *,
    guideline_text: str = "",
    violation_message: str = "",
    detection_semantics: str = "",
    pattern_type: str = "",
    ast_evidence: str = "",
    ai_context: str = "",
) -> str:
    """Return a cache key namespaced by every input that can alter the verdict."""
    provider = settings.L3_PROVIDER
    if provider == "openai":
        model = settings.LLM_MODEL_L3
    elif provider == "local":
        model = settings.LOCAL_LLM_HF_MODEL or settings.LOCAL_LLM_MODEL
    else:
        model = settings.GEMINI_L3_MODEL
    rag_mode = "no-rag" if rag_ablation_disabled() else "rag"
    payload = "\x1f".join((
        _L3_PROMPT_CACHE_VERSION,
        provider,
        model,
        rag_mode,
        rule_id,
        detection_semantics,
        pattern_type,
        hashlib.sha256(ast_evidence.encode()).hexdigest(),
        hashlib.sha256(ai_context.encode()).hexdigest(),
        hashlib.sha256(violation_message.encode()).hexdigest(),
        hashlib.sha256(guideline_text.encode()).hexdigest(),
        hashlib.sha256(code_block.encode()).hexdigest(),
    ))
    return hashlib.sha256(payload.encode()).hexdigest()[:24]


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
      L3는 AST가 확인한 구조적 사실을 검증하는 역할 (재확인 아닌 영향도 판단).
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

    # Triage Memory: 규칙별 TP/FP few-shot 예시 주입
    few_shot_section = get_few_shot_examples(rule_id)

    # 방안 2: 파일명 기반 모드/역할 힌트
    file_mode_hint = _detect_file_mode(file_path)

    if use_cot:
        reasoning_section = """
판정 단계 (아래 순서로 분석 후 JSON 출력):
STEP 1 [관찰]: 코드에서 실제로 발견한 패턴·함수·값을 구체적으로 기술하라.
STEP 2 [비교]: 판정 기준 및 가이드라인과 비교하여 차이·부재 항목을 명확히 설명하라.
STEP 3 [결론]: 위 분석을 토대로 아래 JSON 객체를 출력하라."""
    else:
        reasoning_section = ""

    pattern_type = v.get("pattern_type", "")
    detection_semantics = _detection_semantics(v)
    is_absence = detection_semantics == "required_absence"
    semantics_note = _semantics_note(v)
    missing_rule_guidance = (
        _missing_rule_review_guidance(rule_id)
        if pattern_type == "missing"
        else ""
    )

    if is_absence:
        # missing 타입은 프로젝트 전체에서 패턴 부재 → 다른 파일/다른 구현 방식 확인 필요
        _missing_extra = ""
        if pattern_type == "missing":
            _missing_extra = """
  ④ 여러 파일이 제공된 경우, 어느 파일이든 요구사항이 동등한 방식으로 구현되어 있으면 false
  ⑤ 매직넘버(16, 32 등)나 sizeof()로 블록 크기/키 길이를 암묵적으로 사용할 때 → 명시적 상수 선언이 없어도 동등 구현으로 인정
  ⑥ 하드코딩된 회전량(<<1, <<3, <<6, >>3, >>5, >>9 등)이 규격 회전량과 일치하면 동등 구현으로 인정"""
        judgment_criteria = f"""{missing_rule_guidance}판정 지침 (엄격 적용):
【이 위반은 "필수 보안 패턴의 부재"가 위반 — L1이 특정 패턴이 없음을 감지했음】
【중요】missing 후보는 L1 단독으로 확정하지 말고, 코드 역할·동등 구현·별도 래퍼/시험 도구 존재 가능성을 함께 판단하라.
【오탐(is_real_issue=false) 판정 조건 — 아래 중 하나라도 해당하면 반드시 false】
  ① 변수명·배열명·주석이 S-box, delta, lookup_table, test_vector, KAT 등 공개 상수를 암시할 때
  ② L1 탐지 메시지의 필수 패턴이 다른 방식(동등한 구현)으로 이미 충족되어 있을 때
  ③ 판정 기준에 명시된 허용 예외에 해당할 때{_missing_extra}
【위반(is_real_issue=true) 판정 조건】
  ● L1 메시지에서 언급한 필수 패턴이 코드 내에 실제로 없음
  ● 허용 예외에 해당하지 않음
  ● confidence ≥ 65
  ※ "패턴 부재" 확인: 함수 전체가 보이면 부재 여부를 판단할 수 있음
  ※ insufficient_context=true는 코드가 실제로 너무 짧아 판단 자체가 불가한 경우에만 사용
【confidence 3단계 기준 (missing 타입 전용)】
  - 90~100: 확실한 위반 — 필수 패턴이 코드 전체에 없고, 동등 구현·위임 증거도 없음
  - 65~84 : 검토 권고 — 패턴이 없지만 래퍼/시험 파일 가능성·다른 파일 위임 가능성 존재
  - false  : 동등 구현이 코드에서 직접 확인됨 (변수명만 다른 경우 포함)"""
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
    # AST 체커가 이미 확인한 구조적 사실을 별도 섹션으로 명시하여 L3가
    # "위반인가?" 대신 "이 AST 발견이 실제 보안 문제인가?"에 집중하도록 유도
    pattern_type_val = v.get("pattern_type", "")
    ast_evidence_val = v.get("ast_evidence", "")  # 체커가 직접 설정한 구조 증거 (선택)
    if pattern_type_val == "ast" and ast_evidence_val:
        ast_fact = ast_evidence_val
        ast_evidence_section = (
            f"\n【C&A Phase 1: AST 구조 분석 결과 (검증된 사실)】\n"
            f"  정적 AST 분석이 다음 구조적 사실을 확인했습니다:\n"
            f"  → {ast_fact}\n"
            f"  ※ 위 사실은 AST 파싱으로 확인된 것입니다. L3 판정 목표:\n"
            f"  ※ '이 구조적 사실이 실제 보안 취약점인가?' (구조 재확인 불필요)"
        )
    else:
        ast_evidence_section = ""

    return f"""당신은 KCMVP(KS X 19790) 암호모듈 보안 전문 리뷰어입니다.
당신의 최우선 목표는 **실제 위반(TP)을 절대 놓치지 않는 것**입니다.
확실한 오탐만 제거하고, 의심스러운 경우 반드시 위반으로 유지하십시오.
판정 전 반드시: (1) 코드의 암호학적 기능을 파악하고, (2) 규칙 요건과 대조하고, (3) 위반 가능성을 우선 검토하십시오.

파일: {file_path}
라인: {line}
rule_id: {rule_id}
판정 기준: {template}{ctx_line}{guideline_section}{few_shot_section}{file_mode_hint}
L1 탐지 메시지: {l1_msg}{ast_evidence_section}
탐지 의미: {semantics_note}

코드:
```c
{code_block}
```
{reasoning_section}
{judgment_criteria}
- confidence: 판정 확신도 (0=오탐/불확실, 100=위반 확실)
- insufficient_context: 코드 절삭이 너무 짧아 판단 불가이면 true
- evidence_type: direct_violation, equivalent_impl, delegated_to_other_file, not_applicable_scope, insufficient_context 중 하나
- requirement_scope: file, function, project, artifact, unknown 중 하나
- concrete_evidence_line: 현재 코드 블록 안에서 오탐 근거가 되는 실제 코드 한 줄. 없으면 빈 문자열
- delegated_target: 다른 함수/파일에 위임되어 오탐이라고 판단한 경우 대상 함수 또는 파일. 없으면 빈 문자열
- supporting_symbol: 동등 구현 또는 위임을 뒷받침하는 함수명/상수명/변수명. 없으면 빈 문자열
- removal_risk: low, medium, high 중 하나. 오탐 제거 시 실제 위반을 놓칠 위험도

반드시 아래 JSON 형식의 객체만 출력하라:
{{"is_real_issue": true 또는 false, "confidence": 0~100 정수, "description": "한글 설명 (2~3문장)", "suggestion": "수정 방향 한 줄", "insufficient_context": false, "evidence_type": "direct_violation", "requirement_scope": "file", "concrete_evidence_line": "", "delegated_target": "", "supporting_symbol": "", "removal_risk": "medium"}}""".strip()


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
        semantics = _detection_semantics(v)
        missing_guide = (
            _missing_rule_review_guidance(rule_id).replace("\n", "\n  ")
            if ptype == "missing"
            else ""
        )
        threshold_note = (
            "  [패턴 부재 위반 — confidence≥65 시 true, insufficient_context는 코드 자체가 너무 짧을 때만]\n"
            if semantics == "required_absence" else (
                "  [구조 위반 — 명시적 구조 모순이 확인되고 confidence≥75 시 true]\n"
                if semantics == "structural_violation" else
                "  [패턴 존재 위반 — confidence≥75 시 true]\n"
            )
        )
        # C&A: AST 위반에 구조 증거 섹션 추가
        ast_ev = v.get("ast_evidence", "")
        l1_msg_batch = v.get("message") or ""
        if ptype == "ast" and ast_ev:
            ast_fact = ast_ev
            ast_section = f"  【C&A AST 분석 결과】 {ast_fact}\n  ※ 위 구조적 사실 기반으로 보안 영향도를 판단하라.\n"
        else:
            ast_section = ""
        # Triage Memory: 규칙별 few-shot 예시 (배치에서는 간략히 FP 1건만)
        batch_few_shot = get_few_shot_examples(rule_id, max_fp=1, max_tp=0)
        batch_few_shot_part = f"\n{batch_few_shot}" if batch_few_shot else ""
        items_text_parts.append(
            f"[위반 {i + 1}]\n"
            f"  rule_id: {rule_id}\n"
            f"  line: {v.get('line') or 'N/A'}\n"
            f"  판정 기준: {template}{ctx_part}{guide_part}{batch_few_shot_part}"
            f"\n  탐지 의미: {_semantics_note(v)}"
            f"\n{threshold_note}"
            f"{missing_guide}"
            f"{ast_section}"
            f"  L1 탐지: {l1_msg_batch}\n"
            f"  코드:\n```c\n{code_block}\n```"
        )
    items_text = "\n\n".join(items_text_parts)
    n = len(batch)
    has_absence = any(
        _detection_semantics(entry["violation"]) == "required_absence"
        for entry in batch
    )
    absence_context_note = (
        ', 단 "패턴 부재 위반"은 함수 전체가 보이면 판단 가능'
        if has_absence else ""
    )
    absence_policy = """
  - 패턴 부재 위반 ([패턴 부재 위반] 표시된 항목): 필수 패턴이 없음이 확인되고 confidence≥65일 때
【패턴 부재 위반 confidence 3단계 기준】
  - 90~100: 확실한 위반 — 필수 패턴이 없고 동등 구현·위임 증거도 없음
  - 65~84 : 검토 권고 — 패턴이 없지만 래퍼/시험 파일 가능성·다른 파일 위임 가능성 존재
  - false  : 동등 구현이 코드에서 직접 확인됨 (변수명만 다른 경우 포함)""" if has_absence else ""

    # 방안 2: 파일명 기반 모드/역할 힌트
    file_mode_hint = _detect_file_mode(file_path)

    return f"""당신은 KCMVP(KS X 19790) 암호모듈 보안 전문 리뷰어입니다.
당신의 최우선 목표는 **실제 위반(TP)을 절대 놓치지 않는 것**입니다.
확실한 오탐만 제거하고, 의심스러운 경우 반드시 위반으로 유지하십시오.
판정 전 반드시: (1) 코드의 암호학적 기능을 파악하고, (2) 규칙 요건과 대조하고, (3) 위반 가능성을 우선 검토하십시오.

파일: {file_path}{file_mode_hint}

아래 {n}개의 위반 후보를 각각 독립적으로 판정하라.

【오탐(is_real_issue=false) 기준 — 아래 중 하나라도 해당하면 반드시 false】
  ① S-box·delta·lookup_table·test_vector·KAT 등 공개 상수임이 변수명·주석으로 드러날 때
  ② 코드 컨텍스트 불충분으로 확신 불가 시 (→ insufficient_context=true{absence_context_note})
  ③ 판정 기준의 허용 예외(테스트 목적, KAT, 단일 블록)에 해당할 때
  ④ 위반 증거가 약하거나 다른 해석이 가능할 때
  ⑤ LEA 알고리즘 규칙인데 파일이 LEA와 무관한 기능(ARIA, SHA, DRBG 등)만 구현할 때
【위반(is_real_issue=true) 기준】
  - 패턴 존재 위반: 코드에서 명확히 확인되고 confidence≥75일 때만
  - 구조 위반: 정적 분석의 명시적 구조 모순·순서 위반이 실제 보안 문제이고 confidence≥75일 때
{absence_policy}

{items_text}

반드시 아래 JSON 배열 형식만 출력하라 (입력과 동일한 순서, idx는 1부터):
[
  {{"idx": 1, "is_real_issue": true 또는 false, "confidence": 0~100 정수, "description": "한글 설명", "suggestion": "수정 방향 한 줄", "insufficient_context": false, "evidence_type": "direct_violation", "requirement_scope": "file", "concrete_evidence_line": "", "delegated_target": "", "supporting_symbol": "", "removal_risk": "medium"}},
  {{"idx": 2, "is_real_issue": true 또는 false, "confidence": 0~100 정수, "description": "한글 설명", "suggestion": "수정 방향 한 줄", "insufficient_context": false, "evidence_type": "equivalent_impl", "requirement_scope": "function", "concrete_evidence_line": "동등 구현 코드 한 줄", "delegated_target": "", "supporting_symbol": "함수명 또는 심볼명", "removal_risk": "low"}}
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
    semantics = _detection_semantics(v)
    absence_policy = (
        "필수 요건 부재 후보이므로 불확실성만으로 false로 변경하지 말고, "
        "동등 구현·다른 파일 위임의 구체적 증거가 있을 때만 false로 판정하라."
        if semantics == "required_absence" else
        "위반이 코드에서 명확히 확인되는 경우에만 true를 유지하라."
    )
    return f"""당신은 KCMVP(KS X 19790) 암호모듈 보안 수석 심사관입니다.
최우선 목표: False Positive(오탐) 최소화 — 위반이 명확히 확인되는 경우에만 true를 유지하십시오.
아래 항목은 1차 AI 판정에서 신뢰도 {first_conf}점(경계값)으로 판정되었습니다.
더 엄격하고 신중하게 재검토하십시오.

파일: {file_path}
rule_id: {rule_id}
탐지 의미: {_semantics_note(v)}
판정 기준: {template}{guideline_section}
1차 판정 설명: {first_desc}

코드:
```c
{code_block}
```

재판정 기준:
- {absence_policy}
- 코드 전체 컨텍스트가 불명확하면 insufficient_context=true로 표시하고 후보를 유지하라.
- confidence를 0~100 범위에서 재산정하라 (1차와 다르게 평가해도 무방).

반드시 아래 JSON 형식만 출력하라:
{{"is_real_issue": true 또는 false, "confidence": 0~100 정수, "description": "재판정 한글 설명 (2~3문장)", "suggestion": "수정 방향 한 줄", "insufficient_context": false, "evidence_type": "direct_violation", "requirement_scope": "file", "concrete_evidence_line": "", "delegated_target": "", "supporting_symbol": "", "removal_risk": "medium"}}""".strip()


# ─────────────────────────────────────────────────────────────────
# 결과 변환
# ─────────────────────────────────────────────────────────────────
def _make_l3_result(v: Dict[str, Any], obj: Dict[str, Any]) -> Dict[str, Any]:
    """
    L3 판정 결과를 표준 위반 형식으로 변환.

    - confidence_score(0~100): Gemini 확신도. 70 이상이면 "확정", 미만이면 "후보"
    - rule_id는 원본 그대로 유지
    - l3_confirmed=True 로 L3 판정 통과 표시
    """
    raw_score = obj.get("confidence")
    try:
        score = int(raw_score) if raw_score is not None else 80
        score = max(0, min(100, score))
    except (TypeError, ValueError):
        score = 80

    pattern_type = (v.get("pattern_type") or "").lower()
    if score >= 85:
        confidence_label = "확정"
    elif pattern_type == "missing" or obj.get("insufficient_context"):
        confidence_label = "검토권고"
    elif score >= 70:
        confidence_label = "확정"
    else:
        confidence_label = "후보"

    result = {
        "source": "L3",
        "file": v.get("file") or v.get("file_path") or "",
        "line": v.get("line"),
        "rule_id": v.get("rule_id") or "UNKNOWN",
        "message": obj.get("description") or "[L3] 의미적 위반",
        "severity": v.get("severity", "medium"),
        "suggestion": obj.get("suggestion") or "",
        "confidence": confidence_label,
        "confidence_score": score,
        "l3_confirmed": True,
        "pattern_type": v.get("pattern_type", ""),
        "l3_is_real_issue": bool(obj.get("is_real_issue")),
        "l3_raw_confidence": score,
        "l3_file_role": obj.get("file_role", ""),
        "l3_evidence_type": obj.get("evidence_type", ""),
        "l3_risk_tier": obj.get("risk_tier", ""),
        "l3_removal_allowed": bool(obj.get("removal_allowed", False)),
        "l3_removal_blocked_reason": obj.get("removal_blocked_reason"),
        "l3_concrete_evidence_line": obj.get("concrete_evidence_line", ""),
        "l3_delegated_target": obj.get("delegated_target", ""),
        "l3_supporting_symbol": obj.get("supporting_symbol", ""),
        "l3_removal_risk": obj.get("removal_risk", ""),
        "detection_semantics": _detection_semantics(v),
    }
    # Frozen-snapshot experiments require an occurrence-level identity.  Keep it
    # opaque to the model but propagate it through the structured result.
    if v.get("candidate_id"):
        result["candidate_id"] = str(v["candidate_id"])
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

    모든 L3 프롬프트 앞에 prepend하여 AI가 코드 전체 구조를 이해한 상태에서 판정하도록 함.
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
        "LEA-032", "LEA-039", "LEA-059", "CTR-005",
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


# ─────────────────────────────────────────────────────────────────
# Priority 2: Flow-Sensitive LLM Context (ZeroFalse style)
# arxiv 2510.02534: flow-sensitive trace reconstruction improves
# LLM judgment accuracy by providing macro definitions + call paths.
# 주 대상: LEA-024, LEA-030, LEA-035 (pycparser MAKE_FUNC parse failure)
# ─────────────────────────────────────────────────────────────────

# MAKE_FUNC-style 매크로를 사용하는 규칙: pycparser가 이를 파싱하지 못해 None 반환
_MAKE_FUNC_RULES = {"LEA-024", "LEA-030", "LEA-035"}

# 매크로 정의 추출 정규식 (#define NAME(...) body 형태)
_MACRO_DEF_RE = re.compile(
    r"^\s*#\s*define\s+(\w+)\s*(\([^)]*\))?\s*(.+)$",
    re.MULTILINE,
)

# MAKE_FUNC 계열 매크로 패턴 (함수 인라인 확장형)
_MAKE_FUNC_RE = re.compile(
    r"(?i)\b(MAKE_FUNC|MAKE_ENC|MAKE_DEC|MAKE_KEY|INLINE_FUNC|DEFINE_FUNC)\b",
)


def _build_flow_context(
    v: Dict[str, Any],
    file_content: str,
    symbol_graph: Optional[Dict[str, Any]] = None,
    max_macros: int = 15,
    max_callers: int = 5,
) -> str:
    """Flow-sensitive context for L3 LLM judgment.

    Addresses Cause B (pycparser MAKE_FUNC failure): when pycparser cannot parse
    MAKE_FUNC-style macros, it returns None and the fallback fires.  This function
    extracts the macro definitions visible in the file so the LLM can understand
    the actual code structure rather than relying on incomplete snippets.

    Also extracts caller information from symbol_graph to provide call-path context
    (ZeroFalse §3.2: caller-context injection).

    Parameters
    ----------
    v            : violation dict
    file_content : raw content of the file containing the violation
    symbol_graph : optional symbol graph for call-path extraction
    max_macros   : maximum number of macro definitions to include
    max_callers  : maximum number of callers to include

    Returns
    -------
    str : flow context string (empty if nothing useful found)
    """
    if not file_content:
        return ""

    rule_id = (v.get("rule_id") or "").upper()
    parts: List[str] = []

    # ── 1. #define 매크로 추출 ──────────────────────────────────────
    macro_defs = _MACRO_DEF_RE.findall(file_content)
    if macro_defs:
        # MAKE_FUNC 계열 매크로 우선, 그 다음 일반 함수형 매크로
        make_func_macros = [
            m for m in macro_defs
            if _MAKE_FUNC_RE.search(m[0]) or _MAKE_FUNC_RE.search(m[2])
        ]
        func_macros = [
            m for m in macro_defs
            if m[1]  # 파라미터 있는 함수형 매크로
            and m not in make_func_macros
        ]
        const_macros = [
            m for m in macro_defs
            if not m[1]  # 단순 상수 매크로 (파라미터 없음)
            and len(m[2]) < 60  # 짧은 것만
        ]

        selected = make_func_macros[:5] + func_macros[:5] + const_macros[:5]
        selected = selected[:max_macros]

        if selected:
            parts.append("[파일 내 매크로 정의 (MAKE_FUNC 포함)]")
            for name, params, body in selected:
                param_str = params if params else ""
                parts.append(f"  #define {name}{param_str} {body[:80].strip()}")

    # ── 2. MAKE_FUNC 위반 규칙 전용: 파일 내 함수 정의 패턴 확인 ──
    if rule_id in _MAKE_FUNC_RULES:
        # MAKE_FUNC 계열 매크로가 파일에 있는지 확인
        has_make_func = bool(_MAKE_FUNC_RE.search(file_content))
        if has_make_func:
            parts.append(
                "\n[MAKE_FUNC 감지] 이 파일은 MAKE_FUNC 계열 매크로로 함수를 정의합니다."
            )
            parts.append(
                "  pycparser는 이 매크로를 직접 파싱할 수 없으므로 아래 코드를 직접 분석하십시오."
            )
            # 매크로가 확장하는 실제 함수 패턴 찾기
            func_pattern = re.compile(
                r"MAKE_\w+\s*\(\s*(\w+)\s*,",
                re.IGNORECASE,
            )
            func_usages = func_pattern.findall(file_content)
            if func_usages:
                parts.append(f"  생성되는 함수들: {', '.join(func_usages[:8])}")

    # ── 3. 호출 경로 (symbol_graph call_graph) ──────────────────────
    if symbol_graph:
        call_graph: List[Dict[str, Any]] = symbol_graph.get("call_graph") or []
        file_hint = (v.get("file") or "").split("/")[-1]
        func_name = v.get("func_name") or ""

        # 위반 파일/함수의 callers 찾기
        callers: List[str] = []
        for edge in call_graph:
            callee = edge.get("callee_name") or ""
            caller_file = (edge.get("caller_file") or "").split("/")[-1]
            caller_func = edge.get("caller_name") or ""

            # 대상 함수가 호출되는 경우
            if func_name and func_name in callee:
                callers.append(f"  {caller_file}::{caller_func} → {callee}")
            elif file_hint and caller_file == file_hint and caller_func:
                callers.append(f"  {caller_file}::{caller_func} → {callee}")

        if callers:
            parts.append(f"\n[호출 경로 (Call Path)]")
            parts.extend(callers[:max_callers])

    if not parts:
        return ""

    header = "=== 흐름 민감 컨텍스트 (Flow-Sensitive Context) ==="
    footer = "=" * len(header)
    return header + "\n" + "\n".join(parts) + "\n" + footer + "\n\n"
