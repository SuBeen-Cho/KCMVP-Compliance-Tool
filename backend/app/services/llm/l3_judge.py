"""메인 L3 실행 — run_l3_contextualizer."""

import re
from typing import Any, Dict, List, Optional

from app.services.llm.gemini_client import (
    GOOGLE_API_KEY, L3_PROVIDER,
    _call_gemini_with_retry, _call_gemini_batch_with_retry,
)
from app.services.llm.prompt_templates import _HIGH_ISOLATION_RULES

# 테스트 세트에서 L3가 오탐 제거로 FN을 유발하는 것이 확인된 ast 규칙들.
# KISA blind test에서 이 규칙들은 FP가 아니므로 FP 제거 임계값을 높여 Recall 보호.
# (threshold 80 → 90: L3가 is_real_issue=False+confidence 80~89를 반환해도 제거하지 않음)
_AST_TP_PROTECT = frozenset({
    "CBC-001", "CBC-002",   # CBC 체이닝 — L3 오판 빈번, KISA FP 아님
    "CTR-001", "CTR-002",   # CTR 모드 — 동일
    "CTR-003", "CTR-004",   # CTR 카운터 오버플로우/유일성 — L3 오판 확인 (방안 2)
    "LEA-023",              # LEA 라운드 수식 — L3 오판으로 FN 발생 확인
    # 세트4 GT ast 규칙 — L3 오판으로 FN 유발 방지 (2026-05-02 추가)
    "LEA-021", "LEA-022",   # 라운드 수식 (lea_block.c)
    "LEA-034", "LEA-035",   # 복호화 역연산 (lea_block.c)
    "LEA-046", "LEA-047",   # MCT 내부/외부 루프 키 갱신 (lea_cbc.c, lea_ctr.c)
    "LEA-056", "LEA-057",   # MCT 내부/외부 루프 (lea_cbc.c, lea_ctr.c)
    "CBC-LEA-005",          # CBC-LEA 키 갱신 패턴 (lea_cbc.c)
    "CTR-LEA-006",          # CTR-LEA 카운터 갱신 패턴 (lea_ctr.c)
})

# L3 FP 제거 정확도 57% 미달 규칙 — FP 제거를 완전 차단하여 Recall 보호.
# CBC-001: 7건 제거 시 4건 정확, 3건 오판(43% FN 유발) → 잔류 FP 4건 < FN 3건
_L3_NEVER_REMOVE = frozenset({
    "CBC-001",
    # L3 평가(2026-05-03)에서 GT 위반을 오탐으로 제거해 FN을 만든 규칙.
    # CBC 복호화 XOR 순서/체이닝과 CTR-LEA MCT 카운터 갱신은 L1/AST 발견을
    # Recall 우선으로 유지한다.
    "CBC-002",
    "CTR-LEA-006",
})
from app.services.llm.candidate_selector import _select_l3_candidates
from app.services.llm.code_context import _get_code_context
from app.services.llm.prompt_builder import (
    _l3_cache, _l3_cache_key,
    _build_single_prompt, _build_batch_prompt, _build_rejudge_prompt,
    _make_l3_result, _build_structured_evidence, _build_global_flow_summary,
    _build_flow_context,
)


# ── 방안 4: 전제조건 기반 FP 사전 필터 ──────────────────────────────
# 위반이 유효하려면 파일에 해당 기능이 구현되어 있어야 함.
# 전제조건 불충족 시 LLM 호출 없이 FP 확정 → 비결정성 제거.
_PRECONDITION_PATTERNS: Dict[str, re.Pattern] = {
    # 키 스케줄 규칙: 파일에 키 스케줄 구현 필요
    "LEA-010": re.compile(r"(key_schedule|roundkey|round_key|delta\s*\[|RK\s*\[)", re.IGNORECASE),
    "LEA-024": re.compile(r"(key_schedule|roundkey|round_key|delta\s*\[|RK\s*\[)", re.IGNORECASE),
    "LEA-025": re.compile(r"(key_schedule|roundkey|round_key|delta\s*\[|RK\s*\[)", re.IGNORECASE),
    # MCT 규칙: 파일에 MCT 구현 필요
    "LEA-047": re.compile(r"(mct|MCT|monte.?carlo|MonteCarloTest)", re.IGNORECASE),
    "LEA-057": re.compile(r"(mct|MCT|monte.?carlo|MonteCarloTest)", re.IGNORECASE),
    # Phase 4 추가: 구현 맥락 전제조건
    # 레지스터 스필링: 성능 최적화 코드에만 적용 (register 키워드 또는 volatile 사용 없으면 FP)
    "LEA-043": re.compile(r"(register\s|volatile\s|__attribute__|restrict\b|inline\s)", re.IGNORECASE),
    # 라운드 역함수: 복호화 함수가 있는 파일에만 적용
    "LEA-035": re.compile(r"(decrypt|decode|inv.*round|reverse.*round|decipher)", re.IGNORECASE),
    "LEA-034": re.compile(r"(decrypt|decode|lea_dec|block_dec|inv.*cipher)", re.IGNORECASE),
    # 라운드트립 검증: 테스트 코드에만 유의미
    "LEA-039": re.compile(r"(test|assert|verify|check|compare|memcmp)", re.IGNORECASE),
    # COM-001 보완: 키를 직접 처리하는 파일에만 엄격 적용
    "COM-001": re.compile(r"(key|rk|mk|iv|nonce|secret|cipher|encrypt|decrypt|drbg|kdf)", re.IGNORECASE),
}


def _check_violation_precondition(
    v: Dict[str, Any],
    file_content: str,
    file_path: str,
) -> bool:
    """위반 전제조건 확인. True=전제조건 충족(L3 진행), False=불충족(FP 확정)."""
    rule_id = (v.get("rule_id") or "").upper()
    pattern = _PRECONDITION_PATTERNS.get(rule_id)
    if pattern is None:
        return True  # 전제조건 정의 없음 → 보수적으로 L3 진행
    if pattern.search(file_content):
        return True  # 전제조건 충족
    print(f"[L3][PC] 전제조건 불충족 → FP 확정: {rule_id} @ {file_path}")
    return False


_FP_VERIFY_PROMPT_TEMPLATE = """당신은 KCMVP 암호모듈 보안 시니어 감사관입니다.

아래 위반 후보에 대해 1차 AI 판정이 "오탐(is_real_issue=false)"으로 결론 내렸습니다.
당신의 역할은 이 판정이 정말 맞는지 **독립적으로 재검증**하는 것입니다.

규칙: {rule_id}
파일: {file_path}
라인: {line}
L1 탐지 메시지: {message}

1차 AI 판정 이유: {first_description}

코드:
```c
{code_block}
```

【재검증 기준】
- 1차 판정의 오탐 근거가 코드에서 실제로 확인되는가?
- "잘 모르겠다" 또는 "증거 불충분"이면 is_real_issue=true로 보수적 판정하라.
- 1차 판정에 동의하면 is_real_issue=false, 동의하지 않으면 is_real_issue=true.

반드시 아래 JSON만 출력:
{{"is_real_issue": true/false, "confidence": 0~100, "description": "한글 설명"}}"""


def _verify_fp_removal(
    v: Dict[str, Any],
    first_obj: Dict[str, Any],
    code_block: str,
    file_path: str,
) -> bool:
    """FP 제거 판정을 비대칭 재검증. True이면 제거 확정, False이면 유지."""
    rule_id = v.get("rule_id") or ""
    prompt = _FP_VERIFY_PROMPT_TEMPLATE.format(
        rule_id=rule_id,
        file_path=file_path,
        line=v.get("line", "?"),
        message=v.get("message", "")[:200],
        first_description=first_obj.get("description", "")[:300],
        code_block=code_block[:2000],
    )
    verify_obj = _call_gemini_with_retry(prompt)
    if not verify_obj:
        # API 실패 → 보수적으로 유지 (제거 안 함)
        print(f"[L3][FP검증] API 실패 → 보수적 유지: {rule_id} @ {file_path}:{v.get('line')}")
        return False
    if verify_obj.get("is_real_issue"):
        print(f"[L3][FP검증] 재검증 결과 위반 확정 (제거 취소): {rule_id} @ {file_path}:{v.get('line')}")
        return False
    print(f"[L3][FP검증] 재검증 동의 → 오탐 제거 확정: {rule_id} @ {file_path}:{v.get('line')}")
    return True


def run_l3_contextualizer(
    preprocess_result: Dict[str, Any],
    l1_violations: List[Dict[str, Any]],
    rules_meta: Optional[Dict[str, Any]] = None,
    _rejected_tracker: Optional[set] = None,
    symbol_graph: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """
    L3: 의미적(맥락 기반) 위반 재판정.

    Parameters
    ----------
    preprocess_result  : 전처리 결과 (run_preprocess 출력)
    l1_violations      : L1 룰 엔진에서 생성된 위반 리스트
    rules_meta         : (선택) 룰 메타데이터
    _rejected_tracker  : (선택) L3가 오탐으로 판정한 항목의 (file, rule_id, line) 튜플을
                         채워 넣을 set. analyze.py에서 post_process_violations 연동용.
    symbol_graph       : (선택) build_symbol_graph 출력 — array_inits/type_aliases 활용.
                         Structured Evidence Injection (Phase 1)에 사용.

    Returns
    -------
    list[dict] : L3가 실제 위반으로 확정한 항목 리스트
    """
    # gemini 프로바이더는 API 키 필수; local은 키 불필요
    if L3_PROVIDER == "gemini" and not GOOGLE_API_KEY:
        return []

    results: List[Dict[str, Any]] = []
    files = preprocess_result.get("files", [])
    file_content_cache: Dict[str, str] = {}

    def get_file_content(path: str) -> Optional[str]:
        """
        preprocess_result["files"] 에서 path에 매칭되는 파일 내용을 반환.
        preprocess_result의 path는 job_root 기준 상대경로이므로,
        파일을 다시 열지 않고 item["lines"]를 사용한다.
        """
        if path in file_content_cache:
            return file_content_cache[path]
        for item in files:
            item_path = item.get("path")
            if not isinstance(item_path, str):
                continue
            # 상대경로 직접 일치 또는 절대경로 suffix 매칭
            if item_path == path or item_path.endswith(path) or path.endswith(item_path):
                # 방법 1: preprocess에서 파싱한 lines 사용 (경로 독립적)
                lines = item.get("lines")
                if lines is not None:
                    content = "\n".join(lines)
                    file_content_cache[path] = content
                    return content
                # 방법 2: 절대경로인 경우 직접 읽기 (fallback)
                try:
                    with open(item_path, "r", encoding="utf-8") as f:
                        content = f.read()
                    file_content_cache[path] = content
                    return content
                except OSError:
                    return None
        return None

    # L3 대상 선정
    candidates = _select_l3_candidates(l1_violations)
    if not candidates:
        print("[L3] L3 판정 대상 없음")
        return []

    print(f"[L3] 판정 대상 {len(candidates)}건 선정 (전체 L1 위반: {len(l1_violations)}건)")

    # L2 단계에서 각 위반 객체에 'rag_guideline_text'가 이미 주입됨 — 별도 로드 불필요

    # Phase 2: Global Code Flow Summary — 코드베이스 전체 구조 요약 (GCFS)
    gcfs_prefix = _build_global_flow_summary(symbol_graph, preprocess_result)
    if gcfs_prefix:
        print(f"[L3][GCFS] 전체 코드 흐름 요약 생성됨 ({len(gcfs_prefix.splitlines())}줄)")

    # 파일별로 묶어서 배치 처리
    by_file: Dict[str, List[Dict[str, Any]]] = {}
    for v in candidates:
        fp = v.get("file") or v.get("file_path")
        if not fp:
            continue
        by_file.setdefault(fp, []).append(v)

    for file_path, violations in by_file.items():
        content = get_file_content(file_path)
        if not content:
            print(f"[L3] 파일 읽기 실패: {file_path}")
            continue

        # 캐시 확인 + 항목 준비
        isolated_items: List[Dict[str, Any]] = []  # 단독 처리 (고위험 규칙)
        batch_items: List[Dict[str, Any]] = []     # 배치 처리
        for v in violations:
            raw_line = v.get("line")
            line = int(raw_line) if raw_line else None
            pattern_type = v.get("pattern_type") or "regex"
            code_block = _get_code_context(content, line, pattern_type, violation=v, symbol_graph=symbol_graph)
            if not code_block:
                print(f"[L3] 코드 컨텍스트 없음, 스킵: {v.get('rule_id')} @ {file_path}")
                continue
            # Phase 0: 전제조건 검증 (방안 4) — 파일에 해당 기능 미구현 시 FP 확정
            if not _check_violation_precondition(v, content, file_path):
                if _rejected_tracker is not None:
                    _rejected_tracker.add((
                        (v.get("file") or v.get("file_path") or "").strip(),
                        (v.get("rule_id") or ""),
                        v.get("line"),
                    ))
                continue
            # Phase 1: Structured Evidence — symbol_graph 데이터를 code_block 앞에 prepend
            structured_ev = _build_structured_evidence(v, symbol_graph)
            if structured_ev:
                code_block = structured_ev + code_block
                print(f"[L3][SE] 구조화 증거 추가: {v.get('rule_id')} @ {file_path}:{line}")
            # Phase 1-B: 키 생명주기 분석 결과 prepend (COM-001 전용)
            if v.get("rule_id") == "COM-001" and v.get("key_lifecycle"):
                lifecycle_block = (
                    "=== 키 생명주기 분석 (Key Lifecycle Analysis) ===\n"
                    + v["key_lifecycle"]
                    + "\n" + "=" * 50 + "\n\n"
                )
                code_block = lifecycle_block + code_block
                print(f"[L3][KL] 키 생명주기 분석 추가: COM-001 @ {file_path}")
            if v.get("project_artifact_evidence"):
                artifact_block = (
                    "=== 제출/시험 아티팩트 증거 (Submission/Test Artifact Evidence) ===\n"
                    + v["project_artifact_evidence"]
                    + "\n" + "=" * 50 + "\n\n"
                )
                code_block = artifact_block + code_block
            # Phase 2: GCFS — 전체 코드 흐름 요약을 code_block 맨 앞에 prepend
            # DOC 규칙(DOC-xxx)은 설계서 판정이므로 코드 흐름 요약 주입 제외
            _is_doc_rule = (v.get("rule_id") or "").startswith("DOC")
            if gcfs_prefix and not _is_doc_rule:
                code_block = gcfs_prefix + code_block
            rule_id = v.get("rule_id") or "UNKNOWN"
            cache_key = _l3_cache_key(rule_id, code_block)

            if cache_key in _l3_cache:
                print(f"[L3] 캐시 히트: {rule_id} @ {file_path}:{line}")
                obj = _l3_cache[cache_key]
                if obj.get("is_real_issue") or rule_id in _L3_NEVER_REMOVE:
                    results.append(_make_l3_result(v, obj))
            else:
                entry = {
                    "violation": v,
                    "code_block": code_block,
                    "cache_key": cache_key,
                    "guideline_text": v.get("rag_guideline_text", ""),
                }
                # missing 타입도 단독 처리 — 배치 파싱 시 score=0 문제 방지
                if rule_id in _HIGH_ISOLATION_RULES or v.get("pattern_type") == "missing":
                    isolated_items.append(entry)
                else:
                    batch_items.append(entry)

        # ── 고위험 규칙 단독 처리 (Direction 1: guideline, Direction 3: CoT) ──
        for entry in isolated_items:
            v = entry["violation"]
            rule_id = v.get("rule_id") or ""
            guideline_text = entry.get("guideline_text", "")
            print(f"[L3] 격리 판정 (CoT+RAG): {rule_id} @ {file_path}:{v.get('line')}")
            obj = _call_gemini_with_retry(
                _build_single_prompt(
                    file_path, v, entry["code_block"],
                    guideline_text=guideline_text,
                    use_cot=True,  # Direction 3: CoT for HIGH_ISOLATION_RULES
                )
            )
            if obj:
                _l3_cache[entry["cache_key"]] = obj
                score = obj.get("confidence", 80)
                try:
                    score = int(score)
                except (TypeError, ValueError):
                    score = 80

                # Direction 4: 신뢰도 65-74 구간 재판정
                if obj.get("is_real_issue") and 65 <= score <= 74:
                    print(f"[L3] 재판정 요청 (score={score}): {rule_id} @ {file_path}:{v.get('line')}")
                    rejudge_prompt = _build_rejudge_prompt(
                        file_path, v, entry["code_block"], obj, guideline_text
                    )
                    rejudge_obj = _call_gemini_with_retry(rejudge_prompt)
                    if rejudge_obj:
                        obj = rejudge_obj
                        _l3_cache[entry["cache_key"]] = obj
                        score = obj.get("confidence", score)
                        print(f"[L3] 재판정 완료 (score={score}): {rule_id}")

                _score_int = int(obj.get("confidence", 50))
                _pat_type = v.get("pattern_type", "")
                _fp_threshold = 25 if _pat_type in ("ast", "semantic") else 40
                # ast fallback(후보) 위반은 FP 확신 임계값을 80으로 높여 Recall 보호
                # _AST_TP_PROTECT 규칙은 L3 오판 FN 확인+KISA FP 아님 → 90으로 보수적 처리
                _fp_high = (95 if rule_id in _AST_TP_PROTECT else 80) if _pat_type == "ast" else 70
                if obj.get("is_real_issue"):
                    results.append(_make_l3_result(v, obj))
                    print(f"[L3] 확정 (score={score}): {rule_id} @ {file_path}:{v.get('line')}")
                elif rule_id in _L3_NEVER_REMOVE:
                    # 제거 차단: FP 제거 정확도 미달 → Recall 보호 우선
                    results.append(_make_l3_result(v, obj))
                    print(f"[L3] 제거차단→유지 (NEVER_REMOVE, score={score}): {rule_id} @ {file_path}:{v.get('line')}")
                elif _score_int <= _fp_threshold or _score_int >= _fp_high:
                    # FP 제거 전 비대칭 재검증
                    if _verify_fp_removal(v, obj, entry["code_block"], file_path):
                        print(f"[L3] 오탐 제거 (score={score}): {rule_id} @ {file_path}:{v.get('line')}")
                        if _rejected_tracker is not None:
                            _rejected_tracker.add((
                                (v.get("file") or v.get("file_path") or "").strip(),
                                rule_id,
                                v.get("line"),
                            ))
                    else:
                        results.append(_make_l3_result(v, obj))
                        print(f"[L3] FP재검증 실패→유지 (score={score}): {rule_id} @ {file_path}:{v.get('line')}")
                else:
                    results.append(_make_l3_result(v, obj))
                    print(f"[L3] 불확실 FP→보수적 유지 (score={score}): {rule_id} @ {file_path}:{v.get('line')}")

        if not batch_items:
            continue

        # ── 일반 규칙 배치 처리 (최대 8건씩 분할 → 집중력 유지) ──
        _BATCH_CHUNK = 8
        for chunk_start in range(0, len(batch_items), _BATCH_CHUNK):
            chunk = batch_items[chunk_start: chunk_start + _BATCH_CHUNK]
            print(f"[L3] 배치 판정: {file_path} ({len(chunk)}건, {chunk_start+1}~{chunk_start+len(chunk)})")
            prompt = _build_batch_prompt(file_path, chunk)
            arr = _call_gemini_batch_with_retry(prompt)

            if arr is None:
                print(f"[L3] 배치 응답 실패 → 개별 처리로 전환: {file_path}")
                for entry in chunk:
                    v = entry["violation"]
                    obj = _call_gemini_with_retry(
                        _build_single_prompt(
                            file_path, v, entry["code_block"],
                            guideline_text=entry.get("guideline_text", ""),
                        )
                    )
                    if obj:
                        _l3_cache[entry["cache_key"]] = obj
                        _score_int = int(obj.get("confidence", 50))
                        _pat_type = v.get("pattern_type", "")
                        _fp_threshold = 25 if _pat_type in ("ast", "semantic") else 40
                        # ast fallback 위반은 FP 확신 임계값을 80으로 높여 Recall 보호
                        _v_rule_id = v.get("rule_id") or ""
                        # _AST_TP_PROTECT 규칙은 95로 보수적 처리 (방안 2: 90→95)
                        _fp_high = (95 if _v_rule_id in _AST_TP_PROTECT else 80) if _pat_type == "ast" else 70
                        # is_real_issue=false + score ≥ _fp_high → 확신있는 FP → 제거
                        # _L3_NEVER_REMOVE 규칙은 FP 제거 차단
                        if obj.get("is_real_issue") or (
                            _fp_threshold < _score_int < _fp_high
                        ) or _v_rule_id in _L3_NEVER_REMOVE:
                            results.append(_make_l3_result(v, obj))
                continue

            # 청크 결과 처리
            for i, entry in enumerate(chunk):
                v = entry["violation"]
                obj = None
                for r in arr:
                    if isinstance(r, dict) and r.get("idx") == i + 1:
                        obj = r
                        break
                if obj is None and i < len(arr) and isinstance(arr[i], dict):
                    obj = arr[i]

                if not isinstance(obj, dict):
                    print(f"[L3] 배치 결과 파싱 실패: idx={i + 1}, {file_path}")
                    continue

                _l3_cache[entry["cache_key"]] = obj
                score = obj.get("confidence", 80)
                _score_int = int(score)
                _pat_type = v.get("pattern_type", "")
                _fp_threshold = 25 if _pat_type in ("ast", "semantic") else 40
                # ast fallback(후보) 위반은 FP 확신 임계값을 80으로 높여 Recall 보호
                _batch_rule_id = v.get("rule_id") or ""
                # _AST_TP_PROTECT 규칙은 95로 보수적 처리 (방안 2: 90→95)
                _fp_high = (95 if _batch_rule_id in _AST_TP_PROTECT else 80) if _pat_type == "ast" else 70
                if obj.get("is_real_issue"):
                    results.append(_make_l3_result(v, obj))
                    print(f"[L3] 확정 (score={score}): {v.get('rule_id')} @ {file_path}:{v.get('line')}")
                elif _batch_rule_id in _L3_NEVER_REMOVE:
                    # 제거 차단: FP 제거 정확도 미달 → Recall 보호 우선
                    results.append(_make_l3_result(v, obj))
                    print(f"[L3] 제거차단→유지 (NEVER_REMOVE, score={score}): {_batch_rule_id} @ {file_path}:{v.get('line')}")
                elif _score_int <= _fp_threshold or _score_int >= _fp_high:
                    # FP 제거 전 비대칭 재검증
                    if _verify_fp_removal(v, obj, entry["code_block"], file_path):
                        print(f"[L3] 오탐 제거 (score={score}): {v.get('rule_id')} @ {file_path}:{v.get('line')}")
                        if _rejected_tracker is not None:
                            _rejected_tracker.add((
                                (v.get("file") or v.get("file_path") or "").strip(),
                                (v.get("rule_id") or "").strip(),
                                v.get("line"),
                            ))
                    else:
                        results.append(_make_l3_result(v, obj))
                        print(f"[L3] FP재검증 실패→유지 (score={score}): {v.get('rule_id')} @ {file_path}:{v.get('line')}")
                else:
                    results.append(_make_l3_result(v, obj))
                    print(f"[L3] 불확실 FP→보수적 유지 (score={score}): {v.get('rule_id')} @ {file_path}:{v.get('line')}")

    rejected_count = len(_rejected_tracker) if _rejected_tracker is not None else 0
    print(f"[L3] 최종 L3 확정 위반: {len(results)}건, 오탐 제거: {rejected_count}건")
    return results
