"""메인 L2 실행 — run_l2_contextualizer."""

import re
from typing import Any, Dict, List, Optional

from app.services.llm.gemini_client import (
    GOOGLE_API_KEY, L2_PROVIDER,
    _call_gemini_with_retry, _call_gemini_batch_with_retry,
)
from app.services.llm.prompt_templates import _HIGH_ISOLATION_RULES
from app.services.llm.candidate_selector import _select_l2_candidates
from app.services.llm.code_context import _get_code_context
from app.services.llm.prompt_builder import (
    _fetch_guideline_text, _l2_cache, _l2_cache_key,
    _build_single_prompt, _build_batch_prompt, _build_rejudge_prompt,
    _make_l2_result, _build_structured_evidence, _build_global_flow_summary,
)


def run_l2_contextualizer(
    preprocess_result: Dict[str, Any],
    l1_violations: List[Dict[str, Any]],
    rules_meta: Optional[Dict[str, Any]] = None,
    _rejected_tracker: Optional[set] = None,
    symbol_graph: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """
    L2: 의미적(맥락 기반) 위반 재판정.

    Parameters
    ----------
    preprocess_result  : 전처리 결과 (run_preprocess 출력)
    l1_violations      : L1 룰 엔진에서 생성된 위반 리스트
    rules_meta         : (선택) 룰 메타데이터
    _rejected_tracker  : (선택) L2가 오탐으로 판정한 항목의 (file, rule_id, line) 튜플을
                         채워 넣을 set. analyze.py에서 post_process_violations 연동용.
    symbol_graph       : (선택) build_symbol_graph 출력 — array_inits/type_aliases 활용.
                         Structured Evidence Injection (Phase 1)에 사용.

    Returns
    -------
    list[dict] : L2가 실제 위반으로 확정한 항목 리스트
    """
    # gemini 프로바이더는 API 키 필수; local은 키 불필요
    if L2_PROVIDER == "gemini" and not GOOGLE_API_KEY:
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

    # L2 대상 선정
    candidates = _select_l2_candidates(l1_violations)
    if not candidates:
        print("[L2] L2 판정 대상 없음")
        return []

    print(f"[L2] 판정 대상 {len(candidates)}건 선정 (전체 L1 위반: {len(l1_violations)}건)")

    # Direction 1: rule_id별 가이드라인 사전 로드 (중복 호출 방지)
    guideline_cache: Dict[str, str] = {}
    unique_rule_ids = {v.get("rule_id") or "UNKNOWN" for v in candidates}
    for rid in unique_rule_ids:
        guideline_cache[rid] = _fetch_guideline_text(rid)
    print(f"[L2][RAG] 가이드라인 로드: {sum(1 for g in guideline_cache.values() if g)}건 (/{len(guideline_cache)})")

    # Phase 2: Global Code Flow Summary — 코드베이스 전체 구조 요약 (GCFS)
    gcfs_prefix = _build_global_flow_summary(symbol_graph, preprocess_result)
    if gcfs_prefix:
        print(f"[L2][GCFS] 전체 코드 흐름 요약 생성됨 ({len(gcfs_prefix.splitlines())}줄)")

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
            print(f"[L2] 파일 읽기 실패: {file_path}")
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
                print(f"[L2] 코드 컨텍스트 없음, 스킵: {v.get('rule_id')} @ {file_path}")
                continue
            # Phase 1: Structured Evidence — symbol_graph 데이터를 code_block 앞에 prepend
            structured_ev = _build_structured_evidence(v, symbol_graph)
            if structured_ev:
                code_block = structured_ev + code_block
                print(f"[L2][SE] 구조화 증거 추가: {v.get('rule_id')} @ {file_path}:{line}")
            # Phase 1-B: 키 생명주기 분석 결과 prepend (COM-001 전용)
            if v.get("rule_id") == "COM-001" and v.get("key_lifecycle"):
                lifecycle_block = (
                    "=== 키 생명주기 분석 (Key Lifecycle Analysis) ===\n"
                    + v["key_lifecycle"]
                    + "\n" + "=" * 50 + "\n\n"
                )
                code_block = lifecycle_block + code_block
                print(f"[L2][KL] 키 생명주기 분석 추가: COM-001 @ {file_path}")
            # Phase 2: GCFS — 전체 코드 흐름 요약을 code_block 맨 앞에 prepend
            # DOC 규칙(DOC-xxx)은 설계서 판정이므로 코드 흐름 요약 주입 제외
            _is_doc_rule = (v.get("rule_id") or "").startswith("DOC")
            if gcfs_prefix and not _is_doc_rule:
                code_block = gcfs_prefix + code_block
            rule_id = v.get("rule_id") or "UNKNOWN"
            cache_key = _l2_cache_key(rule_id, code_block)

            if cache_key in _l2_cache:
                print(f"[L2] 캐시 히트: {rule_id} @ {file_path}:{line}")
                obj = _l2_cache[cache_key]
                if obj.get("is_real_issue"):
                    results.append(_make_l2_result(v, obj))
            else:
                entry = {
                    "violation": v,
                    "code_block": code_block,
                    "cache_key": cache_key,
                    "guideline_text": guideline_cache.get(rule_id, ""),
                }
                if rule_id in _HIGH_ISOLATION_RULES:
                    isolated_items.append(entry)
                else:
                    batch_items.append(entry)

        # ── 고위험 규칙 단독 처리 (Direction 1: guideline, Direction 3: CoT) ──
        for entry in isolated_items:
            v = entry["violation"]
            rule_id = v.get("rule_id") or ""
            guideline_text = entry.get("guideline_text", "")
            print(f"[L2] 격리 판정 (CoT+RAG): {rule_id} @ {file_path}:{v.get('line')}")
            obj = _call_gemini_with_retry(
                _build_single_prompt(
                    file_path, v, entry["code_block"],
                    guideline_text=guideline_text,
                    use_cot=True,  # Direction 3: CoT for HIGH_ISOLATION_RULES
                )
            )
            if obj:
                _l2_cache[entry["cache_key"]] = obj
                score = obj.get("confidence", 80)
                try:
                    score = int(score)
                except (TypeError, ValueError):
                    score = 80

                # Direction 4: 신뢰도 65-74 구간 재판정
                if obj.get("is_real_issue") and 65 <= score <= 74:
                    print(f"[L2] 재판정 요청 (score={score}): {rule_id} @ {file_path}:{v.get('line')}")
                    rejudge_prompt = _build_rejudge_prompt(
                        file_path, v, entry["code_block"], obj, guideline_text
                    )
                    rejudge_obj = _call_gemini_with_retry(rejudge_prompt)
                    if rejudge_obj:
                        obj = rejudge_obj
                        _l2_cache[entry["cache_key"]] = obj
                        score = obj.get("confidence", score)
                        print(f"[L2] 재판정 완료 (score={score}): {rule_id}")

                _score_int = int(obj.get("confidence", 50))
                _pat_type = v.get("pattern_type", "")
                _fp_threshold = 25 if _pat_type in ("ast", "semantic") else 40
                if obj.get("is_real_issue"):
                    results.append(_make_l2_result(v, obj))
                    print(f"[L2] 확정 (score={score}): {rule_id} @ {file_path}:{v.get('line')}")
                elif _score_int <= _fp_threshold or _score_int >= 70:
                    # score ≤ threshold: 일관된 FP (낮은 위반 확신)
                    # score ≥ 70: 모델이 is_real_issue=false + 높은 확신 → 확신있는 FP 판정
                    print(f"[L2] 오탐 제거 (score={score}): {rule_id} @ {file_path}:{v.get('line')}")
                    if _rejected_tracker is not None:
                        _rejected_tracker.add((
                            (v.get("file") or v.get("file_path") or "").strip(),
                            rule_id,
                            v.get("line"),
                        ))
                else:
                    results.append(_make_l2_result(v, obj))
                    print(f"[L2] 불확실 FP→보수적 유지 (score={score}): {rule_id} @ {file_path}:{v.get('line')}")

        if not batch_items:
            continue

        # ── 일반 규칙 배치 처리 (최대 8건씩 분할 → 집중력 유지) ──
        _BATCH_CHUNK = 8
        for chunk_start in range(0, len(batch_items), _BATCH_CHUNK):
            chunk = batch_items[chunk_start: chunk_start + _BATCH_CHUNK]
            print(f"[L2] 배치 판정: {file_path} ({len(chunk)}건, {chunk_start+1}~{chunk_start+len(chunk)})")
            prompt = _build_batch_prompt(file_path, chunk)
            arr = _call_gemini_batch_with_retry(prompt)

            if arr is None:
                print(f"[L2] 배치 응답 실패 → 개별 처리로 전환: {file_path}")
                for entry in chunk:
                    v = entry["violation"]
                    obj = _call_gemini_with_retry(
                        _build_single_prompt(
                            file_path, v, entry["code_block"],
                            guideline_text=entry.get("guideline_text", ""),
                        )
                    )
                    if obj:
                        _l2_cache[entry["cache_key"]] = obj
                        _score_int = int(obj.get("confidence", 50))
                        _pat_type = v.get("pattern_type", "")
                        _fp_threshold = 25 if _pat_type in ("ast", "semantic") else 40
                        # is_real_issue=false + score ≥ 70 → 확신있는 FP → 제거
                        if obj.get("is_real_issue") or (
                            _fp_threshold < _score_int < 70
                        ):
                            results.append(_make_l2_result(v, obj))
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
                    print(f"[L2] 배치 결과 파싱 실패: idx={i + 1}, {file_path}")
                    continue

                _l2_cache[entry["cache_key"]] = obj
                score = obj.get("confidence", 80)
                _score_int = int(score)
                _pat_type = v.get("pattern_type", "")
                _fp_threshold = 25 if _pat_type in ("ast", "semantic") else 40
                if obj.get("is_real_issue"):
                    results.append(_make_l2_result(v, obj))
                    print(f"[L2] 확정 (score={score}): {v.get('rule_id')} @ {file_path}:{v.get('line')}")
                elif _score_int <= _fp_threshold or _score_int >= 70:
                    # score ≤ threshold: 일관된 FP / score ≥ 70: 확신있는 FP 판정
                    print(f"[L2] 오탐 제거 (score={score}): {v.get('rule_id')} @ {file_path}:{v.get('line')}")
                    if _rejected_tracker is not None:
                        _rejected_tracker.add((
                            (v.get("file") or v.get("file_path") or "").strip(),
                            (v.get("rule_id") or "").strip(),
                            v.get("line"),
                        ))
                else:
                    results.append(_make_l2_result(v, obj))
                    print(f"[L2] 불확실 FP→보수적 유지 (score={score}): {v.get('rule_id')} @ {file_path}:{v.get('line')}")

    rejected_count = len(_rejected_tracker) if _rejected_tracker is not None else 0
    print(f"[L2] 최종 L2 확정 위반: {len(results)}건, 오탐 제거: {rejected_count}건")
    return results
