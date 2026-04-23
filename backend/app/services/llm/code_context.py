"""코드 절삭 — symbol_graph 연동 + code_slicer 위임."""

import re
from typing import Any, Dict, List, Optional

from app.services.code_slicer import slice_code


# pattern_type별 코드 절삭 범위 (라인 수)
_WINDOW_BY_PATTERN_TYPE: Dict[str, int] = {
    "regex": 30,
    "semantic": 50,
    "ast": 50,
    "missing": 0,
}


def _find_func_boundary_from_sg(
    line: int,
    symbol_graph: Dict[str, Any],
) -> tuple:
    """symbol_graph["definitions"]에서 주어진 라인을 포함하는 함수를 찾아 (start, end) 반환.

    반환: (start_line, end_line) 1-based, 못 찾으면 (-1, -1)
    """
    definitions = symbol_graph.get("definitions") or {}
    best_start, best_end = -1, -1
    best_size = float("inf")
    for func_name, entries in definitions.items():
        if not isinstance(entries, list):
            entries = [entries]
        for entry in entries:
            s = entry.get("line") or entry.get("start_line")
            e = entry.get("end_line")
            if not s or not e:
                continue
            try:
                s, e = int(s), int(e)
            except (TypeError, ValueError):
                continue
            if s <= line <= e:
                size = e - s
                if size < best_size:
                    best_size = size
                    best_start, best_end = s, e
    return best_start, best_end


def _get_code_context(
    content: str,
    line: Optional[int],
    pattern_type: str,
    violation: Optional[Dict[str, Any]] = None,
    symbol_graph: Optional[Dict[str, Any]] = None,
) -> str:
    """code_slicer.slice_code로 위임. line=None 이면 함수명 기반 절삭 시도.

    ast 타입에서 line=None인 경우:
      1. violation의 message/rule_id 에서 함수 키워드 추출
      2. 파일에서 해당 함수 본체 절삭 (전역 스켈레톤 포함)
      3. 실패 시 파일 앞부분 100줄

    symbol_graph가 있고 line이 주어진 경우:
      symbol_graph["definitions"]에서 해당 라인을 포함하는 함수를 찾아
      end_line을 이용해 정확한 함수 본체를 반환한다.
    """
    lines = content.splitlines()

    if line:
        # symbol_graph의 end_line으로 정확한 함수 경계 사용
        if symbol_graph:
            sg_start, sg_end = _find_func_boundary_from_sg(line, symbol_graph)
            if sg_start != -1 and sg_end != -1:
                func_lines = lines[sg_start - 1: sg_end]
                if len(func_lines) > 200:
                    # 위반 라인 중심으로 200줄 슬라이싱
                    rel = max(0, line - sg_start)
                    half = 100
                    start_off = max(0, rel - half)
                    end_off = min(len(func_lines), start_off + 200)
                    start_off = max(0, end_off - 200)
                    func_lines = func_lines[start_off:end_off]
                return "\n".join(func_lines)
        result = slice_code(lines, line, pattern_type)
        return result if result is not None else ""

    # line=None 처리
    if pattern_type not in ("ast", "semantic", "missing"):
        return ""

    # missing 타입(project-scope): 대표 파일 전체 구조를 컨텍스트로 제공
    if pattern_type == "missing":
        from app.services.code_slicer import extract_global_skeleton
        skeleton = extract_global_skeleton(lines)
        if skeleton:
            return skeleton
        return "\n".join(lines[:150])

    from app.services.code_slicer import extract_global_skeleton, _find_function_boundary
    import re as _re

    # rule_id → 관련 함수 키워드 매핑
    # ast: 구조 검사 대상 함수, semantic: 보안 패턴이 있어야 할 함수
    _RULE_FUNC_KEYWORDS: Dict[str, List[str]] = {
        # AST 규칙
        "lea-010": ["key_schedule", "set_key", "keygen", "key_setup", "key_expand"],
        "lea-021": ["key", "key_schedule", "set_key", "keygen", "key_sched", "key_exp"],
        "lea-022": ["key", "key_schedule", "set_key", "keygen", "key_sched", "key_exp"],
        "lea-023": ["decrypt", "dec", "dec_key", "set_dec", "decrypt_key", "key_schedule"],
        "lea-025": ["key", "key_schedule", "set_key", "keygen", "key_sched", "key_exp"],
        "lea-030": ["encrypt", "enc_block", "lea_enc"],
        "lea-031": ["encrypt", "enc_block", "round"],
        "lea-034": ["decrypt", "dec_block", "lea_dec"],
        "lea-035": ["decrypt", "dec_block"],
        "lea-039": ["encrypt", "decrypt", "enc", "dec"],
        "lea-040": ["encrypt", "decrypt"],
        "lea-047": ["mct", "monte", "carlo", "lea_mct"],
        "ecb-002": ["ecb_enc", "ecb_encrypt", "ecb_cipher", "ecb"],
        "cbc-001": ["cbc_encrypt", "cbc"],
        "cbc-002": ["cbc_decrypt", "cbc"],
        "gcm-001": ["gcm_encrypt", "gcm_init", "gcm"],
        # Semantic 규칙 — 보안 패턴이 있어야 할 함수 위치
        "com-001": ["encrypt", "decrypt", "cbc", "gcm", "ctr", "final"],
        "com-002": ["encrypt", "decrypt", "init", "update", "final", "set_key"],
        "com-005": ["online", "init", "update", "final", "stream"],
        "lea-044": ["encrypt", "decrypt", "final", "cbc", "gcm", "ctr"],
        "lea-049": ["kat", "test", "variable", "vector"],
        "lea-050": ["kat", "test", "variable", "vector"],
        "lea-060": ["kat", "test", "known", "reference", "verify"],
        "lea-061": ["set_key", "key_schedule", "init", "encrypt"],
        "lea-062": ["kat", "variable", "req", "rsp"],
        "cbc-003": ["cbc", "iv", "init", "encrypt", "csprng", "random"],
        "cbc-004": ["cbc", "encrypt", "decrypt", "final", "free"],
        "gcm-003": ["gcm", "init", "encrypt", "decrypt", "final"],
        "gcm-004": ["gcm", "decrypt", "final", "verify", "auth"],
        "gcm-005": ["gcm", "final", "free", "clear"],
        "ctr-003": ["ctr", "iv", "nonce", "init", "random"],
        "ctr-004": ["ctr", "final", "free", "clear"],
        "ccm-004": ["ccm", "decrypt", "verify", "auth"],
        "ccm-005": ["ccm", "final", "free", "clear"],
        "cmac-002": ["cmac", "verify", "compare", "final"],
        "cmac-003": ["cmac", "final", "free", "clear"],
        "cfb-001": ["cfb", "iv", "init", "random"],
    }

    # violation 메시지에서 함수명 직접 추출 (우선순위 높음)
    func_keywords: List[str] = []
    if violation:
        # 1순위: rule_engine이 AST 체커 메시지에서 미리 추출한 실제 함수명
        stored_func = violation.get("func_name")
        if stored_func:
            func_keywords.append(stored_func.lower())
        # 2순위: 메시지에서 "함수 'name'" 패턴 직접 파싱 (fallback)
        if not func_keywords:
            msg_match = _re.search(r"함수\s+'([^']+)'", violation.get("message") or "")
            if msg_match:
                func_keywords.append(msg_match.group(1).lower())

        rid = (violation.get("rule_id") or "").lower()
        # rule_id 기반 키워드 매핑
        for kw, hints in _RULE_FUNC_KEYWORDS.items():
            if rid.startswith(kw):
                func_keywords.extend(hints)
                break
        # 매핑 없으면 rid 자체에서 추론 (cbc-003 → ["cbc"])
        if not func_keywords:
            parts = rid.replace("-", "_").split("_")
            func_keywords.extend(p for p in parts if len(p) > 2 and not p.isdigit())

    # 키워드로 함수 찾기
    found_start = -1
    found_end = -1
    if func_keywords:
        func_pattern = "|".join(func_keywords)
        for i, raw_line in enumerate(lines):
            stripped = raw_line.strip()
            # 함수 정의 줄 (반환형 + 이름 + 괄호 패턴)
            import re as _re
            if (
                "(" in stripped
                and _re.search(func_pattern, stripped, _re.IGNORECASE)
                and not stripped.startswith("//")
                and not stripped.startswith("*")
            ):
                s, e = _find_function_boundary(lines, i + 1)
                if s != -1:
                    found_start, found_end = s, e
                    break

    skeleton = extract_global_skeleton(lines)

    if found_start != -1:
        func_body = "\n".join(lines[found_start - 1: found_end])
        if skeleton:
            return (
                f"// === 전역 구조 요약 ===\n{skeleton}\n\n"
                f"// === 관련 함수 본체 ===\n{func_body}"
            )
        return func_body

    # 함수 못 찾으면 전역 스켈레톤 + 파일 앞 100줄
    header = "\n".join(lines[:100])
    if skeleton:
        ctx = f"// === 전역 구조 요약 ===\n{skeleton}\n\n// === 파일 앞부분 ===\n{header}"
    else:
        ctx = header

    # ast/semantic 위반은 코드가 전혀 없더라도 최소한 파일 앞 50줄을 반환
    # (패턴 부재를 확인하기 위해 AI가 파일 전체 맥락을 볼 필요가 있음)
    if not ctx and pattern_type in ("semantic", "ast"):
        ctx = "\n".join(lines[:50])

    return ctx
