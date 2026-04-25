"""
CodeSlicer: pattern_type별 코드 절삭 모듈.

절삭 전략:
  - regex   : ±30라인 윈도우
  - semantic : 해당 라인을 포함하는 함수 전체 (Pure Python 중괄호 카운팅)
  - ast      : 함수 전체 + 전역 스켈레톤 (타입·함수 선언부 요약)
  - missing  : None (위치 정보 없음 → L3 호출 스킵)

Tree-sitter 미설치 환경 대응:
  Tier1 = 순수 Python 중괄호 카운팅으로 함수 경계 탐지
  Tier2 = ±window 라인 윈도우 fallback
"""

from typing import List, Optional, Tuple

# ─────────────────────────────────────────────────────────────────
# 상수
# ─────────────────────────────────────────────────────────────────
_REGEX_WINDOW = 50
_SEMANTIC_WINDOW = 70   # 함수 탐지 실패 시 fallback


# ─────────────────────────────────────────────────────────────────
# 1. 함수 경계 탐지 (Tier1: 중괄호 카운팅)
# ─────────────────────────────────────────────────────────────────
def _find_function_boundary(lines: List[str], target_line: int) -> Tuple[int, int]:
    """
    target_line(1-indexed)을 포함하는 top-level 함수의 시작/끝 라인 번호 반환 (1-indexed).
    탐지 실패 시 (-1, -1) 반환.

    알고리즘 (순방향 스캔 + 상태 머신):
      파일 전체를 처음부터 순방향으로 읽으며 depth 0→1 진입(블록 시작)과
      depth 1→0 복귀(블록 끝)를 추적한다.
      주석(// /* */) 및 문자열/문자 리터럴 내부의 '{' '}' 는 무시한다.
      target_line이 [블록 시작, 블록 끝] 범위 안에 있는 top-level 블록이 정답.
    """
    n = len(lines)
    if not (1 <= target_line <= n):
        return -1, -1

    idx = target_line - 1  # 0-indexed
    depth = 0
    block_open = -1  # 현재 top-level 블록의 '{' 라인 인덱스

    # 상태 머신 상태
    in_block_comment = False
    in_string = False       # "..." 내부
    in_char = False         # '...' 내부
    escape_next = False     # 직전 문자가 백슬래시

    for i, raw in enumerate(lines):
        j = 0
        length = len(raw)

        # 라인 코멘트(//)는 해당 라인 끝까지 무시하므로 별도 플래그 없이 처리
        line_comment = False

        while j < length:
            ch = raw[j]

            # ── 탈출 문자 처리 ──
            if escape_next:
                escape_next = False
                j += 1
                continue

            # ── 블록 주석 종료 ──
            if in_block_comment:
                if ch == "*" and j + 1 < length and raw[j + 1] == "/":
                    in_block_comment = False
                    j += 2
                    continue
                j += 1
                continue

            # ── 문자열 리터럴 내부 ──
            if in_string:
                if ch == "\\":
                    escape_next = True
                elif ch == '"':
                    in_string = False
                j += 1
                continue

            # ── 문자 리터럴 내부 ──
            if in_char:
                if ch == "\\":
                    escape_next = True
                elif ch == "'":
                    in_char = False
                j += 1
                continue

            # ── 라인 주석 ──
            if line_comment:
                j += 1
                continue

            # ── 새 상태 진입 감지 ──
            if ch == "/" and j + 1 < length:
                if raw[j + 1] == "/":
                    line_comment = True
                    j += 2
                    continue
                if raw[j + 1] == "*":
                    in_block_comment = True
                    j += 2
                    continue

            if ch == '"':
                in_string = True
                j += 1
                continue

            if ch == "'":
                in_char = True
                j += 1
                continue

            # ── 중괄호 처리 (실제 코드 영역) ──
            if ch == "{":
                if depth == 0:
                    block_open = i  # top-level 블록 시작
                depth += 1
            elif ch == "}":
                if depth > 0:
                    depth -= 1
                if depth == 0 and block_open != -1:
                    # top-level 블록 완결: [block_open, i]
                    if block_open <= idx <= i:
                        # 함수 서명: block_open 위로 연속된 비-빈 라인 포함 (최대 5줄)
                        sig_start = block_open
                        for k in range(block_open - 1, max(block_open - 6, -1), -1):
                            s = lines[k].strip()
                            # 빈 줄, 주석, 혹은 이전 블록 끝/시작이면 중단
                            if (not s
                                    or s.startswith("//")
                                    or s.startswith("*")
                                    or s.startswith("/*")
                                    or s.endswith("}")
                                    or s.endswith(";")):
                                break
                            sig_start = k
                        return sig_start + 1, i + 1  # 1-indexed
                    block_open = -1

            j += 1

    return -1, -1


# ─────────────────────────────────────────────────────────────────
# 2. 전역 스켈레톤 추출 (ast 타입용)
# ─────────────────────────────────────────────────────────────────
def extract_global_skeleton(lines: List[str], max_lines: int = 150) -> str:
    """
    파일 전체에서 전역 구조 요약 추출.
    포함 항목 (우선순위 순):
      1. typedef struct/union/enum {...} Name; 블록 전체
      2. 최상위 struct/enum 선언
      3. #define — LEA/암호 관련 키워드 포함 우선, 그 외 수치 상수
      4. 함수 프로토타입(세미콜론으로 끝나는 선언)
    반환: 요약 텍스트 (최대 max_lines 라인, 기본 150)
    """
    # 우선순위 버킷
    priority_lines: List[str] = []   # typedef 블록 / LEA 핵심 #define
    secondary_lines: List[str] = []  # 일반 #define / 함수 프로토타입 / struct

    in_block_comment = False
    depth = 0

    # typedef struct {...} Name; 블록 수집 상태
    in_typedef_block = False
    typedef_buf: List[str] = []
    typedef_depth_start = 0

    # 암호/LEA 관련 키워드 (대문자 비교)
    crypto_kw = {
        "KEY", "IV", "NONCE", "LEN", "SIZE", "BLOCK", "TAG", "HASH",
        "ROUND", "DELTA", "SCHEDULE", "SUBKEY", "RK", "MK",
        "LEA", "ARIA", "CBC", "GCM", "CTR", "CCM", "CMAC",
        "ENCRYPT", "DECRYPT", "CIPHER", "MASK", "ROT", "ROL", "ROR",
    }

    for raw in lines:
        line = raw.rstrip()

        # 블록 주석 처리
        if in_block_comment:
            if "*/" in line:
                in_block_comment = False
            continue
        if "/*" in line and "*/" not in line:
            in_block_comment = True

        # typedef struct/union/enum 블록 수집
        stripped = line.strip()
        if not in_typedef_block:
            is_typedef_open = (
                stripped.startswith("typedef ") and
                any(kw in stripped for kw in ("struct", "union", "enum")) and
                "{" in stripped
            )
            if is_typedef_open:
                in_typedef_block = True
                typedef_buf = [line]
                typedef_depth_start = depth
                for ch in line:
                    if ch == "{":
                        depth += 1
                    elif ch == "}":
                        depth = max(0, depth - 1)
                if depth == typedef_depth_start:
                    in_typedef_block = False
                    priority_lines.extend(typedef_buf)
                    typedef_buf = []
                continue
        else:
            typedef_buf.append(line)
            for ch in line:
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth = max(0, depth - 1)
            if depth == typedef_depth_start:
                in_typedef_block = False
                priority_lines.extend(typedef_buf)
                typedef_buf = []
            continue

        # 중괄호 깊이 추적
        for ch in line:
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth = max(0, depth - 1)

        if depth != 0:
            continue

        if not stripped or stripped.startswith("//"):
            continue

        # 최상위 struct/enum (typedef 없는 경우)
        if stripped.startswith(("struct ", "enum ")):
            secondary_lines.append(line)
            continue

        # #define: LEA 핵심 상수 → priority, 그 외 수치 상수 → secondary
        if stripped.startswith("#define"):
            upper = stripped.upper()
            if any(kw in upper for kw in crypto_kw):
                priority_lines.append(line)
            else:
                # 숫자 리터럴 포함 상수만 (0x... 또는 순수 숫자)
                import re as _re
                if _re.search(r'\b(0x[0-9a-fA-F]+|\d+[uUlL]*)\b', stripped):
                    secondary_lines.append(line)
            continue

        # 함수 프로토타입: 세미콜론으로 끝나고 '(' 포함
        if stripped.endswith(";") and "(" in stripped and not stripped.startswith("#"):
            secondary_lines.append(line)

    # 우선순위 버킷 먼저, 그 다음 보조 버킷으로 max_lines 채우기
    result: List[str] = []
    for ln in priority_lines:
        if len(result) >= max_lines:
            break
        result.append(ln)
    for ln in secondary_lines:
        if len(result) >= max_lines:
            break
        result.append(ln)

    return "\n".join(result)


# ─────────────────────────────────────────────────────────────────
# 3. 메인 API
# ─────────────────────────────────────────────────────────────────
def slice_code(
    lines: List[str],
    line_number: int,
    pattern_type: str,
) -> Optional[str]:
    """
    pattern_type에 따라 코드 절삭 후 문자열 반환.

    Parameters
    ----------
    lines       : 파일 전체 라인 리스트 (splitlines 결과)
    line_number : 위반 라인 번호 (1-indexed)
    pattern_type: "regex" | "semantic" | "ast" | "missing"

    Returns
    -------
    str  : 절삭된 코드 블록
    None : missing 타입 또는 절삭 불가
    """
    ptype = (pattern_type or "regex").lower()

    if ptype == "missing":
        return None

    n = len(lines)

    if ptype == "regex":
        # Tier1: 위반 라인이 속한 함수 전체 (더 정확한 컨텍스트)
        func_start, func_end = _find_function_boundary(lines, line_number)
        if func_start != -1:
            return "\n".join(lines[func_start - 1 : func_end])
        # Tier2: 함수 탐지 실패 → ±50라인 윈도우 fallback
        start = max(0, line_number - 1 - _REGEX_WINDOW)
        end = min(n, line_number - 1 + _REGEX_WINDOW)
        return "\n".join(lines[start:end])

    if ptype in ("semantic", "ast"):
        # Tier1: 함수 경계 탐지
        func_start, func_end = _find_function_boundary(lines, line_number)

        if func_start != -1:
            func_body = "\n".join(lines[func_start - 1 : func_end])

            # ast/semantic 모두: 함수 전체 + 전역 스켈레톤 헤더
            # (struct/typedef/define 구조를 AI가 알아야 키·IV 판단 정확도 향상)
            skeleton = extract_global_skeleton(lines)
            if skeleton:
                return f"// === 전역 구조 요약 ===\n{skeleton}\n\n// === 함수 본체 ===\n{func_body}"
            return func_body

        # Tier2: 함수 탐지 실패 → ±window 라인 fallback
        window = _SEMANTIC_WINDOW
        start = max(0, line_number - 1 - window)
        end = min(n, line_number - 1 + window)
        return "\n".join(lines[start:end])

    # 알 수 없는 pattern_type → regex 동일 처리
    start = max(0, line_number - 1 - _REGEX_WINDOW)
    end = min(n, line_number - 1 + _REGEX_WINDOW)
    return "\n".join(lines[start:end])
