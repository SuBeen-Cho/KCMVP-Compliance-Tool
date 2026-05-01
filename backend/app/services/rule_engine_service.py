"""
RuleEngineService (L1): 룰셋 기반 탐지.
- 공통 → 알고리즘 → 모드 순으로 룰 로드 및 적용.
- 정규식/AST 패턴 매칭으로 위반 리스트 출력.
- COM-001 "missing": AST의 file_calls가 있으면 그걸로 제거 함수 호출 여부 판단 (우선), 없으면 원문 정규식.

[GPTScan 앵커 기반 FP 차단]
mode 필드가 있는 규칙은 해당 모드를 구현하는 파일에만 적용한다.
파일명이나 콘텐츠에 모드 고유 API 패턴이 없으면 해당 파일은 해당 모드를 구현하지 않는 것으로 간주,
규칙 적용을 건너뛴다. (GPTScan ICSE 2024 앵커 조건 개념 적용)
"""
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
import yaml


# ─────────────────────────────────────────────────────────────────────────────
# [GPTScan 앵커] 모드별 파일 관련성 판단 패턴
# 파일명 또는 콘텐츠에 모드 키워드(\bGCM\b 등)가 없으면 미관련 파일로 판단.
# API명 기반 매칭보다 키워드 기반이 더 robust: violation 파일은 표준 API를 안 써도 됨.
# ─────────────────────────────────────────────────────────────────────────────
_MODE_KEYWORD_RE: Dict[str, re.Pattern] = {
    mode: re.compile(rf'\b{mode}\b', re.IGNORECASE)
    for mode in ("gcm", "ctr", "cbc", "cfb", "cmac", "ccm", "ofb", "ecb")
}


# _dedup_nearby_violations 에서 사용하는 모듈 레벨 상수/유틸
_VAR_RE = re.compile(r'\b([a-zA-Z_]\w*)\s*(?:\[|=)', re.ASCII)
_UINT_TYPE_RE = re.compile(r'^uint\d+_t$', re.ASCII)
_C_TYPE_KEYWORDS: frozenset = frozenset({
    "static", "const", "extern", "volatile", "unsigned", "signed",
    "int", "char", "long", "short", "void", "float", "double",
})


# ─────────────────────────────────────────────────────────────────────────────
# 알고리즘 스코프 필터
# LEA에 중점을 두고 있으므로, 비-LEA 알고리즘 구현 파일에는 LEA 전용 규칙을 적용하지 않는다.
# COM-* (공통 보안) 규칙은 모든 파일에 계속 적용.
# ─────────────────────────────────────────────────────────────────────────────
# 명확하게 비-LEA 알고리즘을 구현하는 파일명 키워드
_NON_LEA_ALGO_FNAME_KW = frozenset({
    "aria",
    "sha", "sha2", "hash",
    "ecdsa", "kcdsa", "ec_kcdsa", "ecc",
    "pbkdf", "kbkdf",
    "hmac",
    "drbg",
    "mpz", "gfp", "gf2n",
})


def _is_lea_related_file(fname_lower: str) -> bool:
    """파일이 LEA 규칙 적용 대상인지 판별.

    - 파일명에 'lea'가 포함되면 LEA 파일 → True
    - 파일명에 명확한 비-LEA 알고리즘 키워드가 있으면 → False
    - 그 외(cipher.c, utils.c, 모드 파일 등) → True (LEA 코드 포함 가능)
    """
    if "lea" in fname_lower:
        return True
    if any(kw in fname_lower for kw in _NON_LEA_ALGO_FNAME_KW):
        return False
    return True  # cipher.c, addmac.c 등 공통/모드 파일은 포함


# ─────────────────────────────────────────────────────────────────────────────
# 파일 분류: impl / test / data / benchmark / wrapper
# 테스트/벤치마크/데이터/wrapper 파일에는 missing 규칙을 적용하지 않음.
# ─────────────────────────────────────────────────────────────────────────────
_TEST_FILENAME_PATTERNS = ("_test", "_vs", "test_", "kat", "_0tv", "vector", "selftest")
_BENCH_FILENAME_PATTERNS = ("benchmark", "bench_", "_bench")
# 인프라/유틸리티 파일: 암호 알고리즘 구현이 아닌 시스템 지원 코드
# "_base": KISA 디스패처 파일(lea_base.c 등) — SIMD 함수 포인터 초기화, 실제 암호 구현 없음
_INFRA_FILENAME_PATTERNS = ("cpu_info", "cpuinfo", "simd_detect", "platform_", "_base")
_FUNC_DEF_RE = re.compile(
    r'^\s*(?:void|int|unsigned|uint\w+|char|float|double|static)\s+\w+\s*\(',
    re.MULTILINE,
)

# Thin wrapper 함수 감지: 함수 본문이 1~2문(세미콜론 기준)만 포함하고
# 다른 함수를 호출만 하는 패턴 (dispatcher/fallback 래퍼)
_WRAPPER_FUNC_RE = re.compile(
    r'(?:void|int|unsigned|uint\w+|char|float|double|static)\s+\w+\s*\([^)]*\)\s*\{',
    re.MULTILINE,
)
_FUNC_BODY_RE = re.compile(
    r'\{([^{}]*)\}',
    re.DOTALL,
)


# 순수 위임 함수(thin wrapper) 판별용 패턴
# - 연산자 존재 = 실제 로직 있음 (wrapper 아님)
# - 지역 변수 선언 = 실제 로직 있음
_ARITHMETIC_OPS_RE = re.compile(r'<<|>>|[|^~]|\+\s*\w|\-\s*\w|[*/%](?!=)')
_ASSIGNMENT_OPS_RE = re.compile(r'\w\s*->\s*\w.*=|[^=!<>]=(?!=)')
_LOCAL_VAR_DECL_RE = re.compile(
    r'\b(?:uint\w+|int|unsigned|char|float|double|size_t|void)\s+\w+\s*[\[;=]',
)


def _is_wrapper_file(content: str) -> bool:
    """모든 함수가 thin wrapper(순수 위임)인 파일인지 판별.

    Dispatcher/fallback 파일: 각 함수가 init_simd() + 실제함수호출() 같은
    1~2줄 위임 패턴만 가진 경우.

    진짜 wrapper 판별 기준:
    - ≤2 statements
    - 지역 변수 선언 없음
    - 연산자/대입 없음 (순수 함수 호출만)
    """
    func_starts = list(_WRAPPER_FUNC_RE.finditer(content))
    if not func_starts:
        return False

    func_count = 0
    wrapper_count = 0
    for m in func_starts:
        brace_start = m.end() - 1
        depth = 0
        body_end = brace_start
        for i in range(brace_start, len(content)):
            if content[i] == '{':
                depth += 1
            elif content[i] == '}':
                depth -= 1
                if depth == 0:
                    body_end = i
                    break
        body = content[brace_start + 1:body_end].strip()
        if not body:
            continue
        func_count += 1
        stmt_count = body.count(';')
        # 순수 위임: ≤2 stmts, 변수 선언 없음, 연산자/대입 없음
        if (stmt_count <= 2
            and not _LOCAL_VAR_DECL_RE.search(body)
            and not _ARITHMETIC_OPS_RE.search(body)
            and not _ASSIGNMENT_OPS_RE.search(body)):
            wrapper_count += 1

    # 함수가 5개 이상 있고 90% 이상이 순수 wrapper → wrapper 파일
    return func_count >= 5 and wrapper_count >= func_count * 0.9


def _classify_file(filename: str, content: str) -> str:
    """파일을 impl/test/data/benchmark/wrapper로 분류.

    - 파일명 패턴으로 먼저 판별 (빠르고 신뢰도 높음)
    - 패턴 미매치 시 코드 구조 분석
    """
    name_lower = filename.lower()

    for p in _BENCH_FILENAME_PATTERNS:
        if p in name_lower:
            return "benchmark"
    for p in _TEST_FILENAME_PATTERNS:
        if p in name_lower:
            return "test"
    for p in _INFRA_FILENAME_PATTERNS:
        if p in name_lower:
            return "data"  # 인프라 파일은 data로 분류 → missing/semantic 규칙 제외

    # main.c 파일: 보통 테스트/데모 드라이버 (단일 main 함수만 포함)
    base = name_lower.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    if base == "main.c":
        return "test"

    # 데이터 전용 파일: 함수 정의 0개 + const 배열만
    has_func_def = bool(_FUNC_DEF_RE.search(content))
    has_const_array = bool(re.search(r'\bconst\b.*\{', content))

    if not has_func_def and has_const_array:
        return "data"

    # Thin wrapper/dispatcher 파일: 모든 함수가 1~2문 위임 패턴
    if has_func_def and _is_wrapper_file(content):
        return "wrapper"

    return "impl"


def _extract_decl_var(snippet: str) -> str:
    """스니펫 첫 줄에서 배열/변수 선언의 식별자(변수명)를 추출한다. 타입 키워드는 건너뜀."""
    first_line = (snippet or "").split("\n")[0]
    for m in _VAR_RE.finditer(first_line):
        name = m.group(1)
        if name.lower() in _C_TYPE_KEYWORDS or _UINT_TYPE_RE.match(name):
            continue
        return name.lower()
    return ""


# COM-001에서 "잔존 정보 제거"로 인정할 함수 이름 (직접 호출 + 래퍼)
# 주의: 일반 memset은 컴파일러 최적화로 제거될 수 있으므로 안전한 함수로 인정하지 않음
CLEARING_FUNCTION_NAMES = {
    "memset_s", "SecureZeroMemory", "explicit_bzero", "RtlSecureZeroMemory",
    "secure_clear", "clear_key", "secure_free_key", "wipe_buffer",
    "lea_module_zeroize",  # 본 프로젝트의 volatile-pointer 기반 안전 제로화 함수
    "bzero",               # POSIX: bzero도 일부 환경에서 최적화 방지 보장
}
CLEARING_PATTERN = re.compile(
    # 함수 호출 구문(\s*\()을 요구하여 코멘트 내 함수명 언급 오매칭 방지
    "|".join(re.escape(n) + r"\s*\(" for n in CLEARING_FUNCTION_NAMES),
    re.IGNORECASE
)

# COM-001: 직접 제로화 루프 패턴
#   for(...) key[i] = 0;  /  for(...) rk[i] = 0;  /  volatile 포인터 루프
# key/iv/rk/nonce/skey/round_key 등 민감 변수명 + [idx] = 0 형태
_ZERO_FILL_LOOP_RE = re.compile(
    r"for\s*\([^)]*\)"           # for(...) 루프 헤더
    r"(?:[^{;]*\{[^}]*|\s*)"    # { ... } 또는 단문
    r"\b(key|rk|iv|nonce|skey|round_key|subkey|mk)\b"
    r"\s*\[[^\]]*\]\s*=\s*0\s*;",
    re.IGNORECASE | re.DOTALL,
)

# COM-001 함수별 키 변수 미제거 탐지 헬퍼
# LEA_KEY/LEA_CTX 지역 변수 또는 uint8_t 암호 배열을 선언하고도 제거 함수를
# 호출하지 않는 함수가 존재하는지 탐지한다. (AST 없이 정규식 기반)
_COM001_ANY_CLEAR_FUNCS = (
    "memset", "memset_s", "lea_zeroize", "lea_module_zeroize", "lea_secure_zero",
    "explicit_bzero", "SecureZeroMemory", "bzero", "RtlSecureZeroMemory",
    "secure_clear", "wipe_buffer",
)
_COM001_KEY_TYPE_DECL_RE = re.compile(
    r"^\s+(?:LEA_KEY|LEA_CTX)\s+(\w+)\s*;",
    re.MULTILINE,
)
_COM001_KEY_ARRAY_DECL_RE = re.compile(
    r"^\s+uint8_t\s+(\w+)\s*\[(?:8|16|24|32)\]",
    re.MULTILINE,
)
_COM001_CRYPTO_ARRAY_KWS = frozenset(
    ["iv", "ctr", "ks", "key", "nonce", "block", "buf", "mac", "tag"]
)


def _extract_top_level_blocks(content: str) -> list:
    """C 소스에서 최상위 {} 블록(함수 본체 등)을 브레이스 매칭으로 추출."""
    blocks = []
    depth = 0
    start = -1
    for i, c in enumerate(content):
        if c == "{":
            depth += 1
            if depth == 1:
                start = i
        elif c == "}":
            depth -= 1
            if depth == 0 and start >= 0:
                blocks.append(content[start : i + 1])
                start = -1
    return blocks


def _has_uncleared_key_var(content: str) -> bool:
    """파일 내 함수 본체를 분석하여 LEA_KEY/LEA_CTX 또는 암호 uint8_t 배열 변수를
    선언하고도 안전 제거 함수로 해제하지 않는 함수가 존재하면 True 반환."""
    stripped = _strip_c_comments(content)
    blocks = _extract_top_level_blocks(stripped)
    clear_func_ptn = "|".join(re.escape(f) for f in _COM001_ANY_CLEAR_FUNCS)
    for block in blocks:
        # LEA_KEY / LEA_CTX 지역 변수 검사
        for m in _COM001_KEY_TYPE_DECL_RE.finditer(block):
            varname = m.group(1)
            clear_re = re.compile(
                r"\b(?:" + clear_func_ptn + r")\s*\(\s*&?"
                + re.escape(varname) + r"\s*,",
            )
            if not clear_re.search(block):
                return True
        # uint8_t 암호 배열 지역 변수 검사
        for m in _COM001_KEY_ARRAY_DECL_RE.finditer(block):
            varname = m.group(1)
            if any(kw in varname.lower() for kw in _COM001_CRYPTO_ARRAY_KWS):
                clear_re = re.compile(
                    r"\b(?:" + clear_func_ptn + r")\s*\(\s*&?"
                    + re.escape(varname) + r"\s*,",
                )
                if not clear_re.search(block):
                    return True
    return False

# COM-003: 하드코딩 키 탐지에서 제외할 변수명/컨텍스트 키워드 (S-box, 룩업테이블, 테스트벡터 등)
_COM003_FP_KEYWORDS = frozenset({
    "sbox", "s_box", "delta", "lookup", "table", "lut",
    "test_pt", "test_ct", "test_key", "test_iv", "test_nonce",
    "kat", "vector", "sample", "round_const", "rcon",
    "permut", "weight", "mds", "mask", "pad", "crc",
    "example", "dummy", "bench", "ref_",
    "reduction", "gf_mul", "galois", "ghash_table",
})


def _strip_c_comments(text: str) -> str:
    """C 블록(/* */) 및 라인(//) 주석 제거. 줄 수는 보존한다."""
    text = re.sub(
        r'/\*.*?\*/',
        lambda m: '\n' * m.group(0).count('\n'),
        text,
        flags=re.DOTALL,
    )
    text = re.sub(r'//[^\n]*', '', text)
    return text


def load_ruleset(rules_dir: Path, category: str, name: Optional[str] = None) -> List[Dict]:
    """
    rules/{common|algorithm|mode}/{name}.yaml 로드.
    name이 None이면 해당 category 하위 전체 로드.
    """
    rules = []
    base = rules_dir / category
    if not base.exists():
        return rules
    if name:
        path = base / f"{name}.yaml"
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
                rules.extend(data.get("rules", []))
    else:
        for f in base.glob("*.yaml"):
            with open(f, "r", encoding="utf-8") as fp:
                data = yaml.safe_load(fp) or {}
                rules.extend(data.get("rules", []))
    return rules



# ─────────────────────────────────────────────────────────────────
# COM-001 키 생명주기 분석 헬퍼
# ─────────────────────────────────────────────────────────────────

# 키 관련 변수명 패턴 (민감 변수)
_KEY_VAR_RE = re.compile(
    r"\b(key|rk|mk|iv|nonce|skey|round_key|subkey|master_key|session_key)\b",
    re.IGNORECASE,
)

# 키 초기화/설정 함수 패턴
_KEY_SETTER_RE = re.compile(
    r"\b(lea_set_key|set_key|key_schedule|keygen|key_init|key_setup|key_expand)\s*\(",
    re.IGNORECASE,
)

# 암호화/복호화 사용 패턴
_CRYPTO_USE_RE = re.compile(
    r"\b(lea_encrypt|lea_decrypt|lea_ecb_enc|lea_ecb_dec|lea_cbc_enc|lea_cbc_dec|lea_ctr_enc|lea_ctr_dec|lea_gcm|lea_ccm|lea_ofb|lea_cfb|encrypt|decrypt)\s*\(",
    re.IGNORECASE,
)


def _build_key_lifecycle(
    content: str,
    file_display: str,
    symbol_graph: Optional[Dict[str, Any]],
) -> str:
    """파일 내 키 생명주기 분석.

    Returns: 키 초기화 → 사용 → 제거 흐름 요약 문자열 (AI 프롬프트용)
    """
    lines = content.splitlines()

    # 1. 키 관련 변수 선언 탐지
    key_decl_lines = []
    for i, line in enumerate(lines, 1):
        if _KEY_VAR_RE.search(line) and re.search(r"\[|=", line):
            key_decl_lines.append((i, line.strip()[:80]))

    # 2. 키 초기화 함수 호출 탐지
    key_init_lines = []
    for i, line in enumerate(lines, 1):
        if _KEY_SETTER_RE.search(line):
            key_init_lines.append((i, line.strip()[:80]))

    # 3. 암호화 사용 탐지
    crypto_lines = []
    for i, line in enumerate(lines, 1):
        if _CRYPTO_USE_RE.search(line):
            crypto_lines.append((i, line.strip()[:80]))

    # 4. 제거 함수 탐지
    clear_lines = []
    for i, line in enumerate(lines, 1):
        if CLEARING_PATTERN.search(line):
            clear_lines.append((i, line.strip()[:80]))

    # 5. 직접 제로화 루프 탐지
    zero_loop_lines = []
    for i, line in enumerate(lines, 1):
        if _ZERO_FILL_LOOP_RE.search(line):
            zero_loop_lines.append((i, line.strip()[:80]))

    parts = ["[키 생명주기 분석]"]
    if key_decl_lines:
        for ln, text in key_decl_lines[:3]:
            parts.append(f"  선언: L{ln} {text}")
    if key_init_lines:
        for ln, text in key_init_lines[:3]:
            parts.append(f"  초기화: L{ln} {text}")
    else:
        parts.append("  초기화: (탐지 안 됨)")
    if crypto_lines:
        for ln, text in crypto_lines[:3]:
            parts.append(f"  사용: L{ln} {text}")
    if clear_lines:
        for ln, text in clear_lines[:3]:
            parts.append(f"  ✅ 제거: L{ln} {text}")
    elif zero_loop_lines:
        for ln, text in zero_loop_lines[:2]:
            parts.append(f"  ✅ 제거(루프): L{ln} {text}")
    else:
        parts.append("  ❌ 제거: 제로화 함수 호출 미발견")

    # symbol_graph에서 크로스파일 제거 정보 보강
    if symbol_graph:
        call_graph = symbol_graph.get("call_graph") or []
        for edge in call_graph:
            if edge.get("caller_file") and file_display in edge.get("caller_file", ""):
                callee = edge.get("callee_name") or ""
                if CLEARING_PATTERN.search(callee):
                    defined_in = edge.get("defined_in") or "외부 함수"
                    parts.append(f"  ✅ 제거(외부): {callee}() @ {defined_in}")
                    break

    return "\n".join(parts)


def _apply_rule_to_file(
    file_path: Path,
    content: str,
    rule: Dict,
    job_root: Path,
    ast: Optional[Dict[str, Any]] = None,
    symbol_graph: Optional[Dict[str, Any]] = None,
    stripped_content: str = "",
) -> List[Dict[str, Any]]:
    """
    단일 파일에 대해 단일 룰 적용.
    - pattern_type "missing" : 패턴이 없으면 파일 전체 레벨 위반 1건 반환.
      COM-001이고 ast.file_calls가 있으면 호출 이름으로 먼저 판단.
    - pattern_type "regex"   : 패턴이 매칭되는 각 위치마다 위반 1건씩 반환.
    - pattern_type "semantic": 키워드(pattern) 미존재 시 L1 위반 후보 1건 반환 +
      needs_ai_review=True 표시 (추후 L3 AI가 의미적 재판정 예정).
    Returns: 위반 리스트(없으면 빈 리스트)
    """
    pattern_type = rule.get("pattern_type")
    pattern = rule.get("pattern")
    if not pattern:
        return []

    violations: List[Dict[str, Any]] = []
    if pattern_type == "missing":
        found = False
        if rule.get("id") == "COM-001" and ast and isinstance(ast.get("file_calls"), list):
            for call in ast.get("file_calls", []):
                name = (call.get("name") if isinstance(call, dict) else None)
                if name and CLEARING_PATTERN.search(name):
                    found = True
                    break
        if not found and rule.get("id") == "COM-001" and symbol_graph:
            try:
                rel_path = file_path.resolve().relative_to(job_root.resolve())
                file_display = str(rel_path).replace("\\", "/")
            except ValueError:
                file_display = str(file_path)
            clearing_files = set(symbol_graph.get("files_with_clearing_call") or [])
            call_graph = symbol_graph.get("call_graph") or []

            # Level-1: 이 파일에서 직접 제거 함수 호출 여부
            for edge in call_graph:
                if edge.get("caller_file") != file_display:
                    continue
                callee = edge.get("callee_name")
                if callee and CLEARING_PATTERN.search(callee):
                    found = True
                    break

            # Level-2: 이 파일의 함수가 호출하는 중간 함수가 제거 함수를 호출하는지 추적
            # 예: lea_encrypt → my_cleanup → memset_s
            if not found:
                # 이 파일에서 호출하는 모든 callee와 그 정의 파일 수집
                callees_with_def = {}  # callee_name → definition_file
                for edge in call_graph:
                    if edge.get("caller_file") != file_display:
                        continue
                    cname = edge.get("callee_name")
                    if not cname:
                        continue
                    # 정의 파일: edge의 defined_in 또는 definitions에서 조회
                    def_file = edge.get("defined_in") or ""
                    if not def_file:
                        definitions = symbol_graph.get("definitions") or {}
                        if cname in definitions:
                            entries = definitions[cname]
                            if not isinstance(entries, list):
                                entries = [entries]
                            for entry in entries:
                                def_file = entry.get("file") or ""
                                if def_file:
                                    break
                    callees_with_def[cname] = def_file

                # 각 callee의 정의 파일이 clearing_files에 포함되거나
                # 해당 파일에서 제거 함수를 직접 호출하는 edge가 있으면 2-hop 성립
                for cname, def_file in callees_with_def.items():
                    if def_file and def_file in clearing_files:
                        found = True
                        break
                    # def_file에서 제거 함수를 호출하는 edge 확인
                    if def_file:
                        for edge2 in call_graph:
                            if edge2.get("caller_file") != def_file:
                                continue
                            callee2 = edge2.get("callee_name") or ""
                            if CLEARING_PATTERN.search(callee2):
                                found = True
                                break
                    if found:
                        break
        if not found:
            try:
                compiled = re.compile(pattern)
                # missing 룰은 주석 제거 콘텐츠에서 검사 (주석 속 "올바른 키워드" 오탐 방지)
                check_content = stripped_content if stripped_content else content
                if re.search(compiled, check_content):
                    found = True
            except re.error:
                pass
        if found:
            return []
        try:
            rel_path = file_path.resolve().relative_to(job_root.resolve())
            file_display = str(rel_path).replace("\\", "/")
        except ValueError:
            file_display = str(file_path)
        snippet = content[:200].strip() if content else ""

        # 키 생명주기 분석 (COM-001 전용) — L3 AI에게 구체적 근거 제공
        key_lifecycle = _build_key_lifecycle(content, file_display, symbol_graph)

        violations.append({
            "rule_id": rule.get("id", ""),
            "file": file_display,
            "line": None,
            "scope": "file",
            "message": rule.get("name") or "잔존 정보 제거 필요",
            "severity": rule.get("severity", "high"),
            "confidence": "확정",
            "snippet": snippet,
            "key_lifecycle": key_lifecycle,
            "needs_ai_review": False,  # COM-001은 L1 확정 위반이나 lifecycle 정보를 AI에게 제공
        })
        return violations

    try:
        compiled = re.compile(pattern)
    except re.error:
        return []

    if pattern_type == "regex":
        # 정규식 패턴은 실제 매칭 위치 기준으로 줄 번호를 계산해, 매칭마다 위반 생성.
        # COM-003처럼 여러 줄에 걸친 블록(하드코딩 배열 등)을 한 덩어리로 다루기 위해
        # 매칭 시작 줄(line)과 끝 줄(end_line)을 함께 기록한다.
        lines = content.splitlines()
        for match in compiled.finditer(content):
            try:
                rel_path = file_path.resolve().relative_to(job_root.resolve())
                file_display = str(rel_path)
            except ValueError:
                file_display = str(file_path)

            start_index = match.start()
            end_index = match.end()
            # 매칭 시작/끝 위치까지의 개행 수를 세어 1-based 줄 번호 계산
            start_line = content.count("\n", 0, start_index) + 1
            end_line = content.count("\n", 0, end_index) + 1
            # snippet은 시작 줄 위주로 짧게 보여준다
            line_text = lines[start_line - 1] if lines else ""
            snippet = line_text[:200].strip()

            # COM-003: S-box·델타상수·테스트벡터 등 FP 패턴 조기 제거
            if rule.get("id") == "COM-003":
                name_match = re.search(r'\b(\w+)\s*[\[=]', line_text)
                var_name = name_match.group(1).lower() if name_match else ""
                ctx_lines = lines[max(0, start_line - 3):start_line + 1]
                ctx_text = " ".join(ctx_lines).lower()
                if any(kw in var_name or kw in ctx_text[:200] for kw in _COM003_FP_KEYWORDS):
                    continue  # 알려진 FP 패턴 — 스킵

            # 주석 줄 매칭 제거 (/* ... */ 또는 // ... 주석에서 함수명 매칭 방지)
            stripped_line = line_text.strip()
            if stripped_line.startswith('//') or stripped_line.startswith('*') or stripped_line.startswith('/*'):
                continue

            # COM-004: rand()/clock()/time() 가 단순 인덱스/비교/테스트용이면 제외
            # clock()/time()은 non-crypto 용도가 많으므로 crypto 컨텍스트 확인 필요
            if rule.get("id") == "COM-004":
                ctx_lines = lines[max(0, start_line - 3):start_line + 3]
                ctx_text = " ".join(ctx_lines).lower()
                matched_text = line_text.lower()

                # clock()/time()은 암호학적 컨텍스트 확인 후에만 위반 처리
                _is_clock_or_time = re.search(r'\bclock\s*\(\s*\)|\btime\s*\(\s*NULL', matched_text)
                if _is_clock_or_time:
                    _crypto_ctx_clock = re.compile(
                        r'\b(iv|key|nonce|ctr|counter|skey|random|entropy)\b',
                        re.IGNORECASE
                    )
                    if not _crypto_ctx_clock.search(ctx_text):
                        continue  # non-crypto context → 시간 측정 등 일반 목적

                # rand()%N은 IV/key/ctr 컨텍스트이면 위반 유지
                _is_rand_pct = re.search(r'rand\s*\(\s*\)\s*%', matched_text)
                if _is_rand_pct:
                    _crypto_ctx = re.compile(
                        r'\b(iv|key|nonce|ctr|counter|secret|skey)\b',
                        re.IGNORECASE
                    )
                    if not _crypto_ctx.search(ctx_text):
                        # 단순 범위 제한 인덱스/비교 목적 → 제외
                        _com004_safe = re.compile(
                            r'rand\s*\(\s*\)\s*==|'
                            r'\b(test|sample|dummy|printf|fprintf|puts)\b',
                            re.IGNORECASE
                        )
                        if _com004_safe.search(ctx_text):
                            continue

            violations.append({
                "rule_id": rule.get("id", ""),
                "file": file_display,
                "line": start_line,
                "end_line": end_line,
                "scope": "line-range",
                "message": rule.get("name", ""),
                "severity": rule.get("severity", "medium"),
                "pattern_type": rule.get("pattern_type", "regex"),
                "confidence": "확정",
                "snippet": snippet,
                "needs_ai_review": False,
            })

    elif pattern_type == "semantic":
        # L1 키워드 트리거: 패턴(핵심 키워드/개념)이 파일에 존재하지 않으면
        # 위반 후보를 생성하고 needs_ai_review=True 로 표시한다.
        # L3 AI가 연결된 후 이 위반들을 의미적으로 재판정한다.
        pattern_found = bool(re.search(compiled, content))

        # COM-005 보강: API 호출 순서 라인-레벨 체크 (init→update→final)
        if rule.get("id") == "COM-005":
            if pattern_found:
                lines_list = content.splitlines()
                init_lines, update_lines, final_lines = [], [], []
                for idx, ln in enumerate(lines_list, 1):
                    if re.search(r'\blea_online_init\s*\(', ln):
                        init_lines.append(idx)
                    if re.search(r'\blea_online_update\s*\(', ln):
                        update_lines.append(idx)
                    if re.search(r'\blea_online_final\s*\(', ln):
                        final_lines.append(idx)
                order_ok = True
                if update_lines and init_lines and min(update_lines) < min(init_lines):
                    order_ok = False  # update before init
                if update_lines and not init_lines:
                    order_ok = False  # update without init
                if init_lines and not final_lines:
                    order_ok = False  # no final after init
                if not order_ok:
                    try:
                        rel_path = file_path.resolve().relative_to(job_root.resolve())
                        file_display = str(rel_path).replace("\\", "/")
                    except ValueError:
                        file_display = str(file_path)
                    # bad_line: 순서 위반이 발생한 첫 번째 줄
                    if update_lines and init_lines and min(update_lines) < min(init_lines):
                        bad_line = update_lines[0]  # update before init
                    elif update_lines and not init_lines:
                        bad_line = update_lines[0]  # update without init
                    elif init_lines and not final_lines:
                        bad_line = init_lines[0]    # init without final
                    else:
                        bad_line = None
                    violations.append({
                        "rule_id": rule.get("id", ""),
                        "file": file_display,
                        "line": bad_line,
                        "scope": "file" if bad_line is None else "line-range",
                        "message": rule.get("name", ""),
                        "severity": rule.get("severity", "high"),
                        "confidence": "후보",
                        "snippet": (lines_list[bad_line - 1][:200] if bad_line else content[:200]).strip(),
                        "needs_ai_review": True,
                        "pattern_type": "semantic",
                    })
            # COM-005는 여기서 끝 (패턴 미발견 = API 미사용 = 별도 위반 불필요)
        elif not pattern_found:
            # 일반 semantic 룰: 패턴이 없으면 위반 후보 생성
            try:
                rel_path = file_path.resolve().relative_to(job_root.resolve())
                file_display = str(rel_path).replace("\\", "/")
            except ValueError:
                file_display = str(file_path)
            snippet = content[:200].strip() if content else ""
            violations.append({
                "rule_id": rule.get("id", ""),
                "file": file_display,
                "line": None,
                "scope": "file",
                "message": rule.get("name", ""),
                "severity": rule.get("severity", "medium"),
                "confidence": "후보",
                "snippet": snippet,
                "needs_ai_review": True,
                "pattern_type": "semantic",
            })

    return violations


def _apply_ast_rule(
    rule: Dict[str, Any],
    file_cache: List[Dict[str, Any]],
    job_root: Path,
    symbol_graph: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """
    pattern_type == ast 인 룰 처리. 3단계 우선순위:

    1. ast_checker_service 구현 규칙 → pycparser 완전 AST로 구조 검사
       위반 없으면 [] 반환 (규칙 준수 확인), 위반 있으면 확정/후보 위반 생성
       파싱 실패 또는 미구현이면 None 반환 → 2단계로 fall through

    2. fallback_pattern 있음 → 파일 스캔으로 구체적 위치 "후보" 위반 생성
       매칭 없으면 관련 파일 1개에 파일 레벨 "후보" 위반 생성

    3. fallback_pattern 없음 → 알고리즘/모드 관련 파일(최대 3개)에 파일 레벨
       "후보" 위반 생성, description 을 AI 판단 컨텍스트로 포함

    생성된 위반은 L3(Gemini)에서 의미적 재판정을 받는다.
    """
    rule_id  = rule.get("id", "")
    severity = rule.get("severity", "medium")
    name     = rule.get("name", "")
    desc     = rule.get("description", "")
    algo     = (rule.get("algorithm") or "").lower()
    mode_kw  = (rule.get("mode") or "").lower()
    fallback = rule.get("fallback_pattern", "")

    # check_in: 규칙을 특정 파일 타입에만 적용 (예: ["test", "benchmark"])
    # MCT/MMT 검증 규칙은 테스트/벤치마크 파일에만 존재해야 함 — 구현 파일 FP 방지
    check_in = rule.get("check_in")
    if check_in:
        # check_in이 지정된 경우, 해당 파일 타입의 파일만 검사 대상으로 제한
        file_cache = [
            item for item in file_cache
            if item.get("file_type", "impl") in check_in
        ]
        if not file_cache:
            return []  # 해당 파일 타입이 없으면 규칙 적용 자체를 건너뜀

    violations: List[Dict[str, Any]] = []
    ast_checker_handled = False  # ast_checker_service 가 처리했는지 여부

    def _get_display(item: Dict[str, Any]) -> str:
        try:
            rel = item["path"].resolve().relative_to(job_root.resolve())
            return str(rel).replace("\\", "/")
        except (ValueError, AttributeError, KeyError):
            return str(item.get("path", ""))

    def _relevant_files() -> List[Dict[str, Any]]:
        """알고리즘/모드 구현 파일 우선 선택. .c 파일 > .h 파일, 테스트 파일 후순위."""
        keywords = [kw for kw in (algo, mode_kw) if kw]
        matched = [
            item for item in file_cache
            if any(kw in (item.get("display") or "").lower() for kw in keywords)
        ] if keywords else list(file_cache)
        if not matched:
            matched = list(file_cache)

        def _sort_key(item: Dict[str, Any]) -> tuple:
            d = (item.get("display") or "").lower()
            fname = d.split("/")[-1]
            is_test = "test" in fname or "vector" in fname
            is_header = fname.endswith(".h")
            is_core = any(kw in fname for kw in ("core", "encrypt", "decrypt", "block"))
            is_impl = fname.endswith(".c") and not is_test
            # 핵심 구현 파일 (0) > 기타 구현 .c (1) > 테스트 .c (2) > .h (3)
            if is_impl and is_core:
                rank = 0
            elif is_impl:
                rank = 1
            elif fname.endswith(".c"):
                rank = 2
            elif is_header:
                rank = 3
            else:
                rank = 4
            return (rank, d)

        return sorted(matched, key=_sort_key)

    # ── 단계 1: ast_checker_service 로 구조적 AST 검사 시도 ──
    parse_failed_items: List[Dict[str, Any]] = []  # 파싱 실패한 파일 목록 (fallback 대상)
    try:
        from app.services import ast_checker_service as _ast_svc
        from app.services.ast_checker_service import check_rule as _ast_check

        # 미구현 규칙이면 파일 루프 자체를 건너뜀
        if rule_id not in _ast_svc._CHECKERS:
            raise ImportError("unimplemented")

        # job 내 .h 파일이 있는 모든 디렉터리를 include 경로로 수집
        base_includes: List[str] = []
        seen_dirs: set = set()
        for h in job_root.rglob("*.h"):
            d = str(h.parent)
            if d not in seen_dirs:
                seen_dirs.add(d)
                base_includes.append(d)

        # AST checker는 파일명이 아닌 함수명/구조로 판단하므로 모든 .c 파일 검사
        # (예: violations_cbc_struct.c 안에 ecb_enc 함수가 있어도 탐지 가능)
        # test/data/benchmark/wrapper 파일은 AST 체커에서도 제외 — 파싱 실패 시
        # parse_failed_items에 들어가 관련 없는 파일에 fallback FP 유발 방지.
        # 단, 운영 모드 보안 규칙(CBC/CTR/GCM 등)은 test 파일에도 적용:
        # 삽입된 위반 함수(CBC without IV, CTR without overflow check)가
        # test 파일에 있어도 탐지해야 함 (mutation recall 보장).
        _MODE_SECURITY_RULES = {
            "CBC-001", "CBC-002", "CTR-001", "CTR-002", "CTR-005",
            "GCM-001", "CCM-001", "ECB-002", "CMAC-001", "OFB-002", "CFB-002",
        }
        _SKIP_FILE_TYPES = ("test", "data", "benchmark", "wrapper")
        if rule_id in _MODE_SECURITY_RULES:
            # 모드 보안 규칙: test 파일 포함 모든 .c 파일 검사
            relevant_for_checker = [
                item for item in file_cache
                if (item.get("display") or "").lower().endswith(".c")
            ] or list(file_cache)
        else:
            relevant_for_checker = [
                item for item in file_cache
                if (item.get("display") or "").lower().endswith(".c")
                and item.get("file_type", "impl") not in _SKIP_FILE_TYPES
            ] or list(file_cache)

        # 참고: 알고리즘별 per-file 필터는 프로젝트 레벨에서만 적용.
        # per-file 필터를 여기에 적용하면 lea_cbc.c/lea_ctr.c 같은 모드 파일의
        # LEA 위반(LEA-046 등)이 누락됨(FN).
        for item in relevant_for_checker:
            content_str = item.get("content") or ""
            fname       = (item.get("display") or "").split("/")[-1]
            # include 경로: 파일 위치 + job src 루트 (헤더 파일 탐색)
            item_path = item.get("path")
            extra_includes: List[str] = list(base_includes)
            if item_path:
                # str → Path 변환 지원 (blind test 등 외부 스크립트 호환)
                _ip = Path(item_path) if isinstance(item_path, str) else item_path
                if _ip.parent.is_dir():
                    extra_includes.insert(0, str(_ip.parent))
            checker_result = _ast_check(rule_id, content_str, fname, rule_meta=rule,
                                        extra_includes=extra_includes or None,
                                        symbol_graph=symbol_graph)
            if checker_result is None:
                # 파싱 실패 → fallback으로 이 파일만 처리
                parse_failed_items.append(item)
                continue
            ast_checker_handled = True
            for finding in checker_result:
                line = finding.get("line")
                msg  = finding.get("message") or name
                # 줄 번호가 있으면 해당 줄 스니펫 추출
                if line:
                    file_lines = content_str.splitlines()
                    snippet = file_lines[line - 1][:200].strip() if line <= len(file_lines) else ""
                else:
                    snippet = content_str[:300].strip()
                # 메시지에서 실제 함수명 추출 (L3 컨텍스트 추출에 사용)
                # AST 체커가 "함수 'funcname'" 형식으로 메시지를 작성하면 여기서 추출됨
                import re as _re_fn
                fn_match = _re_fn.search(r"함수\s+'([^']+)'", msg)
                func_name = fn_match.group(1) if fn_match else None
                violations.append({
                    "rule_id":         rule_id,
                    "file":            _get_display(item),
                    "line":            line,
                    "scope":           "line" if line else "file",
                    "message":         msg,
                    "severity":        severity,
                    "confidence":      "후보",
                    "snippet":         snippet,
                    "needs_ai_review": True,
                    "pattern_type":    "ast",
                    "ai_context":      desc,
                    "func_name":       func_name,
                })
            # 모든 관련 파일을 검사하여 위반 누락 방지 (break 제거)
    except ImportError:
        pass  # 미구현 규칙 → fallback 경로로 진행
    except Exception:
        pass

    # 파싱 성공 파일은 AST 결과로 확정. 파싱 실패 파일은 fallback으로 추가 검사.
    # ast_checker_handled이더라도 파싱 실패 파일이 있으면 그 파일들에만 fallback 적용.
    if ast_checker_handled and not parse_failed_items:
        return violations  # 모든 파일 AST 처리 완료

    # ── 미구현 규칙 + fallback_pattern 없음 → 완전 skip ──
    # fallback_pattern이 없으면 AI에 보낼 의미 있는 코드 컨텍스트가 없으므로
    # 허위 위반을 생성하지 않고 빈 결과 반환
    if not fallback:
        return violations  # = []

    # fallback 적용 대상: AST 미구현/모두 실패 시 전체 file_cache,
    # AST 일부 성공 시 파싱 실패 파일만 대상
    fallback_targets = parse_failed_items if ast_checker_handled else None

    if fallback:
        # ── 경로 1a: fallback_pattern 으로 파일 스캔하여 구체적 위치 위반 생성 ──
        try:
            compiled = re.compile(fallback, re.IGNORECASE)
        except re.error:
            compiled = None

        if compiled:
            scan_items = fallback_targets if fallback_targets is not None else file_cache
            for item in scan_items:
                # 테스트/벤치마크/데이터/wrapper 파일은 fallback regex 스캔 제외
                if item.get("file_type", "impl") in ("test", "data", "benchmark", "wrapper"):
                    continue
                # 참고: per-file 알고리즘 필터는 FN 위험으로 미적용
                # (프로젝트 레벨 필터만 사용)
                content = item.get("content") or ""
                # 주석 제거 콘텐츠로 스캔 — 주석 속 키워드 오탐 방지 (GPTScan 앵커 원칙)
                scan_content = item.get("stripped_content") or content
                lines   = content.splitlines()
                for match in compiled.finditer(scan_content):
                    start_line = scan_content.count("\n", 0, match.start()) + 1
                    line_text  = lines[start_line - 1] if lines else ""
                    violations.append({
                        "rule_id":         rule_id,
                        "file":            _get_display(item),
                        "line":            start_line,
                        "scope":           "line",
                        "message":         name,
                        "severity":        severity,
                        "confidence":      "후보",
                        "snippet":         line_text[:200].strip(),
                        "needs_ai_review": True,
                        "pattern_type":    "ast",
                        "ai_context":      desc,
                    })

        # ── 경로 1b: 매칭 없어도 관련 파일 1개에 파일 레벨 후보 위반 생성 ──
        # (AI가 전체 파일을 검토하여 오구현을 잡아내도록)
        if not violations:
            relevant = _relevant_files()
            item = relevant[0] if relevant else None
            if item:
                violations.append({
                    "rule_id":         rule_id,
                    "file":            _get_display(item),
                    "line":            None,
                    "scope":           "file",
                    "message":         name,
                    "severity":        severity,
                    "confidence":      "후보",
                    "snippet":         (item.get("content") or "")[:300].strip(),
                    "needs_ai_review": True,
                    "pattern_type":    "ast",
                    "ai_context":      desc,
                })
    else:
        # ── 경로 2: 관련 파일에 파일 레벨 후보 위반 생성 (최대 3개 파일) ──
        relevant = _relevant_files()
        for item in relevant[:3]:
            violations.append({
                "rule_id":         rule_id,
                "file":            _get_display(item),
                "line":            None,
                "scope":           "file",
                "message":         name,
                "severity":        severity,
                "confidence":      "후보",
                "snippet":         (item.get("content") or "")[:300].strip(),
                "needs_ai_review": True,
                "pattern_type":    "ast",
                "ai_context":      desc,
            })

    return violations


def _apply_project_missing_rule(
    rule: Dict[str, Any],
    files: List[Dict[str, Any]],
    job_root: Path,
    symbol_graph: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """
    pattern_type == missing 이면서 scope == project 인 룰 처리.
    - "어디든 한 번이라도 존재하면 통과"
    - "어디에도 없으면 프로젝트 레벨 위반 1건만 생성"
    COM-001 은 AST/symbol_graph 를 우선 사용하고, 나머지는 정규식만 사용한다.
    """
    pattern = rule.get("pattern")
    if not pattern:
        return []

    rule_id = rule.get("id")
    found = False

    # COM-005: 파일별 lea_online API 호출 순서 체크 (init→update→final)
    if rule_id == "COM-005":
        per_file_violations = []
        for item in files:
            content = item.get("content") or ""
            # 이 파일에서 lea_online_* API를 사용하지 않으면 스킵
            if not re.search(r'\b(lea_online_init|lea_online_update|lea_online_final)\s*\(', content):
                continue
            lines_list = content.splitlines()
            init_lines, update_lines, final_lines = [], [], []
            for idx, ln in enumerate(lines_list, 1):
                if re.search(r'\blea_online_init\s*\(', ln):
                    init_lines.append(idx)
                if re.search(r'\blea_online_update\s*\(', ln):
                    update_lines.append(idx)
                if re.search(r'\blea_online_final\s*\(', ln):
                    final_lines.append(idx)
            order_ok = True
            if update_lines and init_lines and min(update_lines) < min(init_lines):
                order_ok = False
            if update_lines and not init_lines:
                order_ok = False
            if init_lines and not final_lines:
                order_ok = False
            if not order_ok:
                if update_lines and init_lines and min(update_lines) < min(init_lines):
                    bad_line = update_lines[0]
                elif update_lines and not init_lines:
                    bad_line = update_lines[0]
                elif init_lines and not final_lines:
                    bad_line = init_lines[0]
                else:
                    bad_line = None
                per_file_violations.append({
                    "rule_id": rule_id,
                    "file": item.get("display", ""),
                    "line": bad_line,
                    "scope": "file" if bad_line is None else "line-range",
                    "message": rule.get("name") or "",
                    "severity": rule.get("severity", "high"),
                    "confidence": "후보",
                    "snippet": (lines_list[bad_line - 1][:200] if bad_line and bad_line <= len(lines_list) else content[:200]).strip(),
                    "needs_ai_review": True,
                    "pattern_type": "semantic",
                })
        return per_file_violations

    # COM-001: 파일별 AST 기반으로 "memset() 호출 O + 안전 제로화 호출 X" 파일을 개별 감지
    # - AST가 있는 파일만 검사 (주석 속 memset_s 오탐 방지)
    # - 프로젝트 어딘가에 안전 함수가 있어도 해당 파일이 직접 쓰지 않으면 위반
    if rule_id == "COM-001":
        UNSAFE_CLEAR_PATTERN = re.compile(r"\bmemset\s*\(")
        per_file_violations = []
        any_ast_available = False
        for item in files:
            # 비구현 파일(test/data/benchmark/wrapper)은 제로화 검사 불필요
            if item.get("file_type", "impl") not in ("impl",):
                continue
            ast = item.get("ast") or {}
            file_calls = ast.get("file_calls")
            if not isinstance(file_calls, list):
                # AST 없음: 원문 정규식 fallback (주석 오탐 가능성 있으나 어쩔 수 없음)
                content = item.get("content") or ""
                # CLEARING_PATTERN은 함수 호출 형식(name\s*\()을 요구 → 주석 내 언급 오탐 방지
                if CLEARING_PATTERN.search(content):
                    continue
                # 직접 제로화 루프도 안전 제로화로 인정 (AST 없는 경우에도)
                if _ZERO_FILL_LOOP_RE.search(content):
                    continue
                # memset이 원문에 있고 안전 함수 없으면 위반 후보 (AST 없으므로 확신 낮음)
                if UNSAFE_CLEAR_PATTERN.search(content):
                    per_file_violations.append({
                        "rule_id": rule_id,
                        "file": item.get("display", ""),
                        "line": None,
                        "scope": "file",
                        "message": rule.get("name") or "잔존 정보 제거 필요",
                        "severity": rule.get("severity", "high"),
                        "confidence": "후보",  # AST 없이 원문 검사 → 확신도 낮음
                        "snippet": "",
                        "pattern_type": rule.get("pattern_type", "missing"),
                        "key_lifecycle": _build_key_lifecycle(content, item.get("display", ""), symbol_graph),
                    })
                elif _has_uncleared_key_var(content):
                    # memset 없이 제로화 완전/부분 누락 케이스 (AST 없이 함수별 분석)
                    per_file_violations.append({
                        "rule_id": rule_id,
                        "file": item.get("display", ""),
                        "line": None,
                        "scope": "file",
                        "message": rule.get("name") or "잔존 정보 제거 필요",
                        "severity": rule.get("severity", "high"),
                        "confidence": "확정",
                        "snippet": "",
                        "pattern_type": rule.get("pattern_type", "missing"),
                        "key_lifecycle": _build_key_lifecycle(content, item.get("display", ""), symbol_graph),
                    })
                continue

            any_ast_available = True
            call_names = {
                c.get("name") for c in file_calls
                if isinstance(c, dict) and c.get("name")
            }
            has_safe_clear = bool(call_names & CLEARING_FUNCTION_NAMES)
            # 직접 제로화 루프도 안전 제로화로 인정
            # for(...) key[i] = 0; / for(...) rk[i] = 0; 등
            if not has_safe_clear:
                content_for_loop = item.get("content") or ""
                if _ZERO_FILL_LOOP_RE.search(content_for_loop):
                    has_safe_clear = True
            # 컴파일러가 memset을 __builtin___memset_chk 등으로 확장하는 경우도 포함
            _UNSAFE_MEMSET_NAMES = {"memset", "__builtin___memset_chk", "__builtin_memset", "__memset_chk"}
            has_unsafe_memset = bool(call_names & _UNSAFE_MEMSET_NAMES)
            if has_unsafe_memset and not has_safe_clear:
                _content_for_lc = item.get("content") or ""
                per_file_violations.append({
                    "rule_id": rule_id,
                    "file": item.get("display", ""),
                    "line": None,
                    "scope": "file",
                    "message": rule.get("name") or "잔존 정보 제거 필요",
                    "severity": rule.get("severity", "high"),
                    "confidence": "확정",  # AST 직접 분석 결과
                    "snippet": "",
                    "pattern_type": rule.get("pattern_type", "missing"),
                    "key_lifecycle": _build_key_lifecycle(_content_for_lc, item.get("display", ""), symbol_graph),
                })
            elif not has_unsafe_memset and not has_safe_clear:
                # memset 없이 제로화 완전/부분 누락 케이스 (AST 통화 + 함수별 분석)
                _content_for_fn = item.get("content") or ""
                if _has_uncleared_key_var(_content_for_fn):
                    per_file_violations.append({
                        "rule_id": rule_id,
                        "file": item.get("display", ""),
                        "line": None,
                        "scope": "file",
                        "message": rule.get("name") or "잔존 정보 제거 필요",
                        "severity": rule.get("severity", "high"),
                        "confidence": "확정",
                        "snippet": "",
                        "pattern_type": rule.get("pattern_type", "missing"),
                        "key_lifecycle": _build_key_lifecycle(_content_for_fn, item.get("display", ""), symbol_graph),
                    })

        # 프로젝트 전체에 안전 제로화 함수가 아예 없는 경우(AST 미파싱 환경 등)에도 최소 1건 보장
        if not per_file_violations and not any_ast_available:
            # 기존 방식: 정규식으로 전체 스캔 (impl 파일만 대상)
            impl_files = [f for f in files if f.get("file_type", "impl") == "impl"]
            try:
                compiled = re.compile(pattern)
            except re.error:
                compiled = None
            if compiled and impl_files:
                project_has_safe = any(
                    re.search(compiled, item.get("content") or "")
                    for item in impl_files
                )
                if not project_has_safe:
                    file_display = impl_files[0].get("display", "") if impl_files else ""
                    return [{
                        "rule_id": rule_id,
                        "file": file_display,
                        "line": None,
                        "scope": "project",
                        "message": rule.get("name") or "",
                        "severity": rule.get("severity", "high"),
                        "confidence": "후보",
                        "snippet": "",
                        "pattern_type": rule.get("pattern_type", "missing"),
                    }]

        return per_file_violations
    else:
        # 일반 project-level missing 룰: 정규식이 어디든 한 번이라도 매칭되면 통과
        # missing 룰은 주석 제거 콘텐츠에서 검사 (주석 속 "올바른 키워드" 오탐 방지)
        #
        # required_all_patterns: 목록의 패턴이 모두 존재해야 통과 (예: LEA-011 델타 상수 8개 전부)
        required_all = rule.get("required_all_patterns") or []
        if required_all:
            all_content = "\n".join(
                item.get("stripped_content") or item.get("content") or ""
                for item in files
                if item.get("file_type", "impl") == "impl"
            )
            missing_ptns = []
            for ptn in required_all:
                try:
                    if not re.search(ptn, all_content, re.IGNORECASE):
                        missing_ptns.append(ptn)
                except re.error:
                    pass
            if not missing_ptns:
                return []  # 모든 필수 패턴 존재 → 통과
            # 하나 이상 누락 → 위반 생성 (found=False 로 fall-through)
        else:
            try:
                compiled = re.compile(pattern)
            except re.error:
                compiled = None
            if compiled:
                for item in files:
                    content = item.get("stripped_content") or item.get("content") or ""
                    if re.search(compiled, content):
                        found = True
                        break

    if found:
        return []

    # 어디에서도 못 찾았으면, 프로젝트 레벨 위반 1건 생성
    # 대표 파일 선택: algorithm/mode 키워드를 포함하는 .c 파일 우선 (헤더 파일 제외)
    file_display = ""
    if files:
        algo_kw = (rule.get("algorithm") or "").lower()
        mode_kw = (rule.get("mode") or "").lower()
        keywords = [kw for kw in (algo_kw, mode_kw) if kw]
        c_candidates = [
            item for item in files
            if (item.get("display") or "").lower().endswith(".c")
            and item.get("file_type", "impl") == "impl"
        ]
        if not c_candidates:
            c_candidates = [
                item for item in files
                if (item.get("display") or "").lower().endswith(".c")
            ]
        if keywords and c_candidates:
            kw_matched = [
                item for item in c_candidates
                if any(kw in (item.get("display") or "").lower() for kw in keywords)
            ]
            if kw_matched:
                file_display = kw_matched[0].get("display") or ""
            else:
                file_display = c_candidates[0].get("display") or ""
        elif c_candidates:
            file_display = c_candidates[0].get("display") or ""
        else:
            file_display = files[0].get("display") or ""

    # 대표 파일의 코드 컨텍스트 준비 (L3 AI 판정용)
    repr_content = ""
    if file_display:
        for item in files:
            if item.get("display", "") == file_display:
                repr_content = (item.get("content") or "")[:2000]
                break

    return [
        {
            "rule_id": rule_id or "",
            "file": file_display,
            "line": None,
            "scope": "project",
            "message": rule.get("name") or "",
            "severity": rule.get("severity", "high"),
            "confidence": "후보",  # L3 AI 재판정 대상
            "snippet": repr_content[:300],
            "needs_ai_review": True,
            "pattern_type": rule.get("pattern_type", "missing"),
            "ai_context": rule.get("description", ""),
        }
    ]


def run_rule_engine(
    preprocess_result: Dict[str, Any],
    rules_dir: Path,
    job_root: Path,
    algorithms: Optional[List[str]] = None,
    modes: Optional[List[str]] = None,
    symbol_graph: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """
    L1 룰 엔진 실행.
    - preprocess_result: PreprocessService.run_preprocess() 출력
    - job_root: 보고서용 상대 경로 계산
    - algorithms: ["LEA"], modes: ["CBC"] 등
    Returns: [ { "rule_id", "file", "line", "message", "severity", "snippet" }, ... ]
    """
    violations: List[Dict[str, Any]] = []
    files_raw = preprocess_result.get("files", [])

    # 파일 내용을 한 번만 읽어서 캐시해 두고, 룰은 이 캐시에 대해 반복 적용한다.
    file_cache: List[Dict[str, Any]] = []
    for item in files_raw:
        path_str = item.get("path")
        if not path_str:
            continue
        path = Path(path_str)
        if not path.is_absolute():
            path = (job_root / path_str).resolve()
        if not path.is_file():
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            content = ""
        try:
            rel = path.resolve().relative_to(job_root.resolve())
            display = str(rel).replace("\\", "/")
        except ValueError:
            display = str(path)
        fname = display.split("/")[-1]
        file_type = _classify_file(fname, content)
        file_cache.append(
            {
                "path": path,
                "display": display,
                "content": content,
                "stripped_content": _strip_c_comments(content),
                "ast": item.get("ast") or {},
                "file_type": file_type,  # impl / test / data / benchmark / wrapper
            }
        )

    def _dispatch_rule(rule: Dict[str, Any]) -> None:
        """규칙 하나를 pattern_type에 따라 적절한 핸들러로 분기."""
        pattern_type = rule.get("pattern_type")
        pattern      = rule.get("pattern")

        # ── 알고리즘 스코프 사전 필터 ─────────────────────────────────────────
        # LEA 전용 규칙(algorithm 카테고리, 또는 모드명에 LEA 포함)은
        # LEA 관련 파일에만 적용한다. 이를 위해 활성 파일 캐시를 미리 필터링.
        # COM-* (common 카테고리)과 일반 모드 규칙은 모든 파일 적용 유지.
        _rc = rule.get("category", "")
        _ri = rule.get("id", "").upper()
        _is_lea_scoped = _rc == "algorithm" or (_rc == "mode" and "LEA" in _ri)
        if _is_lea_scoped:
            _active_cache = [
                item for item in file_cache
                if _is_lea_related_file((item.get("display") or "").lower())
            ]
        else:
            _active_cache = file_cache

        if pattern_type == "ast":
            violations.extend(_apply_ast_rule(rule, _active_cache, job_root,
                                              symbol_graph=symbol_graph))
            return

        # missing / regex / semantic 은 pattern 필드가 필수
        if pattern_type not in ("missing", "regex", "semantic") or not pattern:
            return

        scope = (rule.get("scope") or "file").lower()

        # semantic 규칙은 명시적 scope=file 이 없으면 project 레벨로 처리한다.
        # 이유: "이 파일에 memset_s가 없다" × N파일보다 "프로젝트에 memset_s가 없다" × 1건이
        # 실제로 의미 있는 신호다. 파일별 발화는 동일 패턴의 위반을 과도하게 부풀린다.
        effective_scope = scope
        if pattern_type == "semantic" and scope == "file":
            effective_scope = "project"

        if pattern_type in ("missing", "semantic") and effective_scope == "project":
            # ── [GPTScan 앵커] project-scope missing 규칙에도 모드 필터 적용 ──
            # mode 필드가 있는 규칙은 해당 모드를 구현하는 파일이 프로젝트에 없으면 skip.
            # 예: CTR missing 규칙이 CBC-only 프로젝트에 firing하는 FP 방지.
            rule_mode_p = (rule.get("mode") or "").lower()
            if rule_mode_p:
                mode_kw_re_p = _MODE_KEYWORD_RE.get(rule_mode_p)
                if mode_kw_re_p:
                    project_has_mode = any(
                        rule_mode_p in (item.get("display") or "").lower()
                        or mode_kw_re_p.search(item.get("content") or "")
                        for item in file_cache
                    )
                    if not project_has_mode:
                        return  # 이 모드를 구현하는 파일 없음 → missing 규칙 skip

            violations.extend(
                _apply_project_missing_rule(rule, _active_cache, job_root, symbol_graph=symbol_graph)
            )
            return

        # ── [GPTScan 앵커] 모드별 파일 관련성 필터 ──────────────────────────
        # mode 필드가 있는 규칙은 해당 모드를 구현하는 파일에만 적용.
        # 파일명 또는 콘텐츠에 모드 키워드(\bGCM\b 등)가 하나라도 있으면 관련 파일.
        # 이 필터로 GCM 규칙이 CBC 파일에, CTR 규칙이 LEA-057 파일에 적용되는 FP를 차단.
        rule_mode = (rule.get("mode") or "").lower()
        mode_kw_re = _MODE_KEYWORD_RE.get(rule_mode) if rule_mode else None

        # COM-003 하드코딩 키 규칙: 테스트/벤치마크 파일은 정당한 테스트 벡터 포함 → 스킵
        _com003_skip = rule.get("id", "") == "COM-003"

        for item in _active_cache:
            ft = item.get("file_type", "impl")

            # check_in field: 규칙이 특정 파일 타입에만 적용되도록 제한
            # 예: check_in: ["test", "benchmark"] → 구현 파일에는 미적용
            _check_in = rule.get("check_in")
            if _check_in and ft not in _check_in:
                continue  # 이 파일의 타입이 check_in 목록에 없으면 건너뜀

            # 파일 분류 기반 필터링: 테스트/데이터/벤치마크/wrapper 파일에는 구현 품질 규칙 미적용
            # 단, COM(보안 필수) 규칙은 test/demo 파일에도 적용
            # — 하드코딩 키, 비표준 RNG, 제로화 누락은 파일 종류와 무관하게 위반
            # 예외: KAT(Known-Answer Test) 벡터 파일(_0tv, _kat 포함)은 정당한 테스트 벡터 포함 → COM도 스킵
            _rule_category = rule.get("category", "")
            _fname_lower = (item.get("display") or "").lower()
            _is_kat_file = any(kw in _fname_lower for kw in ("_0tv", "0tv_", "_kat", "kat_", "selftest"))
            _is_security_always = (_rule_category == "common") and not _is_kat_file
            if ft in ("test", "data", "benchmark", "wrapper") and not _is_security_always:
                # missing 규칙: 패턴 부재 = 위반인데, 비구현 파일에는 해당 없음
                if pattern_type == "missing":
                    continue
                # regex 규칙: 테스트/벤치마크 파일의 패턴 매칭은 구현 품질과 무관
                if pattern_type == "regex":
                    continue
                # semantic 규칙: 테스트/벤치마크 파일의 구현 품질 검사 스킵
                if pattern_type == "semantic":
                    continue

            if mode_kw_re is not None:
                fname_lower = (item.get("display") or "").lower()
                # 파일명에 모드명이 있으면 관련 파일
                if rule_mode not in fname_lower:
                    # 콘텐츠에 모드 키워드가 없으면 미관련 → skip
                    if not mode_kw_re.search(item.get("content") or ""):
                        continue

            for v in _apply_rule_to_file(
                item["path"],
                item["content"],
                rule,
                job_root,
                ast=item.get("ast"),
                symbol_graph=symbol_graph,
                stripped_content=item.get("stripped_content", ""),
            ):
                violations.append(v)

    # 공통 룰
    for rule in load_ruleset(rules_dir, "common"):
        _dispatch_rule(rule)

    # 알고리즘 룰: 지정되면 해당 알고리즘만, 미지정이면 전체 알고리즘 룰 로드
    # 단, 프로젝트에 해당 알고리즘 구현 코드가 없으면 전체 건너뜀 (FP 방지)
    if algorithms:
        algo_rules = []
        for algo in algorithms:
            algo_rules.extend(load_ruleset(rules_dir, "algorithm", algo.lower()))
    else:
        algo_rules = load_ruleset(rules_dir, "algorithm")

    for rule in algo_rules:
        _dispatch_rule(rule)

    # 모드 룰: 지정되면 해당 모드만, 미지정이면 전체 모드 룰 로드
    if modes:
        mode_rules = []
        for mode in modes:
            mode_rules.extend(load_ruleset(rules_dir, "mode", mode.lower()))
    else:
        mode_rules = load_ruleset(rules_dir, "mode")

    for rule in mode_rules:
        _dispatch_rule(rule)

    # 최종 단계: 중복 제거
    # - missing / semantic: 같은 rule_id + file 조합은 1건만 (파일별 1건)
    # - regex: 같은 rule_id + file + line 조합은 1건만 (위치별 1건, 최대 _MAX_PER_RULE건)
    #   → 서로 다른 파일/라인에서 발생한 실제 위반은 모두 유지
    _MAX_PER_RULE = 30  # rule_id 당 최대 위반 수 (노이즈 방지)
    seen_keys: set = set()
    per_rule_count: Dict[str, int] = {}
    deduped: List[Dict[str, Any]] = []
    for v in violations:
        rid = v.get("rule_id") or ""
        if not rid:
            deduped.append(v)
            continue
        # line이 있는 위반은 항상 라인 레벨 dedup (pattern_type 무관)
        # → 같은 룰이 같은 파일의 여러 줄에서 매칭될 때 각각 별도 위반으로 유지
        if v.get("line") is not None:
            key = (rid, v.get("file", ""), v.get("line"))
        else:
            # file-scope / project-scope: 파일당 1건
            key = (rid, v.get("file", ""))
        if key in seen_keys:
            continue
        # file-scope 위반(line=None, scope='file')은 파일당 1건이므로 캡 적용 제외
        # (파일 수가 30+ 이면 정상 위반이 캡에 걸려 FN 발생)
        is_file_scoped = v.get("line") is None and v.get("scope") == "file"
        if not is_file_scoped and per_rule_count.get(rid, 0) >= _MAX_PER_RULE:
            continue
        seen_keys.add(key)
        per_rule_count[rid] = per_rule_count.get(rid, 0) + 1
        deduped.append(v)

    # 근접 라인 중복 제거: 같은 rule_id + 같은 파일 + 20라인 이내 연속 위반 → 첫 번째만 유지
    # (배열 초기화값 각 줄이 별도 위반으로 탐지되는 노이즈 방지)
    deduped = _dedup_nearby_violations(deduped, window=20)

    return deduped


def _dedup_nearby_violations(
    violations: List[Dict[str, Any]],
    window: int = 20,
) -> List[Dict[str, Any]]:
    """
    같은 (rule_id, file) 조합에서 line이 있는 위반들 중
    앞 위반과의 거리가 window 이내이고 스니펫 변수명이 같을 때 중복으로 간주.

    변수명이 다르면 서로 다른 배열/구조의 위반으로 판정해 유지한다.
    line=None 위반(파일 레벨)은 그대로 보존한다.
    """
    if not violations:
        return violations

    result: List[Dict[str, Any]] = []
    last_kept: Dict[tuple, tuple] = {}  # (rule_id, file) → (line, varname)

    for v in violations:
        line = v.get("line")
        if line is None:
            result.append(v)
            continue

        rid  = v.get("rule_id") or ""
        file = v.get("file") or ""
        key  = (rid, file)
        var  = _extract_decl_var(v.get("snippet", ""))

        prev = last_kept.get(key)
        if prev is not None:
            prev_line, prev_var = prev
            if abs(line - prev_line) <= window:
                if not (var and prev_var and var != prev_var):
                    continue  # 같은 변수 또는 변수명 미확인 → 중복 제거

        last_kept[key] = (line, var)
        result.append(v)

    return result