"""
TraceabilityService: 설계서–코드–시험서 간 추적성/일치성 검사.

TRC-001: 설계서 인터페이스 명세 vs 헤더 파일 함수 선언 일치성
  - 헤더(.h) 파일에서 공개 함수 선언 추출
  - 설계서 텍스트/테이블에서 함수 언급 확인
  - 헤더에 있지만 설계서에 언급이 없는 함수 → 위반

TRC-002: 에러 코드 일치성
  - 설계서 텍스트/테이블에서 에러 코드 상수 추출
  - 코드 파일에서 #define 에러 코드 추출
  - 설계서에는 있지만 코드에 없는 에러 코드 → 위반

TRC-003: 공개 함수 시험 커버리지
  - 헤더 파일 공개 함수 목록
  - 시험서 텍스트에서 함수 언급 확인
  - 언급 없는 함수 비율이 임계값 초과 → 위반

입력 구조:
  design_doc : doc_preprocess_result["sections"] 중 doc_type=="design"인 항목 리스트
  code_index : {
      "header_funcs": {name: {file, line, signature}},  # 헤더 파일 공개 함수
      "source_funcs": {name: {file, line}},             # 구현 파일 정의 함수
      "error_codes":  {code_name: {file, value}},       # #define 에러 코드
  }
  test_doc   : doc_preprocess_result["sections"] 중 doc_type=="test"인 항목 리스트
  rules      : YAML에서 로드한 TRC 룰 리스트
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple

# ─────────────────────────────────────────────────────────────────
# 정규식 패턴
# ─────────────────────────────────────────────────────────────────

# C 헤더 파일의 함수 선언 패턴 (세미콜론으로 끝나는 선언)
# 예: void lea_encrypt(unsigned char *ct, const unsigned char *pt, const LeaKeyCtx *key);
# re.MULTILINE: ^ 가 각 줄 시작 매칭. [^;{]* 는 개행 포함 — 멀티라인 파라미터 지원.
_FUNC_DECL_RE = re.compile(
    r"^"                                     # 줄 시작 (re.MULTILINE)
    r"(?:[a-zA-Z_][a-zA-Z0-9_\s\*]+?\s+)"  # 반환 타입
    r"([a-zA-Z_][a-zA-Z0-9_]*)"             # 함수명 캡처
    r"\s*\([^;{]*\)\s*;",                   # 파라미터 + 세미콜론 (멀티라인 가능)
    re.MULTILINE,
)

# 텍스트에서 함수명처럼 보이는 식별자 추출 (소문자_언더스코어 또는 대문자 시작)
# 괄호가 뒤따르는 경우 우선, 없어도 snake_case는 포함
_FUNC_MENTION_RE = re.compile(
    r"\b([a-zA-Z_][a-zA-Z0-9_]{2,})\s*\("  # 이름 + 여는 괄호
)
_SNAKE_CASE_RE = re.compile(
    r"\b([a-z][a-z0-9]*(?:_[a-z][a-z0-9]*){1,})\b"  # snake_case (최소 2단어)
)

# C 에러 코드 패턴: #define XXXXX_ERR_YYY  -1 또는 숫자
_DEFINE_ERR_RE = re.compile(
    r"#define\s+([A-Z][A-Z0-9_]*(?:ERR(?:OR)?|FAIL(?:URE)?|INVALID|BAD|WRONG)[A-Z0-9_]*)\s+(-?\d+)"
)
# 에러 코드 언급 패턴 (대문자 상수, ERR/FAIL/INVALID 포함)
_ERR_CONST_RE = re.compile(
    r"\b([A-Z][A-Z0-9_]*(?:ERR(?:OR)?|FAIL(?:URE)?|INVALID|BAD|WRONG)[A-Z0-9_]*)\b"
)

# 제외할 C 예약어/공통 함수
_C_KEYWORDS: Set[str] = {
    "if", "for", "while", "do", "switch", "case", "return", "sizeof", "typedef",
    "struct", "enum", "union", "static", "extern", "const", "void", "int", "char",
    "unsigned", "signed", "long", "short", "float", "double", "auto", "register",
    "volatile", "inline", "include", "define", "ifdef", "ifndef", "endif", "else",
    "printf", "fprintf", "malloc", "free", "memset", "memcpy", "memmove",
    "strlen", "strcmp", "strcpy", "strncpy", "assert", "NULL", "true", "false",
}

# 헤더 함수 중 TRC 검사에서 제외할 제너릭 이름
# (모듈 접두어가 없어 설계서 언급 여부 판단이 의미 없는 이름들)
_GENERIC_FUNC_NAMES: Set[str] = {
    "init", "cleanup", "reset", "clear", "update", "final", "finish",
    "encrypt", "decrypt", "encode", "decode",
    "generate", "verify", "validate", "check",
    "get", "set", "read", "write", "open", "close",
    "create", "destroy", "alloc", "dealloc",
    "test", "debug", "print", "dump", "log",
    "hash", "sign", "mac", "kdf", "kat",
    "process", "run", "start", "stop", "handle",
}

# 테스트·벤치마크 함수 식별 suffix — TRC 검사에서 제외
_TEST_FUNC_SUFFIXES: tuple = (
    "_test", "_tests", "_benchmark", "_bench", "_perf",
    "_demo", "_sample", "_example", "_main",
)

# 테스트·벤치마크 헤더 파일 패턴 — 이 파일의 함수는 인덱싱 제외
_TEST_HEADER_PATTERNS: tuple = (
    "benchmark", "bench", "perf", "_test", "test_", "_vs",
    "demo", "sample", "example",
)

# 최소 커버리지 임계값 (TRC-003)
_MIN_COVERAGE_RATIO = 0.5  # 헤더 함수의 50% 이상이 시험서에서 언급되어야 함

# TRC-001, TRC-002 개별 위반 최대 건수 (초과 시 요약 위반 1건으로 대체)
_MAX_TRC001_VIOLATIONS = 10
_MAX_TRC002_VIOLATIONS = 10


# ─────────────────────────────────────────────────────────────────
# 코드 인덱스 구축
# ─────────────────────────────────────────────────────────────────

def build_code_index(preprocess_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    preprocess_result에서 TRC 검사용 코드 인덱스 구축.

    Returns
    -------
    {
        "header_funcs": {func_name_lower: {file, line, signature}},
        "source_funcs": {func_name_lower: {file, line}},
        "error_codes":  {code_name: {file, value}},
    }
    """
    header_funcs: Dict[str, Dict[str, Any]] = {}
    source_funcs: Dict[str, Dict[str, Any]] = {}
    error_codes:  Dict[str, Dict[str, Any]] = {}

    for fi in preprocess_result.get("files", []):
        path = fi.get("path") or ""
        lines_list = fi.get("lines") or []
        full_text = "\n".join(lines_list)
        ast = fi.get("ast") or {}

        # 테스트·벤치마크 헤더 파일 제외 (public API가 아님)
        path_lower = path.lower().replace("\\", "/")
        is_test_header = any(pat in path_lower for pat in _TEST_HEADER_PATTERNS)
        is_header = path.endswith(".h") and not is_test_header

        # ── 헤더 파일: AST 우선 추출 → regex fallback ──
        if is_header:
            # 1. AST 기반 추출 (멀티라인 선언·인라인 함수 정확 인식)
            for func in ast.get("functions") or []:
                name = func.get("name") or ""
                if name.lower() in _C_KEYWORDS or len(name) < 3:
                    continue
                key = name.lower()
                if key not in header_funcs:
                    header_funcs[key] = {
                        "file": path,
                        "line": func.get("line"),
                        "signature": (func.get("signature") or name)[:120],
                        "name": name,
                    }
            # 2. regex fallback (AST 파싱 불가 헤더 대비; 이미 추가된 항목은 스킵)
            for m in _FUNC_DECL_RE.finditer(full_text):
                name = m.group(1)
                if name.lower() in _C_KEYWORDS or len(name) < 3:
                    continue
                key = name.lower()
                if key not in header_funcs:
                    line_no = full_text[: m.start()].count("\n") + 1
                    header_funcs[key] = {
                        "file": path,
                        "line": line_no,
                        "signature": m.group(0).strip()[:120],
                        "name": name,
                    }

        # ── 소스 파일: AST 함수 정의 추출 ──
        for func in ast.get("functions") or []:
            name = func.get("name") or ""
            if not name or len(name) < 3:
                continue
            key = name.lower()
            if key not in source_funcs:
                source_funcs[key] = {
                    "file": path,
                    "line": func.get("line"),
                    "name": name,
                }

        # ── 에러 코드: #define XXXXX_ERR_YYY 추출 ──
        for m in _DEFINE_ERR_RE.finditer(full_text):
            code_name = m.group(1)
            value = m.group(2)
            if code_name not in error_codes:
                error_codes[code_name] = {"file": path, "value": value}

    return {
        "header_funcs": header_funcs,
        "source_funcs": source_funcs,
        "error_codes": error_codes,
    }


# ─────────────────────────────────────────────────────────────────
# 문서 텍스트에서 함수명/에러코드 추출
# ─────────────────────────────────────────────────────────────────

def _iter_section_cells(sections: List[Dict[str, Any]]):
    """섹션 리스트에서 텍스트와 테이블 셀을 순서대로 yield."""
    for sec in sections:
        yield sec.get("text") or ""
        for table in sec.get("tables") or []:
            # tables 구조: [{name, page, headers, rows}]
            if isinstance(table, dict):
                for h in table.get("headers") or []:
                    yield str(h)
                for row in table.get("rows") or []:
                    if isinstance(row, list):
                        for cell in row:
                            yield str(cell)
                    else:
                        yield str(row)
            elif isinstance(table, list):
                # 구형 호환: [[row], ...]
                for row in table:
                    cells = row if isinstance(row, list) else [row]
                    for cell in cells:
                        yield str(cell)


def _extract_func_names_from_sections(sections: List[Dict[str, Any]]) -> Set[str]:
    """
    문서 섹션 리스트에서 함수명 언급 추출.
    반환: lowercase 함수명 집합
    """
    names: Set[str] = set()
    for chunk in _iter_section_cells(sections):
        for m in _FUNC_MENTION_RE.finditer(chunk):
            n = m.group(1)
            if n.lower() not in _C_KEYWORDS and len(n) >= 3:
                names.add(n.lower())
        for m in _SNAKE_CASE_RE.finditer(chunk):
            n = m.group(1)
            if n.lower() not in _C_KEYWORDS:
                names.add(n.lower())
    return names


def _extract_error_codes_from_sections(sections: List[Dict[str, Any]]) -> Set[str]:
    """문서 섹션에서 에러 코드 상수명 추출."""
    codes: Set[str] = set()
    for chunk in _iter_section_cells(sections):
        for m in _ERR_CONST_RE.finditer(chunk):
            codes.add(m.group(1))
    return codes


# ─────────────────────────────────────────────────────────────────
# TRC 검사 함수들
# ─────────────────────────────────────────────────────────────────

def _is_func_mentioned(name: str, key: str, mentioned: Set[str]) -> bool:
    """
    함수명이 문서에서 언급됐는지 확인.

    완화 매칭 규칙 (순서대로 적용):
    1. 완전 매칭: key in mentioned
    2. 모듈_동작 2-파트 접두어: lea_encrypt_block → "lea_encrypt"가 언급되면 통과
    3. 모듈 접두어 (5자 이상): 너무 짧은 접두어("lea" 등)는 과탐 방지를 위해 제외.
       암호모듈 전용 접두어(lea, aria, aes, ccm, gcm 등)는 예외적으로 허용.
    4. 함수명 전체가 제너릭 이름(_GENERIC_FUNC_NAMES)이면 → 통과 (검사 불필요)
    """
    if key in mentioned:
        return True

    # snake_case 분해: lea_encrypt_block → ["lea", "encrypt", "block"]
    parts = key.split("_")

    if len(parts) >= 2:
        # 모듈_동작 2-파트 접두어 매칭 (가장 신뢰도 높음)
        prefix2 = "_".join(parts[:2])
        if prefix2 in mentioned:
            return True

        # 모듈 접두어 매칭 (암호모듈 전용 단어 허용 리스트)
        _CRYPTO_PREFIXES = {"lea", "aria", "aes", "des", "rsa", "ecc", "sha", "hmac",
                            "gcm", "ccm", "cbc", "ctr", "cfb", "ofb", "ecb", "cmac"}
        prefix = parts[0]
        if (len(prefix) >= 5 or prefix in _CRYPTO_PREFIXES) and prefix in mentioned:
            return True

    # 함수 자체가 제너릭 단일 동사이면 설계서 확인 의미 없음 → 통과 처리
    if key in _GENERIC_FUNC_NAMES or name.lower() in _GENERIC_FUNC_NAMES:
        return True

    return False


def _check_trc001(
    design_sections: List[Dict[str, Any]],
    code_index: Dict[str, Any],
    rule: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    TRC-001: 설계서 인터페이스 명세 vs 헤더 함수 선언 일치성.

    헤더 파일에 선언된 공개 API 함수가 설계서에 언급되어 있는지 확인.
    언급 없으면 '설계서에 인터페이스 명세가 누락되었을 가능성' 위반 후보 생성.

    위반이 _MAX_TRC001_VIOLATIONS 건 초과 시, 개별 위반 대신 요약 위반 1건 반환.
    """
    header_funcs = code_index.get("header_funcs", {})
    if not header_funcs or not design_sections:
        return []

    # 설계서 텍스트에서 언급된 함수명 집합
    mentioned = _extract_func_names_from_sections(design_sections)

    unmentioned = []
    severity = rule.get("severity", "medium")

    for key, info in header_funcs.items():
        name = info["name"]
        # 내부/유틸 함수 제외: 언더스코어 시작, 짧은 이름, 테스트 함수
        if name.startswith("_") or len(name) < 5:
            continue
        # 제너릭 단독 이름 제외 (모듈 접두어 없는 경우)
        if name.lower() in _GENERIC_FUNC_NAMES and "_" not in name:
            continue
        # 테스트·벤치마크 함수 제외 (설계서 명세 대상 아님)
        if key.endswith(_TEST_FUNC_SUFFIXES):
            continue
        if _is_func_mentioned(name, key, mentioned):
            continue
        unmentioned.append(info)

    if not unmentioned:
        return []

    total_header = sum(
        1 for k, info in header_funcs.items()
        if not info["name"].startswith("_") and len(info["name"]) >= 5
        and not (info["name"].lower() in _GENERIC_FUNC_NAMES and "_" not in info["name"])
        and not k.endswith(_TEST_FUNC_SUFFIXES)
    )
    uncovered_count = len(unmentioned)

    # 위반 수가 캡 초과 → 요약 위반 1건으로 대체
    if uncovered_count > _MAX_TRC001_VIOLATIONS:
        sample_names = [info["name"] for info in unmentioned[:5]]
        return [{
            "rule_id": rule.get("id", "TRC-001"),
            "source": "TRC",
            "file": None,
            "line": None,
            "message": (
                f"설계서–코드 인터페이스 불일치: 헤더 함수 {total_header}개 중 "
                f"{uncovered_count}개가 설계서에 명세되지 않음 "
                f"(예: {', '.join(sample_names)} 등)"
            ),
            "severity": severity,
            "confidence": "후보",
            "needs_ai_review": True,
            "pattern_type": "trc",
            "trc_type": "interface_match",
            "uncovered_funcs": [info["name"] for info in unmentioned[:20]],
        }]

    # 캡 이하 → 개별 위반 반환
    violations = []
    for info in unmentioned:
        violations.append({
            "rule_id": rule.get("id", "TRC-001"),
            "source": "TRC",
            "file": info["file"],
            "line": info["line"],
            "message": (
                f"헤더 함수 '{info['name']}'이 설계서에 명세되지 않음 "
                f"(설계서–코드 인터페이스 추적 불가)"
            ),
            "severity": severity,
            "confidence": "후보",
            "needs_ai_review": True,
            "pattern_type": "trc",
            "trc_type": "interface_match",
            "func_name": info["name"],
            "signature": info.get("signature", ""),
        })
    return violations


def _check_trc002(
    design_sections: List[Dict[str, Any]],
    code_index: Dict[str, Any],
    rule: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    TRC-002: 에러 코드 일치성.

    설계서에 정의된 에러 코드 상수가 코드에도 정의되어 있는지 확인.
    위반이 _MAX_TRC002_VIOLATIONS 건 초과 시 요약 위반 1건으로 대체.
    """
    design_codes = _extract_error_codes_from_sections(design_sections)
    if not design_codes or not design_sections:
        return []

    code_error_codes = code_index.get("error_codes", {})
    missing_codes = [c for c in design_codes if c not in code_error_codes]
    if not missing_codes:
        return []

    severity = rule.get("severity", "medium")

    # 위반 수가 캡 초과 → 요약 위반 1건으로 대체
    if len(missing_codes) > _MAX_TRC002_VIOLATIONS:
        sample = missing_codes[:5]
        return [{
            "rule_id": rule.get("id", "TRC-002"),
            "source": "TRC",
            "file": None,
            "line": None,
            "message": (
                f"설계서–코드 에러 코드 불일치: 설계서의 에러 코드 {len(missing_codes)}개가 "
                f"코드에 정의되지 않음 (예: {', '.join(sample)} 등)"
            ),
            "severity": severity,
            "confidence": "후보",
            "needs_ai_review": True,
            "pattern_type": "trc",
            "trc_type": "error_code_match",
            "missing_codes": missing_codes[:20],
        }]

    violations = []
    for code_name in missing_codes:
        violations.append({
            "rule_id": rule.get("id", "TRC-002"),
            "source": "TRC",
            "file": None,
            "line": None,
            "message": (
                f"설계서의 에러 코드 '{code_name}'이 코드에 정의되지 않음 "
                f"(설계서–코드 에러 코드 불일치)"
            ),
            "severity": severity,
            "confidence": "후보",
            "needs_ai_review": True,
            "pattern_type": "trc",
            "trc_type": "error_code_match",
            "error_code": code_name,
        })
    return violations


def _check_trc003(
    code_index: Dict[str, Any],
    test_sections: List[Dict[str, Any]],
    rule: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    TRC-003: 공개 함수 시험 커버리지.

    헤더 파일의 공개 함수가 시험서에서 테스트 항목으로 언급되어 있는지 확인.
    임계값(_MIN_COVERAGE_RATIO) 미만 시 위반.
    """
    header_funcs = code_index.get("header_funcs", {})
    if not header_funcs or not test_sections:
        return []

    # 시험서에서 언급된 함수명 집합
    mentioned = _extract_func_names_from_sections(test_sections)

    uncovered = []
    for key, info in header_funcs.items():
        name = info["name"]
        # TRC-001과 동일한 필터 기준 적용
        if name.startswith("_") or len(name) < 5:
            continue
        if name.lower() in _GENERIC_FUNC_NAMES and "_" not in name:
            continue
        # 테스트·벤치마크 함수 제외
        if key.endswith(_TEST_FUNC_SUFFIXES):
            continue
        if not _is_func_mentioned(name, key, mentioned):
            uncovered.append(info)

    # 필터링 기준이 동일하므로, uncovered + covered = 실제 검사 대상 수
    eligible = sum(
        1 for key, info in header_funcs.items()
        if not info["name"].startswith("_") and len(info["name"]) >= 5
        and not (info["name"].lower() in _GENERIC_FUNC_NAMES and "_" not in info["name"])
        and not key.endswith(_TEST_FUNC_SUFFIXES)
    )
    total = eligible if eligible > 0 else len(header_funcs)
    covered = total - len(uncovered)
    coverage_ratio = covered / total if total > 0 else 1.0

    severity = rule.get("severity", "medium")
    violations = []

    if coverage_ratio < _MIN_COVERAGE_RATIO:
        # 전체 커버리지 부족 → 단일 summary 위반
        violations.append({
            "rule_id": rule.get("id", "TRC-003"),
            "source": "TRC",
            "file": None,
            "line": None,
            "message": (
                f"시험 커버리지 부족: 헤더 함수 {total}개 중 {covered}개만 시험서에 언급됨 "
                f"({coverage_ratio:.0%}, 기준 {_MIN_COVERAGE_RATIO:.0%})"
            ),
            "severity": severity,
            "confidence": "후보",
            "needs_ai_review": True,
            "pattern_type": "trc",
            "trc_type": "test_coverage",
            "coverage_ratio": round(coverage_ratio, 2),
            "uncovered_funcs": [info["name"] for info in uncovered[:10]],
        })
    else:
        # 커버리지는 충분하나 누락된 개별 함수 보고 (최대 5건)
        for info in uncovered[:5]:
            violations.append({
                "rule_id": rule.get("id", "TRC-003"),
                "source": "TRC",
                "file": info["file"],
                "line": info["line"],
                "message": (
                    f"함수 '{info['name']}'이 시험서에 언급되지 않음 "
                    f"(시험 커버리지 누락)"
                ),
                "severity": "low",
                "confidence": "후보",
                "needs_ai_review": True,
                "pattern_type": "trc",
                "trc_type": "test_coverage",
                "func_name": info["name"],
            })

    return violations


# ─────────────────────────────────────────────────────────────────
# 메인 진입점
# ─────────────────────────────────────────────────────────────────



# ─────────────────────────────────────────────────────────────────
# TRC-004: symbol_graph 기반 API 시그니처 매핑
# ─────────────────────────────────────────────────────────────────

def _check_trc004(
    design_sections: List[Dict[str, Any]],
    symbol_graph: Dict[str, Any],
    rule: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    TRC-004: symbol_graph 함수 포인터 typedef vs 설계서 API 명세 자동 매핑.

    symbol_graph["type_aliases"]에서 *_ptr 형식의 함수 포인터 typedef를 추출해
    설계서 API 테이블과 대조한다.

    위반 조건:
    - 코드에 함수 포인터 typedef가 있지만 설계서에 해당 함수 언급이 없음
    - 설계서 API 테이블에 기재된 함수명이 symbol_graph["definitions"]에 없음
    """
    if not symbol_graph or not design_sections:
        return []

    type_aliases: Dict[str, Any] = symbol_graph.get("type_aliases") or {}
    definitions: Dict[str, Any] = symbol_graph.get("definitions") or {}
    severity = rule.get("severity", "medium")

    # 1. 함수 포인터 typedef 추출 (*_ptr 이름, (*) 포함)
    api_funcs: Dict[str, str] = {}  # func_name → full signature
    for alias_name, alias_type in type_aliases.items():
        if not alias_name.endswith("_ptr"):
            continue
        if "(*)" not in alias_type:
            continue
        func_name = alias_name[:-4]  # lea_cbc_enc_ptr → lea_cbc_enc
        api_funcs[func_name] = alias_type

    if not api_funcs:
        return []

    # 2. 설계서에서 언급된 함수명 추출
    mentioned = _extract_func_names_from_sections(design_sections)

    # 3. 코드 API 중 설계서에 미언급된 항목 탐지
    violations: List[Dict[str, Any]] = []
    unmentioned_apis: List[Dict[str, Any]] = []

    for func_name, sig in api_funcs.items():
        key = func_name.lower()
        if _is_func_mentioned(func_name, key, mentioned):
            continue
        # 파일 정보 조회
        file_info = None
        for fname, entries in definitions.items():
            if fname.lower() == key:
                if isinstance(entries, list):
                    file_info = entries[0]
                else:
                    file_info = entries
                break
        unmentioned_apis.append({
            "func_name": func_name,
            "signature": sig[:100],
            "file": (file_info.get("file") or "") if file_info else "",
            "line": (file_info.get("line")) if file_info else None,
        })

    # 4. 설계서 API 테이블에서 추출한 함수 중 코드에 없는 항목 탐지
    defined_lower = {k.lower() for k in definitions.keys()}
    api_funcs_lower = {k.lower() for k in api_funcs.keys()}

    doc_funcs_not_in_code: List[str] = []
    for sec in design_sections:
        for table in sec.get("tables") or []:
            if not isinstance(table, dict):
                continue
            for row in table.get("rows") or []:
                if not isinstance(row, list):
                    continue
                for cell in row:
                    cell_str = str(cell)
                    for m in _FUNC_MENTION_RE.finditer(cell_str):
                        fname = m.group(1).lower()
                        # 암호화 관련 함수 패턴만 (lea_, aria_ 등)
                        if re.match(r"(lea|aria|cbc|ctr|gcm|cfb|ofb|cmac|ccm)_", fname):
                            if fname not in defined_lower and fname not in api_funcs_lower:
                                if fname not in doc_funcs_not_in_code:
                                    doc_funcs_not_in_code.append(fname)

    # 5. 위반 생성
    if unmentioned_apis:
        if len(unmentioned_apis) > 8:
            sample = [a["func_name"] for a in unmentioned_apis[:5]]
            violations.append({
                "rule_id": rule.get("id", "TRC-004"),
                "source": "TRC",
                "file": None,
                "line": None,
                "message": (
                    f"코드 공개 API {len(api_funcs)}개 중 {len(unmentioned_apis)}개가 "
                    f"설계서에 명세되지 않음 (예: {', '.join(sample)} 등) — "
                    f"API 시그니처 누락 의심"
                ),
                "severity": severity,
                "confidence": "후보",
                "needs_ai_review": True,
                "pattern_type": "trc",
                "trc_type": "api_mapping",
                "unmatched_apis": [a["func_name"] for a in unmentioned_apis[:20]],
            })
        else:
            for api in unmentioned_apis:
                violations.append({
                    "rule_id": rule.get("id", "TRC-004"),
                    "source": "TRC",
                    "file": api["file"] or None,
                    "line": api["line"],
                    "message": (
                        f"공개 API '{api['func_name']}' 시그니처가 설계서에 명세되지 않음: "
                        f"{api['signature'][:80]}"
                    ),
                    "severity": severity,
                    "confidence": "후보",
                    "needs_ai_review": True,
                    "pattern_type": "trc",
                    "trc_type": "api_mapping",
                    "func_name": api["func_name"],
                    "signature": api["signature"],
                })

    if doc_funcs_not_in_code:
        violations.append({
            "rule_id": rule.get("id", "TRC-004"),
            "source": "TRC",
            "file": None,
            "line": None,
            "message": (
                f"설계서 API 테이블에 기재된 함수가 코드에서 미발견: "
                f"{', '.join(doc_funcs_not_in_code[:8])}"
            ),
            "severity": severity,
            "confidence": "후보",
            "needs_ai_review": True,
            "pattern_type": "trc",
            "trc_type": "api_mapping",
            "missing_in_code": doc_funcs_not_in_code,
        })

    return violations

def run_traceability_checks(
    design_doc: Dict[str, Any],
    code_index: Dict[str, Any],
    test_doc: Dict[str, Any],
    rules: List[Dict[str, Any]],
    symbol_graph: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """
    설계서–코드–시험서 간 추적성 검사.

    Parameters
    ----------
    design_doc  : {"sections": [...]}  doc_type=="design" 섹션
    code_index  : build_code_index(preprocess_result) 반환값
    test_doc    : {"sections": [...]}  doc_type=="test" 섹션
    rules       : TRC YAML에서 로드한 룰 리스트
    symbol_graph: (선택) build_symbol_graph 출력 — TRC-004 API 매핑에 활용

    Returns
    -------
    violations : TRC 위반 리스트
    """
    design_sections = design_doc.get("sections", [])
    test_sections = test_doc.get("sections", [])

    # 문서가 전혀 없으면 TRC 검사 불가
    if not design_sections and not test_sections:
        return []

    # rule_id → 룰 매핑
    rule_map: Dict[str, Dict[str, Any]] = {}
    for r in rules:
        rid = r.get("id") or ""
        if rid:
            rule_map[rid] = r

    violations: List[Dict[str, Any]] = []

    for rule in rules:
        rid = rule.get("id") or ""
        rtype = rule.get("type") or ""

        try:
            if rtype == "interface_match" or rid == "TRC-001":
                if design_sections:
                    violations.extend(_check_trc001(design_sections, code_index, rule))

            elif rtype == "error_code_match" or rid == "TRC-002":
                if design_sections:
                    violations.extend(_check_trc002(design_sections, code_index, rule))

            elif rtype == "test_coverage" or rid == "TRC-003":
                violations.extend(_check_trc003(code_index, test_sections, rule))

            elif rtype == "api_mapping" or rid == "TRC-004":
                if design_sections and symbol_graph:
                    violations.extend(_check_trc004(design_sections, symbol_graph, rule))

        except Exception as e:
            print(f"[TRC] {rid} 검사 중 오류: {e}")

    print(f"[TRC] 추적성 검사 완료: {len(violations)}건")
    return violations
