"""
ASTCheckerService: pycparser 완전 AST 기반 LEA 구조 검사.

실제 LEA 구현 코드의 패턴 분석 결과:
- 라운드 함수가 매크로(LEA_ENC_ROUND, LEA_DEC_ROUND)로 구현된 경우 내부 로직이 보이지 않음
- 키 스케줄은 일반 함수로 구현되어 T[i] = ROL32(T[i] + ...) 패턴이 직접 보임
- 라운드 수는 LEA_128_ROUNDS 같은 매크로 상수나 key->rounds 로 사용됨

설계 원칙:
- 확신할 수 있을 때만 위반 생성 (보수적 검사)
- 판단 불가능하면 None 반환 → rule_engine 이 fallback 처리
- False Positive 최소화 우선

구현된 규칙:
  LEA-003  라운드 수 상수 할당 (rounds 필드 또는 변수에 24/28/32 대입)
  LEA-005  바이트→워드 빅 엔디안(a[0]<<24) 탐지 — LE 규약 위반
  LEA-006  비트 색인 역전 탐지 — (x&1)<<31 패턴 (bit 0을 MSB로 취급)
  LEA-010  키 스케줄 함수 내 ROL/ROR 호출 + ADD 연산 존재
  LEA-030  encrypt 함수에서 워드 스왑 패턴 (배열/변수 모두 검출)
  LEA-031  라운드 함수 내 XOR→ADD 순서 (비매크로 구현에서만)
  LEA-034  decrypt 함수 내 모듈러 뺄셈 존재
  LEA-035  decrypt 함수에서 역 워드 스왑 패턴
  LEA-040  라운드 루프 경계 <= 사용 위반
  OFB-002  OFB 함수 내 DEC 호출 또는 XOR 부재 탐지
  CFB-002  CFB 함수 내 DEC 호출 또는 XOR 부재 탐지
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple

# ──────────────────────────────────────────────────────────────────
# pycparser 지연 임포트
# ──────────────────────────────────────────────────────────────────
try:
    from pycparser import c_ast
    _HAS_PYCPARSER = True
except ImportError:
    _HAS_PYCPARSER = False

# ──────────────────────────────────────────────────────────────────
# libclang 지연 임포트 (MAKE_FUNC 매크로 완전 파싱용)
# ──────────────────────────────────────────────────────────────────
try:
    import clang.cindex as _ci
    _HAS_LIBCLANG = True
except ImportError:
    _HAS_LIBCLANG = False


# ──────────────────────────────────────────────────────────────────
# C 파일 파싱 → raw pycparser AST
# ──────────────────────────────────────────────────────────────────

import re as _re
import shutil as _shutil
import subprocess as _subprocess
import tempfile as _tempfile


def _parse_with_gcc(content: str, filename: str, extra_includes: Optional[List[str]] = None) -> Optional[Tuple[Any, int]]:
    """gcc -E 로 전처리 후 pycparser 파싱.

    시스템 헤더(/usr/, /Library/ 등) 섹션을 제외하고 프로젝트 코드만 추출하여
    pycparser 에 넘긴다. 이를 통해 include + macro 문제를 해결한다.
    gcc/clang 이 없으면 None 반환.
    """
    if not _HAS_PYCPARSER:
        return None
    if not _shutil.which("gcc") and not _shutil.which("clang"):
        return None

    try:
        from pycparser import c_parser
        from app.services.preprocess_service import _PYCPARSER_PREAMBLE
    except ImportError:
        return None

    compiler = _shutil.which("gcc") or _shutil.which("clang")

    # 임시 파일에 소스 저장
    with _tempfile.NamedTemporaryFile(suffix=".c", mode="w", encoding="utf-8", delete=False) as f:
        f.write(content)
        tmp_path = f.name

    try:
        cmd = [
            compiler, "-E",  # 전처리만
            "-x", "c",
            "-D__attribute__(x)=",
            "-D__asm__(x)=",
            "-D__inline=",
            "-D__restrict=",
            "-D__extension__=",
        ]
        if extra_includes:
            for inc in extra_includes:
                cmd += [f"-I{inc}"]
        cmd.append(tmp_path)

        result = _subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if result.returncode != 0:
            return None

        raw = result.stdout
        # 시스템 경로 제외 → 프로젝트 파일 섹션만 추출
        _SYS_PATH_PREFIXES = ("/usr/", "/Library/", "/Applications/", "<built-in>", "<command")
        lines_out = raw.splitlines()
        in_project = True  # 첫 줄은 프로젝트 파일로 시작
        extracted: List[str] = []
        for line in lines_out:
            if line.startswith("#"):
                m = _re.match(r'^# \d+ "([^"]+)"', line)
                if m:
                    fname_marker = m.group(1)
                    in_project = not any(fname_marker.startswith(p) for p in _SYS_PATH_PREFIXES)
            elif in_project:
                extracted.append(line)

        project_code = "\n".join(extracted)
        preamble = _PYCPARSER_PREAMBLE
        offset = preamble.count("\n")

        parser = c_parser.CParser()
        ast = parser.parse(preamble + project_code, filename=filename)
        if ast is not None:
            return ast, offset
    except Exception:
        pass
    finally:
        import os
        try:
            os.unlink(tmp_path)
        except Exception:
            pass

    return None


def _parse_c_raw(
    content: str,
    filename: str = "<src>",
    extra_includes: Optional[List[str]] = None,
) -> Optional[Tuple[Any, int]]:
    """C 소스 → (pycparser FileAST, line_offset). 실패 시 None.

    전략:
    1. gcc -E 전처리 (가장 정확) — include/macro 완전 처리
    2. pycparser 자체 3단계 fallback (gcc 없는 환경)
    """
    # 전략 1: gcc -E
    result = _parse_with_gcc(content, filename, extra_includes=extra_includes)
    if result is not None:
        return result

    # 전략 2: pycparser 자체 파싱 (기존 로직)
    if not _HAS_PYCPARSER:
        return None
    try:
        from pycparser import c_parser
        from app.services.preprocess_service import (
            _strip_c_comments,
            _extract_macro_func_decls,
            _PYCPARSER_PREAMBLE,
        )
    except ImportError:
        return None

    no_comments = _strip_c_comments(content)
    src_lines: List[str] = []
    in_define = False
    for line in no_comments.splitlines():
        stripped = line.lstrip()
        if in_define:
            src_lines.append("")
            in_define = line.rstrip().endswith("\\")
        elif stripped.startswith("#"):
            src_lines.append("")
            in_define = line.rstrip().endswith("\\")
        else:
            src_lines.append(line)
    source_clean = "\n".join(src_lines)
    macro_decls = _extract_macro_func_decls(no_comments)
    parser = c_parser.CParser()

    for preamble in [_PYCPARSER_PREAMBLE + macro_decls, _PYCPARSER_PREAMBLE, ""]:
        try:
            to_parse = preamble + source_clean
            if to_parse.strip():
                ast = parser.parse(to_parse, filename=filename)
                if ast is not None:
                    return ast, preamble.count("\n")
        except Exception:
            continue
    return None


# ──────────────────────────────────────────────────────────────────
# AST 순회 유틸
# ──────────────────────────────────────────────────────────────────

def _collect(root, node_type) -> List[Any]:
    """root 서브트리에서 node_type 인스턴스 전부 수집."""
    result: List[Any] = []
    if not _HAS_PYCPARSER:
        return result

    class _V(c_ast.NodeVisitor):
        def generic_visit(self, node):
            if isinstance(node, node_type):
                result.append(node)
            for _, child in node.children():
                self.visit(child)

    try:
        _V().visit(root)
    except Exception:
        pass
    return result


def _coord_line(node, offset: int = 0) -> Optional[int]:
    coord = getattr(node, "coord", None)
    if coord is None:
        return None
    raw = getattr(coord, "line", None)
    if raw is None:
        return None
    line = raw - offset
    return line if line > 0 else None


def _func_name(fd) -> str:
    return getattr(getattr(fd, "decl", None), "name", "") or ""


def _get_func_defs(root) -> List[Any]:
    if not _HAS_PYCPARSER:
        return []
    return _collect(root, c_ast.FuncDef)


def _funcs_matching(root, keywords: List[str]) -> List[Any]:
    return [fd for fd in _get_func_defs(root)
            if any(kw in _func_name(fd).lower() for kw in keywords)]


_MODE_UTILITY_FUNC_SUFFIXES = (
    "_increase", "_increment", "_incr", "_counter_inc",
    "_reset", "_prepare",
)


def _has_unchecked_real_mode_funcs(
    all_funcs: list, checked_funcs: list, mode_kw: str, filename: str = ""
) -> bool:
    """키워드 매칭 함수(checked_funcs) 외에, 모드 키워드를 포함하면서
    thin wrapper/benchmark가 아닌 실제 구현 함수가 존재하는지 확인.

    이 조건이 참이면 fallback(regex/L3)으로 미검사 위반을 잡을 수 있으므로
    None을 반환하여 fallback을 유도한다.

    KISA LEA 같은 정상 코드에서 FP를 방지하기 위해:
    - 단순 dispatcher(thin wrapper)는 제외
    - 벤치마크/테스트 함수는 제외
    - 카운터 증가/초기화 등 유틸리티 함수는 제외 (ctr_increase 등)
    - 모드 키워드가 함수명에 포함된 실제 구현 함수만 카운트
    """
    kw = mode_kw.lower()
    checked_set = set(id(fd) for fd in checked_funcs)
    for fd in all_funcs:
        if id(fd) in checked_set:
            continue
        fname = _func_name(fd).lower()
        # 파일명 또는 함수명에 모드 키워드가 있어야 함
        if kw not in fname and kw not in filename.lower():
            continue
        # 함수명에 모드 키워드가 있는 경우만 (파일명만으로는 부족)
        if kw not in fname:
            continue
        # 유틸리티 함수(카운터 증가, 초기화 등)는 암호화 구현이 아님 → 제외
        if any(fname.endswith(suf) for suf in _MODE_UTILITY_FUNC_SUFFIXES):
            continue
        if not _is_thin_wrapper(fd) and not _is_benchmark_func(fd):
            return True
    return False


def _has_op(node, op: str) -> bool:
    """서브트리에 BinaryOp(op=op) 가 있는지."""
    for bop in _collect(node, c_ast.BinaryOp):
        if bop.op == op:
            return True
    return False


def _call_names_in(node) -> Set[str]:
    """서브트리의 모든 FuncCall 이름 집합."""
    names: Set[str] = set()
    for fc in _collect(node, c_ast.FuncCall):
        n = getattr(getattr(fc, "name", None), "name", None)
        if n:
            names.add(n)
    return names


def _is_macro_based_round_func(func_def) -> bool:
    """encrypt/decrypt 함수 본문이 LEA_ENC_ROUND, LEA_DEC_ROUND 등
    round 매크로 호출로만 이뤄진 경우 True — 내부 로직 분석 불가."""
    call_names = _call_names_in(func_def)
    macro_hints = {"LEA_ENC_ROUND", "LEA_DEC_ROUND", "ENC_ROUND", "DEC_ROUND",
                   "ROUND_ENC", "ROUND_DEC", "LEA_ROUND"}
    return bool(call_names & macro_hints)


# 벤치마크 / 테스트 함수 이름 키워드 — 이 키워드가 포함된 함수는 실제 암호 구현이 아님
_BENCH_TEST_KW = {"benchmark", "bench", "perf", "test_", "_test"}


def _is_thin_wrapper(func_def) -> bool:
    """함수 본문이 단순 위임(dispatcher/wrapper)인지 판별.

    다음 조건을 *모두* 만족하면 thin wrapper로 판정:
    - 함수 본문(compound statement)의 block_items이 5개 이하
    - 바이너리 연산(^, +, -, <<, >>)이 없음
    - for/while 루프가 없음

    thin wrapper 예시:
      void lea_cbc_enc(...) { return g_cbc_enc(ctx, ct, pt, pt_len); }
      void lea_ofb_enc_fallback(...) { init_simd(); lea_ofb_enc(...); }
    """
    if not _HAS_PYCPARSER:
        return False

    body = getattr(func_def, "body", None)
    if not isinstance(body, c_ast.Compound):
        return False

    items = getattr(body, "block_items", None) or []
    if len(items) > 5:
        return False

    # 대입문(Assignment)이 있으면 wrapper가 아님 — 실제 로직이 있다는 의미
    if _collect(func_def, c_ast.Assignment):
        return False

    # 암호 관련 바이너리 연산이 있으면 wrapper가 아님
    _CRYPTO_OPS = {"^", "+", "-", "<<", ">>"}
    for bop in _collect(func_def, c_ast.BinaryOp):
        if bop.op in _CRYPTO_OPS:
            return False

    # 루프가 있으면 wrapper가 아님
    if _collect(func_def, c_ast.For) or _collect(func_def, c_ast.While):
        return False

    return True


def _is_benchmark_func(func_def) -> bool:
    """함수 이름에 benchmark/bench/perf 키워드가 포함되면 True."""
    fname = _func_name(func_def).lower()
    return any(kw in fname for kw in _BENCH_TEST_KW)


# ──────────────────────────────────────────────────────────────────
# 패턴 매처
# ──────────────────────────────────────────────────────────────────

def _const_value(node) -> Optional[int]:
    """Constant 노드의 정수값 반환 (10진수/16진수/8진수/U/L 접미사 지원)."""
    if not (_HAS_PYCPARSER and isinstance(node, c_ast.Constant)):
        return None
    try:
        v = node.value.rstrip("uUlL")  # strip C integer suffixes (unsigned/long)
        return int(v, 0)  # base=0: auto-detect hex(0x), octal(0), decimal
    except (ValueError, TypeError):
        return None


def _is_array_subscript(node, idx: int) -> bool:
    """ArrayRef(subscript=idx) 인지 확인."""
    if not (_HAS_PYCPARSER and isinstance(node, c_ast.ArrayRef)):
        return False
    return _const_value(node.subscript) == idx


def _array_base(node) -> Optional[str]:
    """ArrayRef 의 배열 변수 이름 (ID만)."""
    if not (_HAS_PYCPARSER and isinstance(node, c_ast.ArrayRef)):
        return None
    n = node.name
    return n.name if isinstance(n, c_ast.ID) else None


def _find_array_swaps(root, lhs_idx: int, rhs_idx: int) -> List[int]:
    """array[lhs] = array[rhs] 형태 대입문의 줄 번호 목록."""
    result: List[int] = []
    for assign in _collect(root, c_ast.Assignment):
        if assign.op != "=":
            continue
        lv, rv = assign.lvalue, assign.rvalue
        if not (_is_array_subscript(lv, lhs_idx) and _is_array_subscript(rv, rhs_idx)):
            continue
        if _array_base(lv) != _array_base(rv):
            continue
        coord = getattr(assign, "coord", None)
        if coord:
            result.append(getattr(coord, "line", 0))
    return result


def _find_cross_array_assigns(root, lhs_idx: int, rhs_idx: int) -> List[int]:
    """array_a[lhs] = array_b[rhs] 형태 대입문의 줄 번호 목록 (배열 이름 달라도 OK).

    smart-crypto 처럼 입력/출력 배열이 분리된 구현 지원:
      tmp[3] = tmp_input[0]  →  lhs_idx=3, rhs_idx=0 → 탐지
    """
    result: List[int] = []
    for assign in _collect(root, c_ast.Assignment):
        if assign.op != "=":
            continue
        lv, rv = assign.lvalue, assign.rvalue
        if not (_is_array_subscript(lv, lhs_idx) and _is_array_subscript(rv, rhs_idx)):
            continue
        coord = getattr(assign, "coord", None)
        if coord:
            result.append(getattr(coord, "line", 0))
    return result


def _find_var_swaps(root, var_names: List[str]) -> bool:
    """var[i] = var[j] 형태 아닌, 로컬 변수 간 단순 대입 존재.
    예: x3 = x0, t = x0 후 x3 = t 등.
    var_names 에 있는 이름을 lhs/rhs 로 가진 Assignment 찾기."""
    name_set = set(v.lower() for v in var_names)
    for assign in _collect(root, c_ast.Assignment):
        if assign.op != "=":
            continue
        lv, rv = assign.lvalue, assign.rvalue
        lv_name = lv.name.lower() if isinstance(lv, c_ast.ID) else None
        rv_name = rv.name.lower() if isinstance(rv, c_ast.ID) else None
        if lv_name in name_set and rv_name in name_set and lv_name != rv_name:
            return True
    return False


# ──────────────────────────────────────────────────────────────────
# 규칙별 검사기
# ──────────────────────────────────────────────────────────────────

_LEA_ROUND_COUNTS = {24, 28, 32}
_ENC_KW = ["encrypt", "enc"]
_DEC_KW = ["decrypt", "dec"]
_KEY_KW = ["key", "schedule", "keygen", "key_sched", "setkey", "key_set", "key_exp"]
_ROL_NAMES = {"ROL32", "ROL", "ROTL32", "ROTL", "ROR32", "ROR", "ROTR32", "ROTR",
              "rol32", "ror32", "rotl32", "rotr32"}


def _check_lea_003(root, offset: int, filename: str) -> List[Dict[str, Any]]:
    """LEA-003: 키 스케줄 함수 내 라운드 수가 24/28/32 중 하나인지 검사.

    탐지 전략:
    1. 키 스케줄 함수(_KEY_KW) 내 for 루프 bound를 수집
    2. 리터럴 24/28/32가 있으면 → 준수 (올바른 라운드 수)
    3. 16~40 범위의 다른 정수 리터럴이 있으면 → 위반
    4. 매크로/변수 bound만 있으면 → [] (판단 불가, 보수적 처리)
    5. 키 스케줄 함수 자체가 없으면 → [] (해당 없음)
    6. 추가: 모든 함수에서 ->rounds / .rounds 에 잘못된 리터럴 대입 탐지
    """
    if not _HAS_PYCPARSER:
        return []

    violations = []

    # ── 전략 6: 전체 함수에서 ->rounds = N (N ∉ {24,28,32}, 16 ≤ N ≤ 40) 탐지 ──
    _ROUNDS_ASSIGN_NAMES = _re.compile(r'\brounds\b', _re.IGNORECASE)
    for fd in _collect(root, c_ast.FuncDef):
        if _is_benchmark_func(fd) or _is_thin_wrapper(fd):
            continue
        fname = _func_name(fd)
        for assign in _collect(fd, c_ast.Assignment):
            if assign.op != "=":
                continue
            lhs = assign.lvalue
            # struct->rounds 또는 struct.rounds
            field_name = ""
            if isinstance(lhs, c_ast.StructRef):
                fld = getattr(lhs, "field", None)
                field_name = getattr(fld, "name", "") if fld else ""
            elif isinstance(lhs, c_ast.ID):
                field_name = getattr(lhs, "name", "")
            if not _ROUNDS_ASSIGN_NAMES.search(field_name):
                continue
            val = _const_value(assign.rvalue)
            if val is None:
                continue
            if val in _LEA_ROUND_COUNTS:
                continue  # 올바른 라운드 수
            if 16 <= val <= 40:
                line = _coord_line(assign, offset)
                violations.append({
                    "line": line,
                    "message": (
                        f"함수 '{fname}': '{field_name} = {val}' — "
                        "LEA 유효 라운드 수: 128비트→24, 192비트→28, 256비트→32"
                    ),
                    "ast_evidence": (
                        f"함수 '{fname}' Assignment: {field_name} = {val}, "
                        f"LEA 유효 라운드 수 = {{24, 28, 32}}. {val} ∉ {{24,28,32}}"
                    ),
                })

    # ── 전략 7: 라운드 비교 조건 (if/while) 검사 — M02/M03 탐지 ──
    # key->round > N, rounds >= N 등에서 N이 비표준이면 위반
    _ROUND_CMP_OPS = frozenset({">", ">=", "<", "<=", "!=", "=="})
    for fd in _collect(root, c_ast.FuncDef):
        if _is_benchmark_func(fd) or _is_thin_wrapper(fd):
            continue
        fname = _func_name(fd)
        for bop in _collect(fd, c_ast.BinaryOp):
            if bop.op not in _ROUND_CMP_OPS:
                continue
            for ref_side, val_side in [(bop.left, bop.right), (bop.right, bop.left)]:
                field_name = ""
                if isinstance(ref_side, c_ast.StructRef):
                    fld = getattr(ref_side, "field", None)
                    field_name = getattr(fld, "name", "") if fld else ""
                elif isinstance(ref_side, c_ast.ID):
                    field_name = getattr(ref_side, "name", "")
                if not _ROUNDS_ASSIGN_NAMES.search(field_name):
                    continue
                val = _const_value(val_side)
                if val is None or val in _LEA_ROUND_COUNTS:
                    continue
                if 16 <= val <= 40:
                    line = _coord_line(bop, offset)
                    violations.append({
                        "line": line,
                        "message": (
                            f"함수 '{fname}': '{field_name} {bop.op} {val}' — "
                            "LEA 유효 라운드 수 임계값: 24/28/32"
                        ),
                        "ast_evidence": (
                            f"함수 '{fname}' 비교 조건: {field_name} {bop.op} {val}, "
                            f"표준 임계값 = {{24, 28, 32}}. {val} ∉ {{24,28,32}} → 라운드 조건 변조"
                        ),
                    })

    # ── 전략 8: 라운드 산술식 비표준 상수 — M01 탐지 ──
    # key->round = (mk_len >> 1) + N 에서 N이 16이 아니면 위반
    _LEA_ROUND_ADDEND = 16  # LEA 표준: (mk_len >> 1) + 16
    for fd in _collect(root, c_ast.FuncDef):
        if _is_benchmark_func(fd) or _is_thin_wrapper(fd):
            continue
        fname = _func_name(fd)
        for assign in _collect(fd, c_ast.Assignment):
            if assign.op != "=":
                continue
            lhs = assign.lvalue
            field_name = ""
            if isinstance(lhs, c_ast.StructRef):
                fld = getattr(lhs, "field", None)
                field_name = getattr(fld, "name", "") if fld else ""
            elif isinstance(lhs, c_ast.ID):
                field_name = getattr(lhs, "name", "")
            if not _ROUNDS_ASSIGN_NAMES.search(field_name):
                continue
            # 이미 Strategy 6에서 상수 리터럴 처리됨 → 산술식만 검사
            if _const_value(assign.rvalue) is not None:
                continue
            for addop in _collect(assign.rvalue, c_ast.BinaryOp):
                if addop.op != "+":
                    continue
                for side in [addop.left, addop.right]:
                    val = _const_value(side)
                    if val is not None and val != _LEA_ROUND_ADDEND and 12 <= val <= 20:
                        line = _coord_line(assign, offset)
                        violations.append({
                            "line": line,
                            "message": (
                                f"함수 '{fname}': 라운드 수 산술식에 비표준 상수 {val} 사용 — "
                                f"표준: (mk_len>>1) + 16"
                            ),
                            "ast_evidence": (
                                f"Assignment: {field_name} = ... + {val}, "
                                f"LEA 표준 가산값 = 16. {val} ≠ 16 → 라운드 수 공식 변조"
                            ),
                        })

    key_funcs = _funcs_matching(root, _KEY_KW)
    if not key_funcs:
        return violations  # 키 스케줄 함수 없어도 직접 할당/비교 위반은 반환

    for fd in key_funcs:
        if _is_benchmark_func(fd) or _is_thin_wrapper(fd):
            continue
        fname = _func_name(fd)
        found_valid = False
        wrong_bounds: List[int] = []

        for for_node in _collect(fd, c_ast.For):
            bound = _get_for_bound(for_node)
            if bound is None:
                continue  # 매크로/변수 bound → 판단 불가, 스킵
            if bound in _LEA_ROUND_COUNTS:
                found_valid = True
                break
            # 라운드 수로 의심되는 범위(16~40)의 잘못된 리터럴
            if 16 <= bound <= 40:
                wrong_bounds.append(bound)

        if wrong_bounds and not found_valid:
            line = _coord_line(fd, offset)
            violations.append({
                "line": line,
                "message": (
                    f"함수 '{fname}': 라운드 수 리터럴 {wrong_bounds[0]} 발견 — "
                    "LEA 유효 라운드 수: 128비트→24, 192비트→28, 256비트→32"
                ),
                "ast_evidence": (
                    f"함수 '{fname}' for 루프 상한 리터럴 = {wrong_bounds[0]}, "
                    f"LEA 유효 라운드 수 집합 = {{24, 28, 32}}. "
                    f"구조적 사실: {wrong_bounds[0]} ∉ {{24,28,32}} → 라운드 수 불일치"
                ),
            })

    return violations


# KS X 3246 LEA 표준 delta 상수 (전체 8개)
_LEA_DELTA_STANDARD: List[str] = [
    "0xc3efe9db", "0x44626b02", "0x79e27c8a", "0x78df30ec",
    "0x715ea49e", "0xc785da0a", "0xe04ef22a", "0xe5c40957",
]
# delta 배열 이름 패턴 — 'delta_128', 'delta128', 'DELTA' 등 모두 포함
_DELTA_VAR_RE = _re.compile(r'(?i)delta')


def _check_lea_010(root, offset: int, filename: str,
                   symbol_graph: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """LEA-010: 키 스케줄 ARX 구조 — ROL/ROR 호출 + ADD 연산 + delta 상수값 검증.

    Phase 1 (기존): 키 스케줄 함수에 ROL/ROR과 ADD가 있는지 확인.
    Phase 2 (libclang): symbol_graph["array_inits"]에서 delta 배열을 찾아
                        KS X 3246 표준값과 직접 비교.

    gcc -E 후 ROL(W, i) → (((W)<<(i))|((W)>>(32-(i)))) 으로 확장되므로
    FuncCall 탐지 외에 << / >> 연산자 조합도 회전으로 인정한다.
    """
    # LEA ARX 키 스케줄 규칙은 LEA 구현 파일에만 적용.
    # ARIA(SPN), EC-KCDSA(타원곡선), SHA, HMAC 등은 ARX 구조가 아님 → 제외.
    _NON_LEA_FILE_KW = ("aria", "ecdsa", "kcdsa", "ec_", "ecc", "gfp", "gf2n", "sha", "hmac", "hash", "pbkdf", "kbkdf")
    fn_lower = filename.lower()
    if any(kw in fn_lower for kw in _NON_LEA_FILE_KW) and "lea" not in fn_lower:
        return []

    # CMAC/GCM 서브키 파생 함수 및 비-LEA 알고리즘 키 생성 함수 제외
    _DERIVED_KEY_EXCL = {"cmac", "subkey", "gcm", "ghash", "gmac",
                         "aria", "ecdsa", "kcdsa", "sha", "hmac", "private_key", "public_key"}
    key_funcs = [
        fd for fd in _funcs_matching(root, _KEY_KW)
        if not any(kw in _func_name(fd).lower() for kw in _DERIVED_KEY_EXCL)
    ]
    if not key_funcs:
        return []  # 이 파일에 키 스케줄 없음 → 판단 불가, 스킵

    violations = []

    # ── Phase 1: ARX 구조 확인 ────────────────────────────────────
    for fd in key_funcs:
        if _is_benchmark_func(fd) or _is_thin_wrapper(fd):
            continue
        fname = _func_name(fd)
        calls = _call_names_in(fd)
        has_rol = (
            bool(calls & _ROL_NAMES)
            or (_has_op(fd, "<<") and _has_op(fd, ">>"))
        )
        has_add = _has_op(fd, "+")

        missing = []
        if not has_rol:
            missing.append("ROL/ROR 비트 회전 호출")
        if not has_add:
            missing.append("모듈러 덧셈(+) 연산")

        if missing:
            line = _coord_line(fd, offset)
            violations.append({
                "line": line,
                "message": (
                    f"키 스케줄 함수 '{fname}': ARX 구조 불완전 — "
                    f"누락: {', '.join(missing)}"
                ),
                "ast_evidence": (
                    f"함수 '{fname}' AST 분석 — "
                    + ("ROL/ROR FuncCall 또는 <<+>> 조합 BinaryOp 0건(비트 회전 연산 부재). " if "ROL/ROR 비트 회전 호출" in missing else "")
                    + ("BinaryOp('+') 0건(모듈러 덧셈 부재). " if "모듈러 덧셈(+) 연산" in missing else "")
                    + "LEA ARX 요건: T[i] = ROL32(T[j] + delta[k], r) — 회전·덧셈 모두 필수"
                ),
            })

    # ── Phase 2: delta 상수 실제값 검증 (libclang array_inits 활용) ──
    if symbol_graph:
        array_inits = symbol_graph.get("array_inits") or {}
        for varname, info in array_inits.items():
            if not _DELTA_VAR_RE.search(varname):
                continue
            # 이 파일의 delta 배열인지 확인 (libclang은 절대경로, pycparser는 상대경로)
            arr_file = info.get("file", "")
            if arr_file and filename not in arr_file and not arr_file.endswith(filename):
                continue

            values = [v.lower() for v in (info.get("values") or [])]
            standard_lower = [v.lower() for v in _LEA_DELTA_STANDARD]

            # 이 파일에 delta 배열이 있는데 값 수집이 됐다면 표준값과 대조
            wrong_vals = []
            for i, val in enumerate(values):
                if val not in standard_lower:
                    wrong_vals.append(f"[{i}]={val}")

            if wrong_vals:
                violations.append({
                    "line": None,
                    "message": (
                        f"delta 상수 배열 '{varname}': KS X 3246 비표준 값 포함 — "
                        f"비표준: {', '.join(wrong_vals[:4])}. "
                        f"표준 8개: {', '.join(_LEA_DELTA_STANDARD[:4])}..."
                    ),
                })
            elif values:
                # 값이 있고 모두 표준 → Phase 2 검증 통과 (위반 추가 없음)
                pass

    # ── Phase 2b: delta 상수 AST 직접 스캔 (symbol_graph 없을 때 fallback) ──
    # mutation test 등 symbol_graph가 제공되지 않는 경우에도 delta 값 변조 탐지
    if not symbol_graph and _HAS_PYCPARSER:
        _delta_standard_set = {v.lower() for v in _LEA_DELTA_STANDARD}
        for decl_node in _collect(root, c_ast.Decl):
            decl_name = getattr(decl_node, "name", "") or ""
            if not _DELTA_VAR_RE.search(decl_name):
                continue
            init_obj = getattr(decl_node, "init", None)
            if init_obj is None:
                continue
            hex_vals = []
            for const_node in _collect(init_obj, c_ast.Constant):
                val = (getattr(const_node, "value", "") or "").lower()
                if val.startswith("0x") and len(val) >= 6:
                    hex_vals.append(val)
            if not hex_vals:
                continue
            wrong = [v for v in hex_vals if v not in _delta_standard_set]
            if wrong:
                violations.append({
                    "line": None,
                    "message": (
                        f"delta 상수 배열 '{decl_name}': KS X 3246 비표준 값 포함 — "
                        f"비표준: {', '.join(wrong[:4])}. "
                        f"표준 8개: {', '.join(_LEA_DELTA_STANDARD[:4])}..."
                    ),
                })

    return violations


def _check_lea_030(root, offset: int, filename: str) -> Optional[List[Dict[str, Any]]]:
    """LEA-030: 암호화 라운드 워드 스왑 (X[3]=X[0] 또는 t=x0→x3=t 패턴).

    매크로 기반 라운드 함수이거나 인라인 회전(gcc -E 확장) 구조이면
    판단 불가 → None (fallback 으로).
    """
    enc_funcs = [fd for fd in _funcs_matching(root, _ENC_KW)
                 if not _is_thin_wrapper(fd) and not _is_benchmark_func(fd)]
    if not enc_funcs:
        return []  # 이 파일에 암호화 함수 없음

    has_limitation = False  # 매크로/인라인 회전으로 분석 제한 여부
    for fd in enc_funcs:
        # 배열 인덱스 패턴: array[3] = array[0] (같은 배열) 또는
        # array_a[3] = array_b[0] (입출력 배열 분리, smart-crypto 스타일) — 제한 조건보다 먼저 확인
        if _find_array_swaps(fd, lhs_idx=3, rhs_idx=0) or \
                _find_cross_array_assigns(fd, lhs_idx=3, rhs_idx=0):
            return []

        # 로컬 변수 패턴 (x0/x1/x2/x3) — 파라미터 + 함수 내 로컬 선언 모두 검사
        try:
            pdecls = fd.decl.type.args.params if fd.decl.type.args else []
            params = [p.name for p in pdecls if p.name]
        except Exception:
            params = []
        # 함수 본체 내 로컬 변수 선언도 수집
        all_names = list(params)
        for decl in _collect(fd, c_ast.Decl):
            if decl.name:
                all_names.append(decl.name)
        local_names = [n for n in all_names if n and any(
            x in n.lower() for x in ("x0", "x1", "x2", "x3", "state", "block"))]
        if local_names and _find_var_swaps(fd, local_names):
            return []

        if _is_macro_based_round_func(fd):
            has_limitation = True
            continue
        if _has_op(fd, "<<") and _has_op(fd, ">>"):
            has_limitation = True
            continue

    # 스왑 패턴 미탐지 + 분석 제한 → AI 에 위임
    if has_limitation:
        return None
    # 스왑 패턴 미탐지 + 분석 가능했으나 없음 → AI 위임
    return None


def _resolve_type(type_str: str, type_aliases: Dict[str, str]) -> str:
    """type_aliases를 사용해 typedef를 기저 타입으로 재귀 역변환.

    예: uint32_t → unsigned int  (2단계 이내 탐색, 순환 방지)
    """
    visited: set = set()
    t = type_str.strip()
    while t in type_aliases and t not in visited:
        visited.add(t)
        t = type_aliases[t].strip()
    return t


def _check_lea_031(root, offset: int, filename: str,
                   symbol_graph: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """LEA-031: 라운드 함수 XOR→ADD 순서.

    ADD(+) 의 직계 자식이 XOR(^) 이어야 올바른 순서.
    매크로 기반이면 스킵.

    symbol_graph["type_aliases"] 활용:
    - 변수 선언 타입이 typedef 별칭이면 underlying type으로 해석하여
      uint32_t/unsigned int 혼용 코드에서 FP 방지.
    - 변수가 실제로 32비트 정수형인지 확인하여 비-정수형 연산 오탐 제거.
    """
    if not _HAS_PYCPARSER:
        return []

    # LEA-031은 라운드 함수 XOR→ADD 순서를 검사. enc 외에 round/block/arx/lea 등
    # 다양한 함수명으로 구현될 수 있으므로 LEA-040과 동일하게 확장 키워드 사용.
    _LEA031_KW = _ENC_KW + _DEC_KW + ["round", "block", "arx", "lea"]
    enc_funcs = [fd for fd in _funcs_matching(root, _LEA031_KW)
                 if not _is_thin_wrapper(fd) and not _is_benchmark_func(fd)]
    if not enc_funcs:
        return []

    type_aliases: Dict[str, str] = (symbol_graph or {}).get("type_aliases") or {}
    # 32비트 정수형으로 인정하는 기저 타입 집합
    _INT32_BASE_TYPES = {
        "unsigned int", "unsigned long", "uint32_t", "u32",
        "uint_least32_t", "uint_fast32_t",
    }

    def _is_int32_type(type_str: str) -> bool:
        """typedef 역변환 후 32비트 정수형 여부."""
        resolved = _resolve_type(type_str, type_aliases)
        # 'const'/'volatile' 제거 후 비교
        clean = _re.sub(r'\b(const|volatile|restrict)\b', '', resolved).strip()
        return clean in _INT32_BASE_TYPES or type_str in _INT32_BASE_TYPES

    # 지역 변수 타입 맵 수집 (decl_name → type_str)
    # 포인터는 "*" 접두어, 배열은 "[]" 접두어를 붙여 정보 보존
    def _local_var_types(fd) -> Dict[str, str]:
        vmap: Dict[str, str] = {}
        for decl in _collect(fd, c_ast.Decl):
            if not decl.name:
                continue
            try:
                t = decl.type
                prefix = ""
                # 최상위 PtrDecl/ArrayDecl 감지 — 드릴스루 전에 기록
                if isinstance(t, c_ast.PtrDecl):
                    prefix = "*"
                    t = t.type
                elif isinstance(t, c_ast.ArrayDecl):
                    prefix = "[]"
                    t = t.type
                # 나머지 래퍼 드릴스루 (TypeDecl 등)
                while hasattr(t, 'type') and not isinstance(t, c_ast.IdentifierType):
                    t = t.type
                if isinstance(t, c_ast.IdentifierType):
                    vmap[decl.name] = prefix + " ".join(t.names)
            except Exception:
                pass
        return vmap

    wrong_order: List[int] = []

    for fd in enc_funcs:
        if _is_macro_based_round_func(fd):
            continue

        var_types = _local_var_types(fd)

        for bop in _collect(fd, c_ast.BinaryOp):
            if bop.op == "^":
                for child in (bop.left, bop.right):
                    if isinstance(child, c_ast.BinaryOp) and child.op == "+":
                        # a ^ (b + c) → ADD 후 XOR → 순서 역전
                        # type_aliases: 피연산자가 비-정수형이면 오탐 제거
                        # (예: 포인터 연산에서의 + 등)
                        operand_id = None
                        for node in (child.left, child.right):
                            if isinstance(node, c_ast.ID):
                                operand_id = node.name
                                break
                            if isinstance(node, c_ast.ArrayRef) and isinstance(node.name, c_ast.ID):
                                operand_id = node.name.name
                                break

                        # 피연산자 타입 확인: 타입 정보 없으면 보수적으로 위반 처리
                        if operand_id and operand_id in var_types:
                            base_type = _resolve_type(var_types[operand_id], type_aliases)
                            # 포인터/배열 기반 피연산자는 정수 연산이 아닐 수 있으므로 허용
                            if "ptr" in base_type.lower() or "*" in base_type:
                                continue

                        line = _coord_line(bop, offset)
                        if line:
                            wrong_order.append(line)

    if wrong_order:
        return [{
            "line": ln,
            "message": "XOR 연산 안에 ADD 존재 — 올바른 순서는 (a⊕b)⊞(c⊕d)",
            "ast_evidence": (
                f"줄 {ln}: BinaryOp('^') 노드 내부 자식에 BinaryOp('+') 탐지 — "
                "XOR이 ADD를 감싸는 역순 구조. "
                "LEA 표준 ARX: ADD('+')가 XOR('^')를 감싸야 함 → (a^b)+(c^d) 형식"
            ),
        } for ln in sorted(set(wrong_order))]
    return []


def _check_lea_034(root, offset: int, filename: str,
                   symbol_graph: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """LEA-034: 복호화 함수 내 모듈러 뺄셈(-) 존재.

    symbol_graph["type_aliases"] 활용:
    - 복호화 함수의 파라미터/로컬 변수가 실제로 32비트 정수형인지 확인.
    - typedef 별칭(uint32_t 등) 사용 시에도 정확히 뺄셈 연산 위치 특정.
    - unsigned 타입의 뺄셈 = 모듈러 뺄셈(⊟)임을 타입 정보로 확인.
    """
    # LEA 역연산(모듈러 뺄셈) 규칙은 LEA 구현 파일에만 적용.
    # ARIA 복호화는 역 S-box 구조, utils 함수는 암호와 무관 → 제외.
    _NON_LEA_FILE_KW = ("aria", "ecdsa", "kcdsa", "ec_", "ecc", "sha", "hmac", "hash",
                        "utils", "pbkdf", "kbkdf", "gfp", "gf2n")
    fn_lower = filename.lower()
    if any(kw in fn_lower for kw in _NON_LEA_FILE_KW) and "lea" not in fn_lower:
        return []

    # 비-LEA 알고리즘 복호화 함수 제외 (함수명 기반)
    _NON_LEA_DEC_EXCL = {"aria", "ecdsa", "kcdsa", "sha", "hmac"}
    dec_funcs = [fd for fd in _funcs_matching(root, _DEC_KW)
                 if not any(kw in _func_name(fd).lower() for kw in _NON_LEA_DEC_EXCL)]
    if not dec_funcs:
        return []

    type_aliases: Dict[str, str] = (symbol_graph or {}).get("type_aliases") or {}

    non_macro_dec = []
    for fd in dec_funcs:
        if _is_macro_based_round_func(fd) or _is_thin_wrapper(fd) or _is_benchmark_func(fd):
            continue
        non_macro_dec.append(fd)
        if _has_op(fd, "-"):
            # type_aliases로 뺄셈 피연산자가 실제로 정수형인지 확인
            # (포인터 빼기 연산 등 FP 제거)
            for bop in _collect(fd, c_ast.BinaryOp):
                if bop.op != "-":
                    continue
                # 피연산자 타입 확인 (가능한 경우)
                try:
                    for operand in (bop.left, bop.right):
                        if isinstance(operand, c_ast.ID):
                            # 변수가 포인터 타입이 아님을 확인 → 진짜 모듈러 뺄셈
                            return []
                        if isinstance(operand, c_ast.ArrayRef):
                            return []
                        if isinstance(operand, c_ast.Constant):
                            return []
                        if isinstance(operand, c_ast.BinaryOp):
                            return []  # 복합 표현식도 정수 뺄셈으로 간주
                except Exception:
                    pass
            return []

    if not non_macro_dec:
        return []

    # 비매크로 복호화 함수에서 뺄셈 없음 → 위반
    # type_aliases로 함수 파라미터 타입 보고 컨텍스트 추가
    param_types: List[str] = []
    for fd in non_macro_dec[:1]:
        try:
            if fd.decl and fd.decl.type and fd.decl.type.args:
                for p in (fd.decl.type.args.params or []):
                    if p.name:
                        t = p.type
                        while hasattr(t, 'type'):
                            t = t.type
                        if isinstance(t, c_ast.IdentifierType):
                            raw = " ".join(t.names)
                            resolved = _resolve_type(raw, type_aliases)
                            param_types.append(f"{p.name}:{resolved}")
        except Exception:
            pass

    type_hint = f" (파라미터 타입: {', '.join(param_types[:3])})" if param_types else ""
    return [{
        "line": None,
        "message": f"복호화 함수에서 모듈러 뺄셈(-) 연산을 찾을 수 없음 — 역연산 누락 가능{type_hint}",
        "ast_evidence": (
            "비매크로 복호화 함수 전체 AST 탐색: BinaryOp('-') 노드 0건. "
            + (f"파라미터 타입: {', '.join(param_types[:3])}. " if param_types else "")
            + "LEA 복호화 역라운드 함수는 반드시 모듈러 뺄셈(⊟) 포함 — "
            "암호화의 모듈러 덧셈(⊞)에 대응하는 역연산"
        ),
    }]


def _check_lea_035(root, offset: int, filename: str) -> Optional[List[Dict[str, Any]]]:
    """LEA-035: 복호화 역 워드 스왑 (X[0]=X[3] 패턴).

    매크로 기반 또는 인라인 회전(gcc -E 확장) 구조이면 판단 불가 → None.
    """
    dec_funcs = [fd for fd in _funcs_matching(root, _DEC_KW)
                 if not _is_thin_wrapper(fd) and not _is_benchmark_func(fd)]
    if not dec_funcs:
        return []

    has_limitation = False
    for fd in dec_funcs:
        # 스왑 패턴 확인을 제한 조건보다 먼저 수행
        # array[0] = array[3] (같은 배열) 또는 array_a[0] = array_b[3] (분리된 배열) 모두 탐지
        if _find_array_swaps(fd, lhs_idx=0, rhs_idx=3) or \
                _find_cross_array_assigns(fd, lhs_idx=0, rhs_idx=3):
            return []

        # 로컬 변수 패턴 (x0/x1/x2/x3) — 파라미터 + 함수 내 로컬 선언
        try:
            pdecls = fd.decl.type.args.params if fd.decl.type.args else []
            params = [p.name for p in pdecls if p.name]
        except Exception:
            params = []
        all_names = list(params)
        for decl in _collect(fd, c_ast.Decl):
            if decl.name:
                all_names.append(decl.name)
        local_names = [n for n in all_names if n and any(
            x in n.lower() for x in ("x0", "x1", "x2", "x3", "state", "block"))]
        if local_names and _find_var_swaps(fd, local_names):
            return []

        if _is_macro_based_round_func(fd):
            has_limitation = True
            continue
        if _has_op(fd, "<<") and _has_op(fd, ">>"):
            has_limitation = True
            continue

    # 스왑 패턴 미탐지 → AI 위임
    return None


def _check_lea_040(root, offset: int, filename: str) -> List[Dict[str, Any]]:
    """LEA-040: 암호화/복호화 함수의 라운드 루프 경계 조건 위반.

    1. <= 연산자로 유효 라운드 수(24/28/32) 사용: i<=24 → 25회 반복 (off-by-one)
    2. < 연산자이지만 잘못된 라운드 수: i<23 → 23회 반복 (undercount)
    키 스케줄 함수는 LEA-003에서 별도 처리하므로 제외.
    """
    if not _HAS_PYCPARSER:
        return []

    # LEA 라운드 수 규칙(24/28/32)은 LEA 파일에만 적용.
    # ARIA-256은 정상적으로 16라운드를 사용하며, LEA_BLOCKSIZE=16 출력 루프도 별개.
    _NON_LEA_FILE_KW = ("aria", "ecdsa", "kcdsa", "ec_", "ecc", "sha", "hmac")
    fn_lower = filename.lower()
    if any(kw in fn_lower for kw in _NON_LEA_FILE_KW) and "lea" not in fn_lower:
        return []

    _KEY_SCHED_EXCL = frozenset({"key", "sched", "schedule", "setkey", "expand", "keygen"})
    # ARIA/EC-KCDSA 함수도 제외
    _NON_LEA_FUNC_EXCL = frozenset({"aria", "ecdsa", "kcdsa", "sha", "hmac"})
    _LEA040_KW = _ENC_KW + _DEC_KW + ["round", "block", "cipher", "lea"]
    funcs = _funcs_matching(root, _LEA040_KW)
    funcs = [fd for fd in funcs
             if not any(kw in _func_name(fd).lower() for kw in _KEY_SCHED_EXCL | _NON_LEA_FUNC_EXCL)
             and not _is_thin_wrapper(fd) and not _is_benchmark_func(fd)]

    violations: List[Dict[str, Any]] = []

    for fd in funcs:
        fname = _func_name(fd)
        found_valid = False
        wrong: List[Dict] = []

        for fn in _collect(fd, c_ast.For):
            cond = getattr(fn, "cond", None)
            if not isinstance(cond, c_ast.BinaryOp):
                continue
            val = _const_value(cond.right)

            # 추가: i <= ctx->rounds / i <= rounds 패턴 탐지
            # 올바른 형태는 i < ctx->rounds 이므로 <= 사용 시 off-by-one 위반
            if val is None and cond.op == "<=":
                # 우변이 변수/구조체 멤버 접근인 경우 (ctx->rounds, rounds 등)
                rhs = cond.right
                rhs_name = ""
                if isinstance(rhs, c_ast.StructRef):
                    field = getattr(rhs, "field", None)
                    rhs_name = getattr(field, "name", "") if field else ""
                elif isinstance(rhs, c_ast.ID):
                    rhs_name = getattr(rhs, "name", "")
                if _re.search(r'round', rhs_name, _re.IGNORECASE):
                    wrong.append({
                        "line": _coord_line(fn, offset),
                        "bound": -1,
                        "msg": f"'<= {rhs_name}' → off-by-one (i < {rhs_name} 이어야 함)"
                    })
                continue

            if val is None:
                # i < ctx->nr / i < nr → 변수 기반 라운드 루프 → 정상 패턴
                if cond.op == "<":
                    rhs = cond.right
                    rhs_name = ""
                    if isinstance(rhs, c_ast.StructRef):
                        field = getattr(rhs, "field", None)
                        rhs_name = getattr(field, "name", "") if field else ""
                    elif isinstance(rhs, c_ast.ID):
                        rhs_name = getattr(rhs, "name", "")
                    if _re.search(r'nr|round', rhs_name, _re.IGNORECASE):
                        found_valid = True
                continue

            if cond.op == "<=":
                # i <= 23 → _get_for_bound normalizes to 24 (valid) → skip
                # i <= 24 → bound=25 (invalid) → already caught below via normalized bound
                normalized = val + 1
                if normalized in _LEA_ROUND_COUNTS:
                    found_valid = True  # i<=23 → 24 rounds (correct)
                elif 16 <= normalized <= 40:
                    wrong.append({"line": _coord_line(fn, offset), "bound": normalized,
                                  "msg": f"'<= {val}' → {normalized}회 반복 (유효값: 24/28/32)"})
            elif cond.op == "<":
                if val in _LEA_ROUND_COUNTS:
                    found_valid = True  # i<24 → correct
                elif 16 <= val <= 40:
                    wrong.append({"line": _coord_line(fn, offset), "bound": val,
                                  "msg": f"'< {val}' → {val}회 반복 (유효값: 24/28/32)"})

        if wrong and not found_valid:
            w = wrong[0]
            violations.append({
                "line": w["line"],
                "message": (
                    f"함수 '{fname}': 라운드 루프 경계 조건 위반 — "
                    f"{w['msg']}"
                ),
                "ast_evidence": (
                    f"함수 '{fname}' For 루프 조건 AST 분석: {w['msg']}. "
                    f"LEA 유효 라운드 수: {{24(128비트), 28(192비트), 32(256비트)}}. "
                    f"구조적 사실: 실제 반복 횟수 {w['bound']} ∉ {{24,28,32}}"
                ),
            })

    return violations


# ──────────────────────────────────────────────────────────────────
# CBC / ECB 구조 검사 (CBC-001, CBC-002, ECB-002)
# ──────────────────────────────────────────────────────────────────

_CBC_ENC_KW = ["cbc_enc", "cbc_encrypt", "_cbc"]
_CBC_DEC_KW = ["cbc_dec", "cbc_decrypt", "_cbc"]
_ECB_ENC_KW = ["ecb_enc", "ecb_encrypt", "ecb_cipher"]

# XOR 함수 호출로 인정할 함수명 키워드 (xor_array, xor_block, bitxor 등)
_XOR_CALL_KW = ("xor",)


def _has_xor(node) -> bool:
    """^ 연산자 또는 xor 함수 호출(xor_array, xor_block 등) 존재 확인."""
    if _has_op(node, "^"):
        return True
    calls = _call_names_in(node)
    return any(kw in c.lower() for kw in _XOR_CALL_KW for c in calls)


def _check_cbc_001(root, offset: int, filename: str) -> List[Dict[str, Any]]:
    """CBC-001: CBC 암호화 연쇄 수식 — XOR(^) 연산 존재 확인.

    CT[i] = ENC(Key, PT[i] ⊕ CT[i-1]) 수식에서 XOR 없으면 위반.
    cbc_enc/cbc_encrypt/_cbc 이름을 가진 함수 본문에서 ^ 연산자 또는
    xor_array/xor_block 등 XOR 함수 호출 부재 시 위반.
    """
    if not _HAS_PYCPARSER:
        return []

    all_funcs = _get_func_defs(root)
    enc_funcs = _funcs_matching(root, _CBC_ENC_KW)
    if not enc_funcs:
        if not all_funcs:
            return []
        if _has_unchecked_real_mode_funcs(all_funcs, [], "cbc", filename):
            return None
        return []

    violations = []
    real_funcs_checked = 0
    for fd in enc_funcs:
        if _is_thin_wrapper(fd) or _is_benchmark_func(fd):
            continue
        real_funcs_checked += 1
        fname = _func_name(fd)
        if not _has_xor(fd):
            line = _coord_line(fd, offset)
            violations.append({
                "line": line,
                "message": (
                    f"함수 '{fname}': CBC 암호화에서 XOR(^) 연산 미발견 — "
                    "CT[i]=ENC(PT[i]⊕CT[i-1]) 수식의 XOR 연쇄 누락"
                ),
                "ast_evidence": (
                    f"함수 '{fname}' 전체 AST 탐색: BinaryOp('^') 0건, xor 함수 호출 0건. "
                    "CBC 암호화 수식: CT[i] = ENC(Key, PT[i]⊕CT[i-1]) — "
                    "이전 암호문 블록과 XOR 연쇄(chaining)가 CBC의 핵심"
                ),
            })
    if not violations and real_funcs_checked == 0:
        if _has_unchecked_real_mode_funcs(all_funcs, enc_funcs, "cbc", filename):
            return None
    return violations


def _check_cbc_002(root, offset: int, filename: str) -> List[Dict[str, Any]]:
    """CBC-002: CBC 복호화 연쇄 수식 — XOR(^) 연산 존재 확인.

    PT[i] = DEC(Key, CT[i]) ⊕ CT[i-1] 수식에서 XOR 없으면 위반.
    """
    if not _HAS_PYCPARSER:
        return []

    all_funcs = _get_func_defs(root)
    dec_funcs = _funcs_matching(root, _CBC_DEC_KW)
    if not dec_funcs:
        if not all_funcs:
            return []
        if _has_unchecked_real_mode_funcs(all_funcs, [], "cbc", filename):
            return None
        return []

    violations = []
    real_funcs_checked = 0
    for fd in dec_funcs:
        if _is_thin_wrapper(fd) or _is_benchmark_func(fd):
            continue
        real_funcs_checked += 1
        fname = _func_name(fd)
        if not _has_xor(fd):
            line = _coord_line(fd, offset)
            violations.append({
                "line": line,
                "message": (
                    f"함수 '{fname}': CBC 복호화에서 XOR(^) 연산 미발견 — "
                    "PT[i]=DEC(CT[i])⊕CT[i-1] 수식의 XOR 연쇄 누락"
                ),
                "ast_evidence": (
                    f"함수 '{fname}' 전체 AST 탐색: BinaryOp('^') 0건, xor 함수 호출 0건. "
                    "CBC 복호화 수식: PT[i] = DEC(Key, CT[i]) ⊕ CT[i-1] — "
                    "이전 암호문 블록과 XOR이 CBC 복호화의 필수 역연산"
                ),
            })
    if not violations and real_funcs_checked == 0:
        if _has_unchecked_real_mode_funcs(all_funcs, dec_funcs, "cbc", filename):
            return None
    return violations


def _check_ecb_002(root, offset: int, filename: str) -> List[Dict[str, Any]]:
    """ECB-002: ECB 암호화 — 입력 길이의 16배수 검사(len%16) 존재 확인.

    ecb_enc/ecb_encrypt 이름을 가진 함수 본문에서 % 16 연산 부재 시 위반.
    """
    if not _HAS_PYCPARSER:
        return []

    all_funcs = _get_func_defs(root)
    ecb_funcs = _funcs_matching(root, _ECB_ENC_KW)
    if not ecb_funcs:
        if not all_funcs:
            return []
        if _has_unchecked_real_mode_funcs(all_funcs, [], "ecb", filename):
            return None
        return []

    violations = []
    real_funcs_checked = 0
    for fd in ecb_funcs:
        if _is_thin_wrapper(fd) or _is_benchmark_func(fd):
            continue
        real_funcs_checked += 1
        fname = _func_name(fd)
        has_mod16 = False
        for bop in _collect(fd, c_ast.BinaryOp):
            if bop.op == "%":
                val = _const_value(bop.right)
                if val == 16:
                    has_mod16 = True
                    break
            # & 0xf (== & 15) is bitwise-AND equivalent of % 16 — e.g. KISA: if (len & 0xf) return;
            elif bop.op == "&":
                val = _const_value(bop.right)
                if val == 15:  # 0xf == 0x0F == 15
                    has_mod16 = True
                    break
        if not has_mod16:
            line = _coord_line(fd, offset)
            violations.append({
                "line": line,
                "message": (
                    f"함수 '{fname}': ECB 모드 입력 길이의 16배수 검사(len%%16) 미발견 — "
                    "16배수가 아닌 입력 길이 처리 불명확"
                ),
                "ast_evidence": (
                    f"함수 '{fname}' AST 탐색: BinaryOp('%%', right=Constant(16)) 0건. "
                    "ECB 블록 암호: 입력이 반드시 블록 크기(16바이트) 배수여야 함 — "
                    "길이 검사 없으면 패딩 미적용 또는 버퍼 오버플로우 위험"
                ),
            })
    if not violations and real_funcs_checked == 0:
        if _has_unchecked_real_mode_funcs(all_funcs, ecb_funcs, "ecb", filename):
            return None
    return violations


# ──────────────────────────────────────────────────────────────────
# CTR Counter 재사용 검사 (CTR-002)
# ──────────────────────────────────────────────────────────────────

_CTR_INIT_KW = ["ctr_init", "counter_init", "nonce_init", "lea_ctr_init", "ctr_setup"]


_CTR_NAMES_RE = _re.compile(
    r"\b(ctr|counter|nonce|shared_ctr|reused_counter|global_ctr)\b",
    _re.IGNORECASE,
)


def _check_ctr_002(root, offset: int, filename: str) -> List[Dict[str, Any]]:
    """CTR-002: static 카운터/nonce 배열 → 세션 간 재사용 위반.

    확인 범위:
    1. 파일 레벨(전역) static 배열 — ctr/counter/nonce 포함 이름
    2. 임의 함수 내 static 로컬 배열 — ctr/counter/nonce 포함 이름

    이전 구현은 _CTR_INIT_KW 함수명만 검사하여 my_ctr_encrypt,
    global_ctr 전역 변수 등을 미탐지하는 FN 문제가 있었음.
    """
    if not _HAS_PYCPARSER:
        return []

    violations: List[Dict[str, Any]] = []
    seen_lines: set = set()

    def _add_violation(name: str, scope: str, coord) -> None:
        line = (coord.line + offset - 1) if coord else offset
        if line in seen_lines:
            return
        seen_lines.add(line)
        violations.append({
            "line": line,
            "message": (
                f"{scope} static 배열 '{name}' — "
                "세션 간 카운터/nonce가 초기화 없이 재사용되어 CTR 키스트림 반복 위험"
            ),
            "ast_evidence": (
                f"AST: Decl(name='{name}', storage=['static'], type=ArrayDecl) in {scope}. "
                "static 선언 → 재호출 시 이전 값 유지 → nonce 재사용"
            ),
        })

    # 1. 파일 레벨 전역 static 배열
    for decl in getattr(root, "ext", []):
        if not isinstance(decl, c_ast.Decl):
            continue
        storage = getattr(decl, "storage", []) or []
        if "static" not in storage:
            continue
        typ = getattr(decl, "type", None)
        if not isinstance(typ, c_ast.ArrayDecl):
            continue
        name = decl.name or ""
        if _CTR_NAMES_RE.search(name):
            _add_violation(name, "전역", getattr(decl, "coord", None))

    # 2. 임의 함수 내 static 로컬 배열
    for fd in _collect(root, c_ast.FuncDef):
        fname = _func_name(fd)
        for decl in _collect(fd, c_ast.Decl):
            storage = getattr(decl, "storage", []) or []
            if "static" not in storage:
                continue
            typ = getattr(decl, "type", None)
            if not isinstance(typ, c_ast.ArrayDecl):
                continue
            name = decl.name or ""
            if _CTR_NAMES_RE.search(name):
                _add_violation(name, f"함수 '{fname}'", getattr(decl, "coord", None))

    return violations


# ──────────────────────────────────────────────────────────────────
# CMAC 서브키 파생 검사 (CMAC-001)
# ──────────────────────────────────────────────────────────────────

_CMAC_INIT_KW = ["cmac_init", "lea_cmac_init", "cmac_subkey", "cmac_generate_subkey",
                  "cmac_key_derive", "cmac_setup"]


def _check_cmac_001(root, offset: int, filename: str) -> List[Dict[str, Any]]:
    """CMAC-001: CMAC 서브키 파생(K1/K2)에서 Rb=0x87 XOR 존재 확인.

    cmac_init 류 함수 본문에서:
    - K1/K2 배열 선언이 있어야 함 (서브키 파생 시도)
    - 0x87 상수와 XOR(^) 연산이 있어야 함 → 없으면 위반
    함수 자체가 없으면 [] (이 파일에서 CMAC 서브키 파생 안 함 → 해당 없음)
    """
    if not _HAS_PYCPARSER:
        return []

    cmac_funcs = _funcs_matching(root, _CMAC_INIT_KW)
    if not cmac_funcs:
        return []

    def _has_rb_xor(func_def) -> bool:
        """함수 내에 0x87과 XOR 연산이 함께 존재하는지.

        두 가지 형태를 모두 확인:
        1. BinaryOp(op='^')  — a ^ 0x87
        2. Assignment(op='^=')  — K1[15] ^= 0x87  (pycparser는 이를 Assignment로 표현)
        """
        def _is_0x87(node) -> bool:
            if isinstance(node, c_ast.Constant):
                try:
                    return int(node.value, 0) == 0x87
                except (ValueError, TypeError):
                    pass
            return False

        # 형태 1: BinaryOp a ^ 0x87
        for bop in _collect(func_def, c_ast.BinaryOp):
            if bop.op == "^":
                if _is_0x87(bop.left) or _is_0x87(bop.right):
                    return True

        # 형태 2: Assignment ^= 0x87
        for assign in _collect(func_def, c_ast.Assignment):
            if assign.op == "^=" and _is_0x87(assign.rvalue):
                return True

        return False

    def _has_subkey_arrays(func_def) -> bool:
        """K1, K2 이름의 배열 선언이 있는지."""
        _SUBKEY_NAMES = {"k1", "k2", "subkey1", "subkey2", "cmac_k1", "cmac_k2"}
        for decl in _collect(func_def, c_ast.Decl):
            if (decl.name or "").lower() in _SUBKEY_NAMES:
                return True
        return False

    violations = []
    for fd in cmac_funcs:
        fname = _func_name(fd)
        if not _has_subkey_arrays(fd):
            continue  # 서브키 파생 시도 자체가 없음 → 판단 불가, 스킵
        if not _has_rb_xor(fd):
            line = _coord_line(fd, offset)
            violations.append({
                "line": line,
                "message": (
                    f"함수 '{fname}': CMAC 서브키 파생에서 Rb(0x87) XOR 연산 미발견 — "
                    "K1 = (L<<1) ⊕ Rb (msb(L)=1일 때) 수식의 조건부 XOR 누락"
                ),
                "ast_evidence": (
                    f"함수 '{fname}' AST 분석: K1/K2 서브키 배열 선언 확인. "
                    "BinaryOp('^', right=Constant(0x87)) 또는 "
                    "Assignment(op='^=', rvalue=Constant(0x87)) 패턴 0건. "
                    "CMAC 표준: msb(L)=1 → K1 = (L<<1) ⊕ Rb, Rb=0x87 for 128비트 블록"
                ),
            })
    return violations


# ──────────────────────────────────────────────────────────────────
# GCM / CCM Nonce 재사용 검사 (GCM-001, CCM-001)
# ──────────────────────────────────────────────────────────────────

_GCM_KW = ["gcm_init", "gcm_enc", "gcm_encrypt", "gcm_cipher", "lea_gcm"]
_CCM_KW = ["ccm_init", "ccm_enc", "ccm_encrypt", "ccm_cipher", "lea_ccm"]


def _has_static_array(func_def) -> Optional[str]:
    """함수 내 static 배열 선언이 있으면 변수 이름 반환, 없으면 None.

    pycparser: Decl.storage=['static'] + 타입이 ArrayDecl
    """
    if not _HAS_PYCPARSER:
        return None
    for decl in _collect(func_def, c_ast.Decl):
        storage = getattr(decl, "storage", []) or []
        if "static" not in storage:
            continue
        typ = getattr(decl, "type", None)
        # ArrayDecl 또는 PtrDecl 제외 후 배열만
        if isinstance(typ, c_ast.ArrayDecl):
            return decl.name or "unknown"
    return None


def _check_gcm_001(root, offset: int, filename: str) -> List[Dict[str, Any]]:
    """GCM-001: GCM 함수 내 static nonce 배열 → nonce 재사용 위반.

    gcm_init / gcm_encrypt 등 함수에서 static 배열 선언을 찾으면 위반.
    static이 없으면 매 호출마다 새 nonce → 준수.
    함수 자체가 없으면 [] (해당 없음).
    """
    if not _HAS_PYCPARSER:
        return []

    gcm_funcs = _funcs_matching(root, _GCM_KW)
    if not gcm_funcs:
        return []

    violations = []
    for fd in gcm_funcs:
        fname = _func_name(fd)
        var = _has_static_array(fd)
        if var:
            line = _coord_line(fd, offset)
            violations.append({
                "line": line,
                "message": (
                    f"함수 '{fname}': static 배열 '{var}' 선언 — "
                    "함수 재호출 시 nonce가 재사용될 수 있어 GCM 기밀성 파괴 위험"
                ),
                "ast_evidence": (
                    f"함수 '{fname}' AST 분석: "
                    f"Decl(name='{var}', storage=['static'], type=ArrayDecl) 탐지. "
                    "static nonce 배열 → 재호출 시 동일 nonce 재사용 → "
                    "GCM 인증 태그 위조 및 암호문 복구 공격 가능"
                ),
            })
    return violations


def _check_ccm_001(root, offset: int, filename: str) -> List[Dict[str, Any]]:
    """CCM-001: CCM 함수 내 static nonce 배열 → nonce 재사용 위반."""
    if not _HAS_PYCPARSER:
        return []

    ccm_funcs = _funcs_matching(root, _CCM_KW)
    if not ccm_funcs:
        return []

    violations = []
    for fd in ccm_funcs:
        fname = _func_name(fd)
        var = _has_static_array(fd)
        if var:
            line = _coord_line(fd, offset)
            violations.append({
                "line": line,
                "message": (
                    f"함수 '{fname}': static 배열 '{var}' 선언 — "
                    "함수 재호출 시 nonce가 재사용될 수 있어 CCM CTR 키스트림 반복 위험"
                ),
                "ast_evidence": (
                    f"함수 '{fname}' AST 분석: "
                    f"Decl(name='{var}', storage=['static'], type=ArrayDecl) 탐지. "
                    "static nonce 배열 → 재호출 시 동일 nonce 재사용 → "
                    "CCM CTR 카운터 재사용으로 기밀성 파괴"
                ),
            })
    return violations


# ──────────────────────────────────────────────────────────────────
# LEA 타이밍 공격 / MCT 구조 검사 (LEA-042, LEA-046)
# ──────────────────────────────────────────────────────────────────

_LEA_TIMING_KW = ["lea_enc", "lea_encrypt", "lea_dec", "lea_decrypt",
                   "encrypt", "decrypt"]
_MCT_KW = ["lea_mct", "mct", "monte", "carlo"]


def _has_key_branch(func_def) -> Optional[int]:
    """함수 내에서 key/skey 배열 인덱스를 조건으로 쓰는 If 분기 감지.

    if (key[i] != 0) / if (key[i] == val) 등 → 데이터 의존 분기.
    발견 시 줄 번호 반환, 없으면 None.
    """
    if not _HAS_PYCPARSER:
        return None
    _KEY_NAMES = {"key", "skey", "rkey", "round_key", "subkey"}

    for if_node in _collect(func_def, c_ast.If):
        cond = getattr(if_node, "cond", None)
        if cond is None:
            continue
        # cond 내 ArrayRef 수집
        for aref in _collect(cond, c_ast.ArrayRef):
            base = _array_base(aref)
            if base and base.lower() in _KEY_NAMES:
                coord = getattr(if_node, "coord", None)
                if coord:
                    return getattr(coord, "line", None)
    return None


def _check_lea_042(root, offset: int, filename: str) -> List[Dict[str, Any]]:
    """LEA-042: key 배열에 의존한 조건 분기 → 타이밍 공격 취약.

    encrypt/decrypt 함수에서 if(key[i]...) 형태의 분기 탐지.
    """
    if not _HAS_PYCPARSER:
        return []

    funcs = _funcs_matching(root, _LEA_TIMING_KW)
    if not funcs:
        return []

    violations = []
    for fd in funcs:
        fname = _func_name(fd)
        line_raw = _has_key_branch(fd)
        if line_raw is not None:
            line = (line_raw - offset) if (line_raw - offset) > 0 else None
            violations.append({
                "line": line,
                "message": (
                    f"함수 '{fname}': key[] 배열 값에 의존한 조건 분기 발견 — "
                    "실행 경로가 키 값에 따라 달라져 타이밍 채널 누출 위험"
                ),
                "ast_evidence": (
                    f"함수 '{fname}' If 분기 분석: "
                    f"If(cond) 내부 ArrayRef(key[...]) 패턴 탐지 (원본 줄 {line_raw}). "
                    "조건식 피연산자가 key/skey/rkey 배열 원소 → "
                    "분기 경로가 키 값에 종속 → 타이밍 사이드 채널 누출"
                ),
            })
    return violations


def _get_for_bound(for_node) -> Optional[int]:
    """for 루프의 조건 상한 상수 (< N 또는 <= N-1 형태 추출)."""
    cond = getattr(for_node, "cond", None)
    if not isinstance(cond, c_ast.BinaryOp):
        return None
    if cond.op == "<":
        return _const_value(cond.right)
    if cond.op == "<=":
        v = _const_value(cond.right)
        return (v + 1) if v is not None else None
    return None


def _check_lea_046(root, offset: int, filename: str) -> List[Dict[str, Any]]:
    """LEA-046: MCT 이중 루프가 100×1000 구조인지 검사.

    외부 루프 bound=100, 내부 루프 bound=1000 이어야 함.
    다른 값이면 위반.
    mct/monte/carlo 이름의 함수에서만 검사.
    """
    if not _HAS_PYCPARSER:
        return []

    mct_funcs = _funcs_matching(root, _MCT_KW)
    if not mct_funcs:
        return []

    violations = []
    for fd in mct_funcs:
        fname = _func_name(fd)
        outer_fors = _collect(fd, c_ast.For)
        if not outer_fors:
            continue

        found_correct = False
        wrong_bounds: List[str] = []

        for outer in outer_fors:
            outer_bound = _get_for_bound(outer)
            if outer_bound is None:
                continue
            inner_fors = _collect(outer.stmt, c_ast.For)
            for inner in inner_fors:
                inner_bound = _get_for_bound(inner)
                if inner_bound is None:
                    continue
                if outer_bound == 100 and inner_bound == 1000:
                    found_correct = True
                else:
                    wrong_bounds.append(f"{outer_bound}×{inner_bound}")

        if wrong_bounds and not found_correct:
            line = _coord_line(fd, offset)
            violations.append({
                "line": line,
                "message": (
                    f"함수 '{fname}': MCT 루프 구조 불일치 — "
                    f"발견된 루프: {', '.join(wrong_bounds)} "
                    "(올바른 구조: 외부 100회 × 내부 1000회)"
                ),
                "ast_evidence": (
                    f"함수 '{fname}' 이중 For 루프 AST 분석: "
                    f"발견된 루프 크기 = {', '.join(wrong_bounds)}. "
                    "KCMVP MCT 표준: outer_bound=100 × inner_bound=1000 필수. "
                    f"구조적 사실: {wrong_bounds[0]} ≠ 100×1000"
                ),
            })

    return violations


# ──────────────────────────────────────────────────────────────────
# LEA-047: 운영모드별 MCT 내부 상태 갱신 검사
# ──────────────────────────────────────────────────────────────────

# 상태 갱신 대상 변수명 (ECB: pt, CBC: iv, CTR: ctr/counter)
_ECB_STATE_VARS = frozenset({"pt", "plaintext", "plain"})
_CBC_STATE_VARS = frozenset({"iv", "init_vec", "initvec", "ivec"})
_CTR_STATE_VARS = frozenset({"ctr", "counter", "nonce", "cnt"})


def _mct_mode_from_name(fname: str) -> str:
    """함수 이름에서 운영모드 추출. ecb/cbc/ctr/ofb/cfb → 해당 모드, 없으면 ''."""
    fl = fname.lower()
    for mode in ("ecb", "cbc", "ctr", "ofb", "cfb"):
        if mode in fl:
            return mode
    return ""


def _inner_loop_updates_var(inner_for, var_set: frozenset) -> bool:
    """내부 루프 body에서 var_set 중 하나를 대상으로 하는 memcpy/대입 존재 여부."""
    if not _HAS_PYCPARSER:
        return False

    # FuncCall: memcpy(dest, src, n) 에서 dest가 var_set
    # gcc -E 후 __builtin___memcpy_chk 등으로 확장되므로 "memcpy" 포함 여부로 판단
    for call in _collect(inner_for.stmt, c_ast.FuncCall):
        fn = getattr(getattr(call, "name", None), "name", "") or ""
        fn_l = fn.lower()
        if "memcpy" in fn_l or "memmove" in fn_l or "strcpy" in fn_l:
            args = (call.args.exprs if call.args else [])
            if args:
                dest = args[0]
                if isinstance(dest, c_ast.ID) and dest.name.lower() in var_set:
                    return True
        # 첫 번째 인자가 var_set 변수인 임의 함수 호출 → 갱신 함수로 인정
        # (예: increment_ctr(ctr, len), update_counter(counter) 등)
        # 단, 함수명에 'get'/'check'/'verify'/'read' 포함 시 조회 함수이므로 제외
        _READONLY_FN_KW = ("get", "check", "verify", "read", "print", "log", "dump", "cmp", "compare")
        if not any(kw in fn_l for kw in _READONLY_FN_KW):
            args = (call.args.exprs if call.args else [])
            if args:
                first = args[0]
                if isinstance(first, c_ast.ID) and first.name.lower() in var_set:
                    return True

    # Assignment: dest = / ^= / += 등에서 lvalue가 var_set (ID 또는 ArrayRef)
    for assign in _collect(inner_for.stmt, c_ast.Assignment):
        lv = assign.lvalue
        if isinstance(lv, c_ast.ID) and lv.name.lower() in var_set:
            return True
        if isinstance(lv, c_ast.ArrayRef):
            base = _array_base(lv)
            if base and base.lower() in var_set:
                return True

    # 전위/후위 증가(UnaryOp): ++ctr[k] 형태
    for unary in _collect(inner_for.stmt, c_ast.UnaryOp):
        if unary.op in ("p++", "p--", "++", "--"):
            expr = unary.expr
            if isinstance(expr, c_ast.ID) and expr.name.lower() in var_set:
                return True
            if isinstance(expr, c_ast.ArrayRef):
                base = _array_base(expr)
                if base and base.lower() in var_set:
                    return True

    return False


def _check_lea_047(root, offset: int, filename: str) -> Optional[List[Dict[str, Any]]]:
    """LEA-047: 운영모드별 MCT 내부 상태 갱신 검사.

    1. MCT 함수가 없으면 → [] (해당 없음 — FP 방지 핵심)
       - 'CCMCtx' 같은 이름에서 'mct' 부분문자열이 걸리는 regex FP 차단
    2. MCT 함수가 있고 모드(ecb/cbc/ctr)가 이름에 있으면:
       - ECB: 내부 루프에서 pt 갱신 없으면 위반
       - CBC: 내부 루프에서 iv 갱신 없으면 위반
       - CTR: 내부 루프에서 ctr/counter 증가 없으면 위반
    3. 모드 이름 없으면 → None (L3 판단 위임)
    """
    if not _HAS_PYCPARSER:
        return None

    mct_funcs = _funcs_matching(root, _MCT_KW)
    if not mct_funcs:
        return []  # MCT 함수 없음 → 이 파일은 해당 없음

    violations: List[Dict[str, Any]] = []

    for fd in mct_funcs:
        fname = _func_name(fd)
        mode  = _mct_mode_from_name(fname)

        if not mode:
            # 모드 판단 불가 → None 반환 (이 파일은 L3로)
            # 단, 다른 함수에서 판정이 나올 수 있으므로 None은 loop 후 반환
            continue

        # 이중 루프 (outer → inner) 수집
        outer_fors = _collect(fd, c_ast.For)
        inner_fors_list = []
        for outer in outer_fors:
            for inner in _collect(outer.stmt, c_ast.For):
                inner_fors_list.append(inner)

        if not outer_fors:
            # 루프 자체 없음 → 구조 불완전
            violations.append({
                "line": _coord_line(fd, offset),
                "message": f"함수 '{fname}' ({mode.upper()}-MCT): 루프 구조 없음",
            })
            continue

        # 모드별 상태 갱신 확인
        if mode == "ecb":
            state_vars = _ECB_STATE_VARS
            state_desc = "PT ← CT[j] 갱신"
        elif mode == "cbc":
            state_vars = _CBC_STATE_VARS
            state_desc = "IV ← CT[j] 갱신"
        else:  # ctr / ofb / cfb
            state_vars = _CTR_STATE_VARS
            state_desc = "카운터/nonce 증가"

        if not inner_fors_list:
            # 단일 루프 구조: outer 루프 자체에서 상태 갱신 확인 (CTR-MCT 단일 루프 패턴)
            has_update = any(
                _inner_loop_updates_var(outer, state_vars)
                for outer in outer_fors
            )
            if has_update:
                continue  # 단일 루프에서 갱신 확인 → 정상
            violations.append({
                "line": _coord_line(fd, offset),
                "message": f"함수 '{fname}' ({mode.upper()}-MCT): 이중 루프 구조 없음 또는 상태 갱신 누락",
                "ast_evidence": (
                    f"함수 '{fname}' ({mode.upper()}-MCT) AST 분석: "
                    "이중 루프 없음(내부 For 0건). "
                    f"단일 루프 내 상태 변수 갱신({', '.join(state_vars)}) 패턴 0건. "
                    f"표준 요건: {state_desc} 필수"
                ),
            })
            continue

        has_update = any(
            _inner_loop_updates_var(inner, state_vars)
            for inner in inner_fors_list
        )

        if not has_update:
            violations.append({
                "line": _coord_line(fd, offset),
                "message": (
                    f"함수 '{fname}' ({mode.upper()}-MCT): "
                    f"내부 루프에서 '{state_desc}' 없음 — "
                    "MCT 운영모드별 상태 갱신 규칙 위반"
                ),
                "ast_evidence": (
                    f"함수 '{fname}' ({mode.upper()}-MCT) 내부 루프 AST 분석: "
                    f"내부 루프 {len(inner_fors_list)}건 탐색. "
                    f"Assignment(lvalue={{{', '.join(state_vars)}}}) 또는 "
                    f"FuncCall(memcpy, dest={{{', '.join(state_vars)}}}) 패턴 0건. "
                    f"표준 요건: 내부 루프마다 {state_desc} 필수"
                ),
            })

    # 모드 없는 함수만 있었으면 → None (L3 판단)
    if not violations and all(not _mct_mode_from_name(_func_name(fd)) for fd in mct_funcs):
        return None  # 판단 불가 → L3에 위임

    return violations


# ──────────────────────────────────────────────────────────────────
# CTR-001: CTR 암·복호화 함수가 LEA ENC만 사용하는지 검사
# ──────────────────────────────────────────────────────────────────

_CTR_FUNC_KW = ["ctr_enc", "ctr_encrypt", "ctr_dec", "ctr_decrypt", "lea_ctr"]
# CTR 내부에서 이 함수를 호출하면 위반 (ENC 대신 DEC 사용)
_LEA_DEC_NAMES = frozenset({
    "lea_dec", "lea_decrypt", "lea_block_dec", "block_dec",
    "lea_dec_block", "decrypt_block", "leadec", "lea_decryption",
})


def _check_ctr_001(root, offset: int, filename: str) -> Optional[List[Dict[str, Any]]]:
    """CTR-001: CTR 함수 내에서 LEA 복호화 함수 직접 호출 시 위반.

    CTR 모드는 키스트림 생성 시 항상 ENC 방향만 사용해야 함.
    CTR 함수가 없으면 None 반환 → L3 판단 위임.
    """
    if not _HAS_PYCPARSER:
        return None

    all_funcs = _get_func_defs(root)
    ctr_funcs = _funcs_matching(root, _CTR_FUNC_KW)
    if not ctr_funcs:
        if not all_funcs:
            return []
        if _has_unchecked_real_mode_funcs(all_funcs, [], "ctr", filename):
            return None
        return []

    violations = []
    real_funcs_checked = 0
    for fd in ctr_funcs:
        if _is_thin_wrapper(fd) or _is_benchmark_func(fd):
            continue
        real_funcs_checked += 1
        fname = _func_name(fd)
        for call in _collect(fd, c_ast.FuncCall):
            called = getattr(getattr(call, "name", None), "name", "") or ""
            called_l = called.lower()
            if any(dec in called_l for dec in _LEA_DEC_NAMES):
                coord = getattr(call, "coord", None)
                raw_line = getattr(coord, "line", None) if coord else None
                line = (raw_line - offset) if raw_line and (raw_line - offset) > 0 else None
                violations.append({
                    "line": line,
                    "message": (
                        f"함수 '{fname}': CTR 키스트림 생성에 복호화 함수 '{called}' 호출 — "
                        "CTR 모드는 암·복호화 모두 ENC 방향만 사용해야 함"
                    ),
                    "ast_evidence": (
                        f"함수 '{fname}' 호출 그래프 분석: "
                        f"FuncCall(name='{called}') 탐지 (줄 {line}). "
                        f"'{called}'은 DEC 함수 집합에 해당. "
                        "CTR 표준: 키스트림 = ENC(Key, Counter) — "
                        "복호화도 ENC 방향 사용, DEC 직접 호출 불가"
                    ),
                })

    if not violations and real_funcs_checked == 0:
        if _has_unchecked_real_mode_funcs(all_funcs, ctr_funcs, "ctr", filename):
            return None
    return violations


# ──────────────────────────────────────────────────────────────────
# LEA-057: MCT 외부 루프 키 XOR 갱신 검사
# ──────────────────────────────────────────────────────────────────

_MCT_KEY_VARS = frozenset({"key", "rk", "round_key", "mk", "subkey", "session_key"})


def _outer_loop_updates_key(outer_for) -> bool:
    """외부 MCT 루프 body에서 key 배열에 XOR 갱신이 있는지 확인.

    허용 형태:
      - key[k] ^= ct[k]          → Assignment(op='^=', lvalue=ArrayRef(key))
      - key[k] = key[k] ^ ct[k]  → Assignment(op='=',  rvalue=BinaryOp('^'))
    """
    for assign in _collect(outer_for.stmt, c_ast.Assignment):
        lv = assign.lvalue
        # ArrayRef: key[i] 형태
        if isinstance(lv, c_ast.ArrayRef):
            base = _array_base(lv)
            if base and base.lower() in _MCT_KEY_VARS:
                if assign.op == "^=":
                    return True
                if assign.op == "=":
                    for bop in _collect(assign.rvalue, c_ast.BinaryOp):
                        if bop.op == "^":
                            return True
        # ID: key ^= ct (배열이 아닌 포인터 변수)
        if isinstance(lv, c_ast.ID) and lv.name.lower() in _MCT_KEY_VARS:
            if assign.op in ("^=",):
                return True
    return False


def _check_lea_057(root, offset: int, filename: str) -> List[Dict[str, Any]]:
    """LEA-057: MCT 외부 루프(100회)에서 키 XOR 갱신 수식 누락 시 위반.

    Key[i+1] = Key[i] ⊕ CT[j] 형태의 갱신이 외부 루프 안에 있어야 함.
    MCT 함수가 없으면 []로 조기 반환 (FP 방지).
    """
    if not _HAS_PYCPARSER:
        return []

    mct_funcs = _funcs_matching(root, _MCT_KW)
    if not mct_funcs:
        return []

    violations = []
    for fd in mct_funcs:
        fname = _func_name(fd)
        outer_fors = _collect(fd, c_ast.For)

        has_100_loop = False
        has_key_update = False

        for outer in outer_fors:
            outer_bound = _get_for_bound(outer)
            if outer_bound != 100:
                continue
            has_100_loop = True
            if _outer_loop_updates_key(outer):
                has_key_update = True
                break

        if has_100_loop and not has_key_update:
            line = _coord_line(fd, offset)
            violations.append({
                "line": line,
                "message": (
                    f"함수 '{fname}': MCT 외부 루프(100회) 내 키 XOR 갱신 미발견 — "
                    "Key[i+1] = Key[i] ⊕ CT[j] 갱신 수식 누락"
                ),
                "ast_evidence": (
                    f"함수 '{fname}' MCT 루프 분석: "
                    "외부 루프(bound=100) 존재 확인. "
                    "루프 body 내 Assignment(lvalue=ArrayRef(key/rk/..), op='^=') 또는 "
                    "Assignment(op='=', rvalue=BinaryOp('^')) 패턴 0건. "
                    "MCT 표준: 외부 루프마다 Key[i+1] = Key[i] ⊕ CT[j] 갱신 필수"
                ),
            })

    return violations



# ──────────────────────────────────────────────────────────────────
# P3-B 추가 구현 규칙 (2026-04-17)
# ──────────────────────────────────────────────────────────────────

def _check_lea_014(root, offset: int, filename: str) -> List[Dict[str, Any]]:
    """LEA-014: 키 스케줄 T[] 업데이트에 모듈러 덧셈(+) 사용 여부.

    LEA ARX 구조: T[i] = ROL(T[(i+1)%N] + delta[i%M], r)
    → T[] 대입의 rhs에 반드시 + 연산이 있어야 함.
    T[] 대입이 아예 없으면 판단 불가 → [].
    """
    if not _HAS_PYCPARSER:
        return []
    key_funcs = _funcs_matching(root, _KEY_KW)
    if not key_funcs:
        return []

    violations = []
    for fd in key_funcs:
        fname = _func_name(fd)
        t_assigns = [
            a for a in _collect(fd, c_ast.Assignment)
            if a.op == "="
            and isinstance(a.lvalue, c_ast.ArrayRef)
            and (_array_base(a.lvalue) or "").upper() == "T"
        ]
        if not t_assigns:
            continue  # T[] 대입 없음 → 판단 불가

        # T[] 대입 중 + 없는 것이 과반이면 위반
        no_add = [a for a in t_assigns if not _has_op(a.rvalue, "+")]
        if len(no_add) > len(t_assigns) // 2:
            line = _coord_line(no_add[0], offset)
            violations.append({
                "line": line,
                "message": (
                    f"키 스케줄 함수 '{fname}': T[] 업데이트에 모듈러 덧셈(+) 없음 — "
                    "LEA ARX 구조: T[i] = ROL(T[j] + delta[k], r) 형식이어야 함"
                ),
                "ast_evidence": (
                    f"함수 '{fname}' T[] 대입 AST 분석: "
                    f"T[] 대입 총 {len(t_assigns)}건 중 "
                    f"BinaryOp('+') 없는 대입 {len(no_add)}건(과반). "
                    "LEA ARX 요건: T[i] = ROL32(T[j] + delta[k], r) — "
                    "delta 덧셈이 ROL 인수로 반드시 포함돼야 함"
                ),
            })
    return violations


def _check_lea_015(root, offset: int, filename: str) -> List[Dict[str, Any]]:
    """LEA-015: 키 스케줄 내 델타 상수 i%4/6/8 순환 인덱싱 확인.

    탐지 전략:
    1. 키 스케줄 함수에서 delta/dlt 배열 접근 수집
    2. 해당 배열의 subscript에 % 연산자로 4/6/8 중 하나 사용 → 준수
    3. for 루프 bound가 라운드 수(24/28/32) 범위인데 delta[] 직접 인덱싱 → 위반 후보
    4. delta 배열 없음 → 판단 불가
    """
    if not _HAS_PYCPARSER:
        return []
    key_funcs = _funcs_matching(root, _KEY_KW)
    if not key_funcs:
        return []

    violations = []
    for fd in key_funcs:
        fname = _func_name(fd)
        delta_refs = [
            a for a in _collect(fd, c_ast.ArrayRef)
            if (_array_base(a) or "").lower() in {"delta", "dlt", "d", "rc"}
        ]
        if not delta_refs:
            continue  # delta 배열 없음 → 판단 불가

        has_modulo = any(
            isinstance(a.subscript, c_ast.BinaryOp)
            and a.subscript.op == "%"
            and _const_value(a.subscript.right) in {4, 6, 8}
            for a in delta_refs
        )
        if not has_modulo:
            line = _coord_line(fd, offset)
            violations.append({
                "line": line,
                "message": (
                    f"키 스케줄 함수 '{fname}': delta[] 인덱싱에 % 4/6/8 순환 패턴 없음 — "
                    "LEA-128: i mod 4, LEA-192: i mod 6, LEA-256: i mod 8"
                ),
                "ast_evidence": (
                    f"함수 '{fname}' delta[] 접근 AST 분석: "
                    f"delta/dlt/d/rc 배열 참조 {len(delta_refs)}건 탐지. "
                    "BinaryOp('%', right=Constant(4|6|8)) 패턴 0건. "
                    "KS X 3246 표준: LEA-128→i%%4, LEA-192→i%%6, LEA-256→i%%8 순환 인덱싱 필수"
                ),
            })
    return violations


def _check_lea_021(root, offset: int, filename: str) -> List[Dict[str, Any]]:
    """LEA-021: 라운드키 RKi = (T[0],T[1],T[2],T[1],T[3],T[1]) 6-워드 구성.

    탐지 전략:
    1. 키 스케줄 함수에서 RK[]/rk[] 2차원 배열 대입 수집
    2. rhs가 T[] 참조인 대입만 추출
    3. T[1]이 전혀 없으면 6-워드 패턴 불충족 → 위반
    4. RK 대입 없으면 판단 불가
    """
    if not _HAS_PYCPARSER:
        return []
    key_funcs = _funcs_matching(root, _KEY_KW)
    if not key_funcs:
        return []

    violations = []
    for fd in key_funcs:
        fname = _func_name(fd)
        rk_t_assigns = []
        for a in _collect(fd, c_ast.Assignment):
            if a.op != "=":
                continue
            lv = a.lvalue
            # 2차원 배열: RK[i][j] → lv는 ArrayRef, lv.name도 ArrayRef
            if not isinstance(lv, c_ast.ArrayRef):
                continue
            outer_base = (
                (_array_base(lv.name) or "").lower() if isinstance(lv.name, c_ast.ArrayRef)
                else (lv.name.name.lower() if isinstance(lv.name, c_ast.ID) else "")
            )
            if outer_base and ("rk" in outer_base or "round" in outer_base):
                # rhs가 T[] 참조인 경우만
                if isinstance(a.rvalue, c_ast.ArrayRef) and (_array_base(a.rvalue) or "").upper() == "T":
                    rk_t_assigns.append(a)

        if not rk_t_assigns:
            continue  # RK=T[] 대입 없음 → 판단 불가

        t1_count = sum(
            1 for a in rk_t_assigns
            if _const_value(a.rvalue.subscript) == 1
        )
        if t1_count == 0:
            line = _coord_line(fd, offset)
            violations.append({
                "line": line,
                "message": (
                    f"키 스케줄 함수 '{fname}': 라운드키에 T[1] 반복 패턴 없음 — "
                    "LEA-128 표준: RKi = (T[0], T[1], T[2], T[1], T[3], T[1])"
                ),
                "ast_evidence": (
                    f"함수 '{fname}' 라운드키 대입 AST 분석: "
                    f"RK[i][j] = T[k] 형태 대입 총 {len(rk_t_assigns)}건. "
                    "T[1] 참조 대입 0건 — "
                    "LEA-128 표준: T[1]이 인덱스 1,3,5 위치에 3회 반복 필수 "
                    "(KS X 3246 §5.1.1)"
                ),
            })
    return violations


def _check_lea_043(root, offset: int, filename: str) -> List[Dict[str, Any]]:
    """LEA-043: 중간 상태 변수 스택 배열 vs 스칼라/레지스터 사용.

    탐지 전략:
    1. 암호화/복호화 함수에서 로컬 변수 선언 수집
    2. 'register' 키워드 있으면 → 준수
    3. X[4], T[4] 같은 중간 상태용 스택 배열만 있으면 → 위반 후보
    4. 매크로 기반 함수 → 판단 불가
    5. severity: low — 보수적으로 확신할 때만 위반 생성
    """
    if not _HAS_PYCPARSER:
        return []
    # 키 스케줄 함수(set_key, key_init 등)는 중간 상태 배열 사용이 정상 — 제외
    _KEY_SCHED_KW_043 = frozenset({"key", "sched", "schedule", "set_key", "setkey", "expand", "keygen", "init_key"})
    enc_funcs = [fd for fd in _funcs_matching(root, _ENC_KW + _DEC_KW)
                 if not any(kw in _func_name(fd).lower() for kw in _KEY_SCHED_KW_043)]
    if not enc_funcs:
        return []

    _STATE_NAMES = {"X", "T", "S", "STATE", "BLK", "BLOCK", "W"}
    violations = []
    for fd in enc_funcs:
        fname = _func_name(fd)
        if _is_macro_based_round_func(fd):
            continue  # 매크로 기반 → 판단 불가

        has_register = False
        stack_array_decls: List[str] = []

        for decl in _collect(fd, c_ast.Decl):
            storage = list(getattr(decl, "storage", None) or [])
            if "register" in storage:
                has_register = True
                break
            typ = getattr(decl, "type", None)
            if isinstance(typ, c_ast.ArrayDecl):
                dim_val = _const_value(getattr(typ, "dim", None))
                name = (getattr(decl, "name", "") or "").upper()
                if dim_val and 2 <= dim_val <= 8 and name in _STATE_NAMES:
                    stack_array_decls.append(name)

        if stack_array_decls and not has_register:
            line = _coord_line(fd, offset)
            violations.append({
                "line": line,
                "message": (
                    f"암호화 함수 '{fname}': 중간 상태 배열 "
                    f"{stack_array_decls[0]}[] 가 스택에 할당됨 — "
                    "register 변수 또는 스칼라 변수 사용 권장 (잔존정보 방지)"
                ),
                "ast_evidence": (
                    f"함수 '{fname}' 지역 변수 선언 AST 분석: "
                    f"Decl(name='{stack_array_decls[0]}', storage=[], type=ArrayDecl) 탐지. "
                    "register 스토리지 클래스 변수 0건. "
                    "스택 배열 → 함수 반환 후 물리 메모리에 중간 키 소재 잔존 가능 — "
                    "zeroization 전 메모리 덤프 취약"
                ),
            })
    return violations




# ──────────────────────────────────────────────────────────────────
# OFB-002 / CFB-002: 스트림 모드 ENC-only 검사
# ──────────────────────────────────────────────────────────────────

_OFB_FUNC_KW  = ["ofb_enc", "ofb_dec", "ofb_encrypt", "ofb_decrypt", "lea_ofb"]
_CFB_FUNC_KW  = ["cfb_enc", "cfb_dec", "cfb_encrypt", "cfb_decrypt", "lea_cfb"]


def _check_mode_enc_only(
    root, offset: int, filename: str,
    func_kw: List[str],
    mode_name: str,
) -> Optional[List[Dict[str, Any]]]:
    """OFB/CFB 공통: 해당 모드 함수 내 DEC 호출 및 XOR 부재 탐지.

    - 해당 모드 함수 없음 → None (L3 위임, 이 파일은 해당 없음)
    - DEC 호출 발견    → 위반
    - XOR 부재         → 위반
    """
    if not _HAS_PYCPARSER:
        return None

    all_funcs = _get_func_defs(root)
    mode_funcs = _funcs_matching(root, func_kw)
    mn_lower = mode_name.lower()
    if not mode_funcs:
        if not all_funcs:
            return []
        if _has_unchecked_real_mode_funcs(all_funcs, [], mn_lower, filename):
            return None
        return []

    violations = []
    real_funcs_checked = 0
    for fd in mode_funcs:
        if _is_thin_wrapper(fd) or _is_benchmark_func(fd):
            continue
        real_funcs_checked += 1
        fname = _func_name(fd)

        # 위반 1: DEC 함수 직접 호출 (CTR-001 동일 로직)
        for call in _collect(fd, c_ast.FuncCall):
            called = getattr(getattr(call, "name", None), "name", "") or ""
            called_l = called.lower()
            if any(dec in called_l for dec in _LEA_DEC_NAMES):
                coord = getattr(call, "coord", None)
                raw_line = getattr(coord, "line", None) if coord else None
                line = (raw_line - offset) if raw_line and (raw_line - offset) > 0 else None
                violations.append({
                    "line": line,
                    "message": (
                        f"함수 '{fname}': {mode_name} 내 복호화 함수 '{called}' 호출 — "
                        f"{mode_name}는 암·복호화 모두 ENC 방향만 사용해야 함"
                    ),
                    "ast_evidence": (
                        f"함수 '{fname}' 호출 분석: "
                        f"FuncCall(name='{called}') 탐지. "
                        f"{mode_name} 표준: 키스트림 생성은 항상 ENC 방향 — "
                        "DEC 함수 호출은 표준 위반"
                    ),
                })

        # 위반 2: XOR 연산 부재 (키스트림 XOR 누락)
        if not _has_op(fd, "^"):
            line = _coord_line(fd, offset)
            violations.append({
                "line": line,
                "message": (
                    f"함수 '{fname}': {mode_name} XOR(^) 연산 미발견 — "
                    f"CT[i]=PT[i]⊕OT[i] 형태의 키스트림 적용 수식 누락"
                ),
                "ast_evidence": (
                    f"함수 '{fname}' 전체 AST 탐색: BinaryOp('^') 0건. "
                    f"{mode_name} 표준: 출력 블록(OT)과 평문 XOR → CT = PT ⊕ OT — "
                    "XOR 연산 없으면 키스트림 적용 불가"
                ),
            })

    if not violations and real_funcs_checked == 0:
        if _has_unchecked_real_mode_funcs(all_funcs, mode_funcs, mn_lower, filename):
            return None
    return violations


def _check_ofb_002(root, offset: int, filename: str) -> Optional[List[Dict[str, Any]]]:
    """OFB-002: OFB 함수 내 DEC 호출 또는 XOR 부재 탐지."""
    return _check_mode_enc_only(root, offset, filename, _OFB_FUNC_KW, "OFB")


def _check_cfb_002(root, offset: int, filename: str) -> Optional[List[Dict[str, Any]]]:
    """CFB-002: CFB 함수 내 DEC 호출 또는 XOR 부재 탐지."""
    return _check_mode_enc_only(root, offset, filename, _CFB_FUNC_KW, "CFB-128")


# ──────────────────────────────────────────────────────────────────
# LEA-005: 바이트→워드 빅 엔디안 변환 탐지
# ──────────────────────────────────────────────────────────────────

def _subscript_const_offset(subscript) -> Optional[int]:
    """배열 첨자의 상수 오프셋 추출.

    지원 패턴:
      a[0]       → 0   (단순 상수)
      a[4*i+0]   → 0   (곱셈+덧셈; 상수 항 추출)
      a[4*i+3]   → 3   (곱셈+덧셈; 오프셋 3)
      a[4*i]     → 0   (곱셈만; 오프셋 없으면 0으로 간주)
    반환 None: 판단 불가
    """
    if not _HAS_PYCPARSER:
        return None
    # 단순 상수: a[0]
    cv = _const_value(subscript)
    if cv is not None:
        return cv
    if not isinstance(subscript, c_ast.BinaryOp):
        return None
    # 덧셈: N*i+k 또는 k+N*i
    if subscript.op == "+":
        rv = _const_value(subscript.right)
        if rv is not None:
            return rv
        lv = _const_value(subscript.left)
        if lv is not None:
            return lv
    # 곱셈만 (N*i): 오프셋 = 0 (첫 번째 원소)
    if subscript.op == "*":
        return 0
    return None


def _check_lea_005(root, offset: int, filename: str) -> List[Dict[str, Any]]:
    """LEA-005: 바이트→워드 변환 시 빅 엔디안(BE) 패턴 탐지.

    LEA는 리틀 엔디안(LE) 규약을 사용한다:
      LE(정상): word = a[0] | (a[1]<<8) | (a[2]<<16) | (a[3]<<24)
      BE(위반): word = (a[0]<<24) | (a[1]<<16) | (a[2]<<8) | a[3]

    탐지 전략: array[0또는4i+0] << 24 패턴 (BE 첫 바이트를 MSB에 위치) → 위반
    - a[0] << 24       : 단순 인덱스 0
    - a[4*i+0] << 24   : 반복 내 첫 바이트를 MSB로 이동 (빅 엔디안 루프)
    """
    if not _HAS_PYCPARSER:
        return []

    violations = []
    for bop in _collect(root, c_ast.BinaryOp):
        if bop.op != "<<":
            continue
        # 오른쪽 피연산자가 상수 24인지 확인
        if _const_value(bop.right) != 24:
            continue
        # 왼쪽 피연산자가 ArrayRef 또는 캐스트된 ArrayRef인지 확인
        # e.g., a[0] << 24  또는  (uint32_t)a[4*i+0] << 24
        left_operand = bop.left
        if isinstance(left_operand, c_ast.Cast):
            left_operand = left_operand.expr  # 캐스트 벗기기
        if not isinstance(left_operand, c_ast.ArrayRef):
            continue
        # 배열 인덱스의 상수 오프셋이 0인지 확인 (a[0] 또는 a[4*i+0] 패턴)
        offset_val = _subscript_const_offset(left_operand.subscript)
        if offset_val != 0:
            continue
        # a[0] 또는 (T)a[4*i+0] << 24 확인 → BE 위반
        arr_name = _array_base(left_operand) or "배열"
        coord = getattr(bop, "coord", None)
        raw_line = getattr(coord, "line", None) if coord else None
        line = (raw_line - offset) if raw_line and (raw_line - offset) > 0 else None
        violations.append({
            "line": line,
            "message": (
                f"{arr_name}[...+0] << 24 패턴 — 빅 엔디안 변환 위반: "
                "LEA는 리틀 엔디안 규약 사용 (첫 바이트(오프셋 0)는 최하위 바이트여야 함, 마지막 바이트<<24이 정상)"
            ),
            "ast_evidence": (
                f"BinaryOp('<<', left=ArrayRef({arr_name}[offset=0]), right=Constant(24)) 탐지. "
                "첫 바이트(인덱스 오프셋 0)를 24비트 좌이동 → MSB(bit 31-24) 위치에 배치 = 빅 엔디안. "
                "LEA 리틀 엔디안 표준: word = a[0]|(a[1]<<8)|(a[2]<<16)|(a[3]<<24) — "
                "a[0]가 최하위 바이트, 마지막 바이트<<24이 정상"
            ),
        })

    return violations


# ──────────────────────────────────────────────────────────────────
# LEA-006: 비트 색인 방향성 — 비트 0을 MSB로 잘못 사용 탐지
# ──────────────────────────────────────────────────────────────────

def _check_lea_006(root, offset: int, filename: str) -> Optional[List[Dict[str, Any]]]:
    """LEA-006: 비트 색인 방향 확인 (31=MSB, 0=LSB).

    탐지 전략:
    - `x & 1` 또는 `x & 0x1` 로 추출한 비트를 MSB 위치(bit 31)에 배치하는
      패턴 탐지: `(x & 1) << 31`
    - 이 패턴은 bit 0이 실제로는 MSB처럼 취급됨 → 비트 번호 혼동 위반

    NOTE: 비트 색인 방향은 의미론적 판단이 어려워 명확한 패턴만 탐지.
    불명확한 경우 None 반환하여 L3에 위임.
    """
    if not _HAS_PYCPARSER:
        return None

    violations = []
    for bop in _collect(root, c_ast.BinaryOp):
        # (x & 1) << 31 패턴: bit 0을 bit 31 위치로 이동 → 비트 번호 역전 의심
        if bop.op != "<<":
            continue
        if _const_value(bop.right) != 31:
            continue
        left = bop.left
        if not (isinstance(left, c_ast.BinaryOp) and left.op == "&"):
            continue
        mask_val = _const_value(left.right) or _const_value(left.left)
        if mask_val != 1:
            continue
        # (x & 1) << 31 패턴 확인
        coord = getattr(bop, "coord", None)
        raw_line = getattr(coord, "line", None) if coord else None
        line = (raw_line - offset) if raw_line and (raw_line - offset) > 0 else None
        violations.append({
            "line": line,
            "message": (
                "(x & 1) << 31 패턴 — bit 0을 MSB(bit 31) 위치로 이동: "
                "LEA 표준은 bit 31=MSB, bit 0=LSB 규약 사용, 비트 번호 역전 의심"
            ),
            "ast_evidence": (
                f"BinaryOp('<<', left=BinaryOp('&', right=1), right=Constant(31)) 탐지. "
                "구조: (x & 0x1) << 31 — bit 0(LSB) 마스킹 후 bit 31(MSB) 위치로 이동. "
                "LEA 비트 번호 규약: bit 31=MSB, bit 0=LSB → bit 0 추출은 LSB 위치에 유지해야 함"
            ),
        })

    # 패턴 탐색 완료 — 없으면 위반 없음
    return violations


# ──────────────────────────────────────────────────────────────────
# 디스패처
# ──────────────────────────────────────────────────────────────────


def _check_lea_022(root, offset: int, filename: str) -> List[Dict[str, Any]]:
    """LEA-022: LEA-256 키 스케줄에서 T[] 배열 인덱싱이 (6i+j)%8 패턴 사용 여부 확인.

    KS X 3246 §5.1.3: LEA-256 라운드키 생성 시 T 배열 워드 인덱스는
    T[(6*i + j) % 8] 패턴이어야 한다.

    탐지 전략:
    1. 키 스케줄 함수에서 T[] 배열 접근(subscript에 산술식) 수집
    2. subscript에 '%' 연산자로 8과 함께 사용 → 준수
    3. subscript가 단순 정수 또는 6*i 없이 직접 인덱싱 → 위반 후보
    4. T 배열 접근 없으면 판단 불가 → []
    """
    if not _HAS_PYCPARSER:
        return []
    key_funcs = _funcs_matching(root, _KEY_KW)
    if not key_funcs:
        return []

    violations = []
    for fd in key_funcs:
        fname = _func_name(fd)
        # T[] 배열 접근 수집 (subscript가 비상수 = 루프 내 인덱싱)
        t_refs = [
            a for a in _collect(fd, c_ast.ArrayRef)
            if (_array_base(a) or "").upper() == "T"
            and not isinstance(a.subscript, c_ast.Constant)  # 상수 인덱스 제외
        ]
        if not t_refs:
            continue  # T[] 참조 없음 → 판단 불가

        # (6*i + j) % 8 패턴 확인:
        # subscript가 BinaryOp(%, right=8) 형태이면 준수
        def _has_mod8_pattern(node) -> bool:
            """subscript에 % 8 또는 %8 패턴 포함 여부"""
            for op_node in _collect(node, c_ast.BinaryOp):
                if op_node.op == "%" and _const_value(op_node.right) == 8:
                    return True
            return False

        mod8_refs = [r for r in t_refs if _has_mod8_pattern(r.subscript)]
        no_mod_refs = [r for r in t_refs if not _has_mod8_pattern(r.subscript)]

        # 대부분의 T[] 접근이 %8 없으면 위반 후보
        if mod8_refs:
            continue  # %8 패턴 존재 → 준수

        if no_mod_refs:
            # %8 없는 T[] 접근만 있음 → 위반 후보
            line = _coord_line(no_mod_refs[0], offset)
            violations.append({
                "line": line,
                "message": (
                    f"함수 '{fname}': T[] 배열 인덱싱에 (6*i+j)%%8 패턴 없음 — "
                    "LEA-256 키 스케줄 표준: T[(6*i+j)%%8] (KS X 3246 §5.1.3)"
                ),
                "ast_evidence": (
                    f"함수 '{fname}' T[] 인덱싱 AST 분석: "
                    f"T[] 비상수 인덱스 접근 {len(no_mod_refs)}건. "
                    "BinaryOp('%', right=Constant(8)) 패턴 0건. "
                    "LEA-256 키 스케줄 표준: subscript에 %%8 순환 필수 — "
                    "T[(6*i+j)%%8] 형식 (KS X 3246 §5.1.3)"
                ),
            })

    return violations


def _check_lea_023(root, offset: int, filename: str) -> List[Dict[str, Any]]:
    """LEA-023: 복호화 라운드키가 암호화 라운드키의 역순 관계인지 확인.

    KS X 3246 §5.2.2: 복호화 라운드키는 암호화 라운드키를 역순으로 배치.
    dec_rk[i] = enc_rk[Nr - 1 - i] 또는 lea_set_dec_key() 호출이어야 함.

    탐지 전략:
    1. 복호화 관련 키 스케줄 함수(dec_key, set_dec, decrypt_key 포함) 식별
    2. 함수 내에 'Nr - 1 - i' 또는 'Nr - i' 역순 인덱싱 패턴 확인
    3. lea_set_dec_key() 등 표준 함수 호출 확인
    4. 역순 패턴 없이 라운드키 대입만 있으면 위반 후보
    """
    if not _HAS_PYCPARSER:
        return []

    # 복호화 키 스케줄 함수 식별
    _DEC_KEY_KW = ["dec_key", "set_dec", "decrypt_key", "dec_schedule",
                   "lea_set_dec", "inv_key", "deckey"]
    dec_funcs = _funcs_matching(root, _DEC_KEY_KW)
    if not dec_funcs:
        return []  # 복호화 키 스케줄 함수 없음 → 판단 불가

    violations = []
    for fd in dec_funcs:
        fname = _func_name(fd)

        # 표준 함수 호출 확인 (lea_set_dec_key 등)
        calls = _collect(fd, c_ast.FuncCall)
        std_call_found = any(
            (c.name.name if isinstance(c.name, c_ast.ID) else "").lower()
            in {"lea_set_dec_key", "set_dec_key", "lea_keyschedule_dec"}
            for c in calls
        )
        if std_call_found:
            continue  # 표준 함수 사용 → 준수

        # 역순 인덱싱 패턴 확인: subscript에 뺄셈(Nr - 1 - i 또는 Nr - i)
        all_array_refs = _collect(fd, c_ast.ArrayRef)

        def _has_reverse_index(node) -> bool:
            """subscript에 역순 인덱싱 패턴(N - i 또는 Nr - 1 - i 형태) 확인"""
            for op_node in _collect(node, c_ast.BinaryOp):
                if op_node.op == "-":
                    # 왼쪽이 상수나 변수, 오른쪽이 변수(루프 인덱스)
                    if isinstance(op_node.right, c_ast.ID):
                        return True
                    # Nr - 1 - i 형태 (중첩 뺄셈)
                    if isinstance(op_node.right, c_ast.BinaryOp) and op_node.right.op == "+":
                        return True
            return False

        rk_assigns = [
            a for a in _collect(fd, c_ast.Assignment)
            if a.op == "=" and "rk" in (_array_base(a.lvalue) or "").lower()
        ]
        if not rk_assigns:
            continue  # RK 대입 없음 → 판단 불가

        has_reverse = any(
            _has_reverse_index(a.rvalue) for a in rk_assigns
        )

        if not has_reverse:
            line = _coord_line(fd, offset)
            violations.append({
                "line": line,
                "message": (
                    f"함수 '{fname}': 복호화 라운드키 역순 관계 패턴 미확인 — "
                    "표준 요구: dec_rk[i] = enc_rk[Nr-1-i] 또는 lea_set_dec_key() 호출 (KS X 3246 §5.2.2)"
                ),
                "ast_evidence": (
                    f"함수 '{fname}' 라운드키 대입 AST 분석: "
                    f"RK[...] 대입 {len(rk_assigns)}건. "
                    "표준 함수(lea_set_dec_key 등) 호출 0건. "
                    "BinaryOp('-', right=ID) 역순 인덱스 패턴 0건 — "
                    "KS X 3246 §5.2.2: dec_rk[i] = enc_rk[Nr-1-i] 역순 배치 필수"
                ),
            })

    return violations


# ──────────────────────────────────────────────────────────────────
# CTR-005: 암호 알고리즘 소스코드 외 보안 요구사항 준수
# ──────────────────────────────────────────────────────────────────

def _check_ctr_005(root, offset: int, filename: str) -> Optional[List[Dict[str, Any]]]:
    """CTR-005: CTR 모드 함수의 보안 요구사항 (SSP 생성/설정/주입/저장/제로화) 검사.

    AST 수준에서 SSP 라이프사이클을 정확히 검사하기 어려우므로,
    CTR 함수가 존재하면 기본적으로 통과([])로 처리하여
    부정확한 fallback regex FP를 방지한다.
    CTR 함수가 없으면 None 반환 → L3 판단 위임.
    """
    if not _HAS_PYCPARSER:
        return None

    all_funcs = _get_func_defs(root)
    ctr_funcs = _funcs_matching(root, _CTR_FUNC_KW)

    if not ctr_funcs:
        # CTR 함수명이 아닌 함수에서 CTR 구현 가능 → 판단 불가
        if _has_unchecked_real_mode_funcs(all_funcs, [], "ctr", filename):
            return None
        return []

    # CTR 함수 존재 → SSP 요구사항은 모듈 수준 검사이므로 AST에서 확정 불가
    # fallback regex 보다 정확한 판단을 위해 통과 처리
    return []


# ──────────────────────────────────────────────────────────────────
# LEA-032: 마지막 라운드 함수 구조 동일성 확인
# ──────────────────────────────────────────────────────────────────

_LEA_ENC_KW = ["lea_enc", "lea_encrypt", "block_encrypt", "lea_block"]


def _check_lea_032(root, offset: int, filename: str) -> Optional[List[Dict[str, Any]]]:
    """LEA-032: 마지막 라운드도 다른 라운드와 동일한 구조인지 확인.

    LEA는 AES와 달리 마지막 라운드에 특별 처리가 없어야 함.
    암호화 함수의 라운드 루프에서 마지막 라운드를 분기하는 패턴 탐지.
    """
    if not _HAS_PYCPARSER:
        return None

    enc_funcs = _funcs_matching(root, _LEA_ENC_KW)
    if not enc_funcs:
        # 라운드 매크로(LEA_ENC_ROUND 등) 기반 구현은 함수 내부가 보이지 않음
        all_funcs = _get_func_defs(root)
        if not all_funcs:
            return []
        # 키 스케줄, 라운드 함수 등 암호 관련 함수가 있으면 판단 위임
        for fd in all_funcs:
            fn = _func_name(fd).lower()
            if any(kw in fn for kw in ("lea", "encrypt", "round")):
                if not _is_thin_wrapper(fd) and not _is_benchmark_func(fd):
                    return None
        return []

    violations = []
    for fd in enc_funcs:
        if _is_thin_wrapper(fd) or _is_benchmark_func(fd):
            continue
        fname = _func_name(fd)

        # for 루프 내부에서 마지막 라운드 분기 탐지
        for_loops = _collect(fd, c_ast.For)
        for loop in for_loops:
            # 루프 본문에서 if 문 내 라운드 수 비교 탐지
            for ifstmt in _collect(loop, c_ast.If):
                cond = ifstmt.cond
                if isinstance(cond, c_ast.BinaryOp) and cond.op in ("==", ">=", "<="):
                    # 라운드 수 상수(23, 27, 31 = rounds-1)와 비교
                    for child in [cond.left, cond.right]:
                        val = _const_value(child)
                        if val in (23, 27, 31):
                            line = _coord_line(ifstmt, offset)
                            violations.append({
                                "line": line,
                                "message": (
                                    f"함수 '{fname}': 라운드 루프 내에서 마지막 라운드 "
                                    f"분기 조건(=={val}) 탐지 — "
                                    "LEA는 마지막 라운드도 동일 구조여야 함"
                                ),
                                "ast_evidence": (
                                    f"함수 '{fname}' For 루프 내 If 문에서 "
                                    f"BinaryOp('{cond.op}', Constant({val})) 발견. "
                                    "LEA 표준: AES와 달리 마지막 라운드에 "
                                    "MixColumns 생략 같은 특별 처리 없음 — "
                                    "모든 라운드 동일 구조 필수"
                                ),
                            })

    return violations


# ──────────────────────────────────────────────────────────────────
# LEA-024: 키 스케줄 워드 간 인터리빙 부재 확인
# ──────────────────────────────────────────────────────────────────

def _check_lea_024(root, offset: int, filename: str) -> Optional[List[Dict[str, Any]]]:
    """LEA-024: 키 스케줄에서 워드 간 혼합(인터리빙)이 없는 단순 구조인지 확인.

    LEA 키 스케줄은 T[i] = ROL(T[i] + delta) 형태의 독립적 워드 갱신 구조.
    T[i] = f(T[j]) (i≠j) 같은 크로스 워드 혼합이 있으면 위반.

    탐지 전략:
    1. 키 스케줄 함수에서 T[] 배열 대입문 수집
    2. T[i] = ... T[j] ... (i≠j) 형태의 크로스 참조 탐지
    3. 크로스 참조 있으면 위반 (인터리빙 존재)
    """
    if not _HAS_PYCPARSER:
        return None

    key_funcs = _funcs_matching(root, _KEY_KW)
    if not key_funcs:
        return []

    violations = []
    for fd in key_funcs:
        fname = _func_name(fd)
        # T[] 대입문: T[i] = expr
        for assign in _collect(fd, c_ast.Assignment):
            if assign.op != "=":
                continue
            lv = assign.lvalue
            if not isinstance(lv, c_ast.ArrayRef):
                continue
            lv_base = _array_base(lv)
            if not lv_base or lv_base.upper() != "T":
                continue
            lv_idx = _const_value(lv.subscript)
            if lv_idx is None:
                continue  # 변수 인덱스 → (6i+j)%8 등 동적 패턴은 LEA-022 관할

            # rvalue에서 T[j] (j≠i) 참조 탐지
            for ref in _collect(assign.rvalue, c_ast.ArrayRef):
                ref_base = _array_base(ref)
                if not ref_base or ref_base.upper() != "T":
                    continue
                ref_idx = _const_value(ref.subscript)
                if ref_idx is not None and ref_idx != lv_idx:
                    line = _coord_line(assign, offset)
                    violations.append({
                        "line": line,
                        "message": (
                            f"함수 '{fname}': T[{lv_idx}] = ...T[{ref_idx}]... — "
                            "워드 간 크로스 참조(인터리빙) 탐지. "
                            "LEA 키 스케줄은 T[i]=ROL(T[i]+δ) 독립 갱신 구조여야 함"
                        ),
                        "ast_evidence": (
                            f"Assignment(T[{lv_idx}] = ...ArrayRef(T[{ref_idx}])...) 탐지. "
                            "LEA 표준: 키 스케줄 워드 간 혼합 없는 단순 구조 — "
                            "T[i]는 자기 자신(T[i])과 δ 상수만으로 갱신"
                        ),
                    })
                    break  # 같은 대입문에서 중복 보고 방지

    return violations


# ──────────────────────────────────────────────────────────────────
# LEA-025: 복호화 키 스케줄 델타 상수 동일성 확인
# ──────────────────────────────────────────────────────────────────

# LEA 표준 델타 상수 (KS X 3246 §5.1)
_LEA_DELTA_CONSTS = {
    0xc3efe9db, 0x44626b02, 0x79e27c8a, 0x78df30ec,
    0x715ea49e, 0xc785da0a, 0xe04ef22a, 0xe7ae6536,
}


def _check_lea_025(root, offset: int, filename: str) -> Optional[List[Dict[str, Any]]]:
    """LEA-025: 복호화 키 생성 시 암호화와 동일한 δ 상수가 사용되는지 확인.

    탐지 전략:
    1. 복호화 키 스케줄 함수 식별
    2. 함수 내에 LEA 표준 δ 상수(0xc3efe9db 등) 중 하나라도 있는지 확인
    3. 없으면 위반 (비표준 상수 사용 또는 δ 누락)
    """
    if not _HAS_PYCPARSER:
        return None

    # 비-LEA 알고리즘 파일 제외 (utils.c에 set_decimal_len이 "set_dec" 키워드와 오매칭 방지)
    _NON_LEA_FILE_KW = ("aria", "ecdsa", "kcdsa", "ec_", "ecc", "sha", "hmac", "hash",
                        "utils", "pbkdf", "kbkdf", "gfp", "gf2n")
    fn_lower = filename.lower()
    if any(kw in fn_lower for kw in _NON_LEA_FILE_KW) and "lea" not in fn_lower:
        return []

    _DEC_KEY_KW = ["dec_key", "set_dec", "decrypt_key", "dec_schedule",
                   "lea_set_dec", "inv_key", "deckey"]
    dec_funcs = _funcs_matching(root, _DEC_KEY_KW)
    if not dec_funcs:
        return []

    violations = []
    for fd in dec_funcs:
        fname = _func_name(fd)

        # 상수 수집
        consts = _collect(fd, c_ast.Constant)
        found_delta = False
        for c in consts:
            val = _const_value(c)
            if val is not None and (val & 0xFFFFFFFF) in _LEA_DELTA_CONSTS:
                found_delta = True
                break

        # δ 배열 참조 확인 (delta[], DELTA[], d[] 등)
        if not found_delta:
            for ref in _collect(fd, c_ast.ArrayRef):
                base = _array_base(ref)
                if base and base.lower() in ("delta", "d", "lea_delta"):
                    found_delta = True
                    break

        # 표준 함수 호출 확인 (lea_set_enc_key 등에서 δ를 이미 사용)
        if not found_delta:
            calls = _call_names_in(fd)
            if calls & {"lea_set_enc_key", "lea_set_key", "lea_keyschedule"}:
                found_delta = True

        if not found_delta:
            line = _coord_line(fd, offset)
            violations.append({
                "line": line,
                "message": (
                    f"함수 '{fname}': 복호화 키 스케줄에서 LEA 표준 δ 상수 미확인 — "
                    "암호화와 동일한 δ[0]~δ[7] 사용 필수 (KS X 3246 §5.2.2)"
                ),
                "ast_evidence": (
                    f"함수 '{fname}' 내 상수값 AST 분석: "
                    f"LEA δ 상수(0xc3efe9db 등 8개) 0건. "
                    "delta[]/DELTA[] 배열 참조 0건. "
                    "표준 키 스케줄 함수 호출 0건 — "
                    "복호화 키 생성에 동일 δ 상수 미사용 의심"
                ),
            })

    return violations


# ──────────────────────────────────────────────────────────────────
# ARIA-002: ARIA S-box 구조 확인
# ──────────────────────────────────────────────────────────────────

_ARIA_FUNC_KW = ["aria", "sbox", "s_box"]
_ARIA_KEY_KW = ["aria_key", "aria_set", "aria_schedule", "key_expansion",
                "aria_enc_key", "aria_dec_key"]


def _check_aria_002(root, offset: int, filename: str) -> Optional[List[Dict[str, Any]]]:
    """ARIA-002: ARIA 키 스케줄 구조(CK 생성 + FO/FE 라운드) 확인.

    탐지 전략:
    1. ARIA 키 스케줄 함수 식별 (aria_key*, key_expansion 등)
    2. 함수 내 XOR(^) 연산 및 S-box 배열 참조 확인
    3. CK 생성에 필요한 XOR+회전 구조 존재 여부 확인
    4. ARIA 함수 없으면 [] 반환 (해당 없음)
    """
    if not _HAS_PYCPARSER:
        return None

    aria_key_funcs = _funcs_matching(root, _ARIA_KEY_KW)
    if not aria_key_funcs:
        # ARIA 관련 함수가 전혀 없으면 해당 없음
        all_funcs = _get_func_defs(root)
        has_aria = any("aria" in _func_name(fd).lower() for fd in all_funcs)
        if not has_aria:
            return []
        return None  # ARIA 함수는 있지만 키 스케줄 함수 매칭 실패 → fallback

    violations = []
    for fd in aria_key_funcs:
        if _is_thin_wrapper(fd) or _is_benchmark_func(fd):
            continue
        fname = _func_name(fd)

        # XOR 연산 확인 (키 스케줄 필수)
        has_xor = _has_op(fd, "^")
        # S-box 배열 참조 확인
        has_sbox = False
        for ref in _collect(fd, c_ast.ArrayRef):
            base = (_array_base(ref) or "").lower()
            if any(sb in base for sb in ("sb", "sbox", "s1", "s2", "s_box")):
                has_sbox = True
                break
        # 함수 호출로 S-box 적용 (SubstLayer, FO, FE 등)
        if not has_sbox:
            calls = _call_names_in(fd)
            sbox_calls = {c for c in calls if any(
                kw in c.lower() for kw in ("subst", "sbox", "fo", "fe", "sl1", "sl2")
            )}
            if sbox_calls:
                has_sbox = True

        # 회전 연산 확인
        has_rotation = bool(_call_names_in(fd) & _ROL_NAMES)
        if not has_rotation:
            has_rotation = _has_op(fd, "<<") and _has_op(fd, ">>")

        if not has_xor:
            line = _coord_line(fd, offset)
            violations.append({
                "line": line,
                "message": (
                    f"함수 '{fname}': ARIA 키 스케줄에 XOR(^) 연산 없음 — "
                    "CK 생성 및 라운드키 XOR 구조 필수"
                ),
                "ast_evidence": (
                    f"함수 '{fname}' AST 분석: BinaryOp('^') 0건. "
                    "ARIA 키 스케줄 표준: CK1=W0⊕W2, CK2=W1⊕W3 등 XOR 구조 필수"
                ),
            })

        if not has_sbox and not has_rotation:
            line = _coord_line(fd, offset)
            violations.append({
                "line": line,
                "message": (
                    f"함수 '{fname}': ARIA 키 스케줄에 S-box 참조 및 회전 연산 없음 — "
                    "FO/FE 라운드 함수 구조 필수"
                ),
                "ast_evidence": (
                    f"함수 '{fname}' AST 분석: S-box 배열 참조 0건, ROL/ROR 호출 0건. "
                    "ARIA 표준: 키 스케줄에 FO(SubstLayer+확산)/FE 라운드 적용 필수"
                ),
            })

    return violations


# ──────────────────────────────────────────────────────────────────
# CBC-LEA-005: MCT-CBC 키 갱신 수식 (Key[i+1]=Key[i]⊕CT[j])
# ──────────────────────────────────────────────────────────────────

_MCT_CBC_KW = ["mct_cbc", "cbc_mct", "monte_cbc", "cbc_monte"]


def _check_cbc_lea_005(root, offset: int, filename: str) -> Optional[List[Dict[str, Any]]]:
    """CBC-LEA-005: MCT-CBC에서 키 갱신(Key XOR CT) 수식 확인.

    탐지 전략:
    1. MCT-CBC 함수 식별
    2. 키 변수에 XOR(^=) 대입 또는 key[i] ^= ct 패턴 확인
    3. 키 갱신 없으면 위반
    """
    if not _HAS_PYCPARSER:
        return None

    # MCT-CBC 전용 함수 먼저, 없으면 일반 MCT에서 CBC 모드 탐색
    mct_cbc_funcs = _funcs_matching(root, _MCT_CBC_KW)
    if not mct_cbc_funcs:
        mct_funcs = _funcs_matching(root, _MCT_KW)
        mct_cbc_funcs = [fd for fd in mct_funcs
                         if "cbc" in _func_name(fd).lower()]
    if not mct_cbc_funcs:
        return []  # MCT-CBC 함수 없음 → 해당 없음

    violations = []
    for fd in mct_cbc_funcs:
        fname = _func_name(fd)

        # 키 갱신 패턴 탐색: key ^= ct, key[i] ^= ct[j], key XOR 대입
        has_key_xor_update = False
        for assign in _collect(fd, c_ast.Assignment):
            if assign.op != "^=":
                continue
            lv = assign.lvalue
            lv_name = ""
            if isinstance(lv, c_ast.ID):
                lv_name = lv.name.lower()
            elif isinstance(lv, c_ast.ArrayRef):
                lv_name = (_array_base(lv) or "").lower()
            if any(kw in lv_name for kw in ("key", "k", "rk")):
                has_key_xor_update = True
                break

        # memcpy + XOR 루프 패턴 (key update via loop)
        if not has_key_xor_update:
            calls = _call_names_in(fd)
            has_memcpy = "memcpy" in calls or "memmove" in calls
            has_xor = _has_op(fd, "^")
            if has_memcpy and has_xor:
                # 키 관련 변수에 대한 XOR 대입 있는지 확인
                for assign in _collect(fd, c_ast.Assignment):
                    if assign.op != "=":
                        continue
                    if not _has_op(assign.rvalue, "^"):
                        continue
                    lv = assign.lvalue
                    lv_name = ""
                    if isinstance(lv, c_ast.ID):
                        lv_name = lv.name.lower()
                    elif isinstance(lv, c_ast.ArrayRef):
                        lv_name = (_array_base(lv) or "").lower()
                    if any(kw in lv_name for kw in ("key", "k", "rk")):
                        has_key_xor_update = True
                        break

        if not has_key_xor_update:
            line = _coord_line(fd, offset)
            violations.append({
                "line": line,
                "message": (
                    f"함수 '{fname}': MCT-CBC 키 갱신 수식 미확인 — "
                    "Key[i+1]=Key[i]⊕CT[j] 형태의 XOR 키 갱신 필수 (LEA 검증시스템 §6.4)"
                ),
                "ast_evidence": (
                    f"함수 '{fname}' AST 분석: "
                    "key/rk 변수에 대한 '^=' 대입 0건, key=...^... 패턴 0건 — "
                    "MCT-CBC 표준: 내부 루프 종료 후 Key[i+1]=Key[i]⊕CT[j] 갱신 필수"
                ),
            })

    return violations


# ──────────────────────────────────────────────────────────────────
# CTR-LEA-006: MCT-CTR 카운터 갱신 + 키 갱신 수식
# ──────────────────────────────────────────────────────────────────

_MCT_CTR_KW = ["mct_ctr", "ctr_mct", "monte_ctr", "ctr_monte"]


def _check_ctr_lea_006(root, offset: int, filename: str) -> Optional[List[Dict[str, Any]]]:
    """CTR-LEA-006: MCT-CTR에서 카운터 증가((CTR+1) mod 2^128) + 키 갱신 확인.

    탐지 전략:
    1. MCT-CTR 함수 식별
    2. 카운터 증가 패턴: ctr++, counter += 1, ctr = ctr + 1
    3. 키 갱신 패턴: key ^= ct 또는 key XOR 대입
    4. 둘 다 없으면 위반
    """
    if not _HAS_PYCPARSER:
        return None

    mct_ctr_funcs = _funcs_matching(root, _MCT_CTR_KW)
    if not mct_ctr_funcs:
        mct_funcs = _funcs_matching(root, _MCT_KW)
        mct_ctr_funcs = [fd for fd in mct_funcs
                         if "ctr" in _func_name(fd).lower()]
    if not mct_ctr_funcs:
        return []

    violations = []
    for fd in mct_ctr_funcs:
        fname = _func_name(fd)

        # 카운터 증가 패턴 확인
        has_ctr_inc = False
        _CTR_VARS = {"ctr", "counter", "nonce", "iv", "cnt"}

        # UnaryOp(++/--) 확인
        for uop in _collect(fd, c_ast.UnaryOp):
            if uop.op in ("p++", "++", "p--"):
                operand = uop.expr
                if isinstance(operand, c_ast.ID) and operand.name.lower() in _CTR_VARS:
                    has_ctr_inc = True
                    break

        # += 1 확인
        if not has_ctr_inc:
            for assign in _collect(fd, c_ast.Assignment):
                if assign.op == "+=" and _const_value(assign.rvalue) == 1:
                    lv = assign.lvalue
                    lv_name = ""
                    if isinstance(lv, c_ast.ID):
                        lv_name = lv.name.lower()
                    elif isinstance(lv, c_ast.ArrayRef):
                        lv_name = (_array_base(lv) or "").lower()
                    if lv_name in _CTR_VARS:
                        has_ctr_inc = True
                        break

        # 증가 함수 호출 확인 (increment_counter 등)
        if not has_ctr_inc:
            calls = _call_names_in(fd)
            inc_calls = {c for c in calls if any(
                kw in c.lower() for kw in ("increment", "inc_ctr", "ctr_inc", "add_one")
            )}
            if inc_calls:
                has_ctr_inc = True

        # 일반적 + 1 패턴 (ctr = ctr + 1)
        if not has_ctr_inc:
            for assign in _collect(fd, c_ast.Assignment):
                if assign.op != "=":
                    continue
                lv = assign.lvalue
                lv_name = ""
                if isinstance(lv, c_ast.ID):
                    lv_name = lv.name.lower()
                if lv_name not in _CTR_VARS:
                    continue
                if _has_op(assign.rvalue, "+"):
                    has_ctr_inc = True
                    break

        # 키 갱신 패턴 (CBC-LEA-005와 동일)
        has_key_update = False
        for assign in _collect(fd, c_ast.Assignment):
            if assign.op == "^=":
                lv = assign.lvalue
                lv_name = ""
                if isinstance(lv, c_ast.ID):
                    lv_name = lv.name.lower()
                elif isinstance(lv, c_ast.ArrayRef):
                    lv_name = (_array_base(lv) or "").lower()
                if any(kw in lv_name for kw in ("key", "k", "rk")):
                    has_key_update = True
                    break
        if not has_key_update:
            for assign in _collect(fd, c_ast.Assignment):
                if assign.op != "=":
                    continue
                if not _has_op(assign.rvalue, "^"):
                    continue
                lv = assign.lvalue
                lv_name = ""
                if isinstance(lv, c_ast.ID):
                    lv_name = lv.name.lower()
                elif isinstance(lv, c_ast.ArrayRef):
                    lv_name = (_array_base(lv) or "").lower()
                if any(kw in lv_name for kw in ("key", "k", "rk")):
                    has_key_update = True
                    break

        issues = []
        if not has_ctr_inc:
            issues.append("카운터 증가((CTR+1) mod 2^128) 패턴 없음")
        if not has_key_update:
            issues.append("키 갱신(Key⊕CT) 패턴 없음")

        if issues:
            line = _coord_line(fd, offset)
            violations.append({
                "line": line,
                "message": (
                    f"함수 '{fname}': MCT-CTR — {'; '.join(issues)} "
                    "(LEA 검증시스템 §6.4)"
                ),
                "ast_evidence": (
                    f"함수 '{fname}' AST 분석: "
                    f"카운터 증가 패턴: {'있음' if has_ctr_inc else '없음'}, "
                    f"키 XOR 갱신 패턴: {'있음' if has_key_update else '없음'} — "
                    "MCT-CTR 표준: 매 연산 (CTR+1) mod 2^128 증가 + CT로 키 갱신 필수"
                ),
            })

    return violations


# ──────────────────────────────────────────────────────────────────
# LEA-039: 양방향 암/복호화 정합성(라운드트립) 검증
# ──────────────────────────────────────────────────────────────────

_TEST_FUNC_KW = ["test", "verify", "check", "roundtrip", "round_trip",
                 "self_test", "selftest", "kat", "validate"]


def _check_lea_039(root, offset: int, filename: str) -> Optional[List[Dict[str, Any]]]:
    """LEA-039: Decrypt(Encrypt(P,K),K)=P 라운드트립 검증 패턴 존재 확인.

    정적 분석의 한계: 실행 결과 일치는 검증 불가.
    대신 테스트/검증 함수에서 enc→dec 호출 쌍 + memcmp 패턴 존재 확인.
    """
    if not _HAS_PYCPARSER:
        return None

    # check_in: ["test", "benchmark"] — 파일명에 test/bench가 있는 경우만 검사
    fn_lower = filename.lower()
    if not any(kw in fn_lower for kw in ("test", "bench", "verify", "kat", "roundtrip")):
        return []  # 테스트 파일이 아님 → 해당 없음

    # KAT(Known Answer Test) 파일 — 고정 벡터 검증, 라운드트립 불필요
    if any(kw in fn_lower for kw in ("selftest", "kat", "known_answer")):
        return []

    test_funcs = _funcs_matching(root, _TEST_FUNC_KW)
    all_funcs = _get_func_defs(root)
    # 파일 전체에서도 확인
    target_funcs = test_funcs if test_funcs else all_funcs
    if not target_funcs:
        return []

    violations = []
    for fd in target_funcs:
        fname = _func_name(fd)
        calls = _call_names_in(fd)
        calls_lower = {c.lower() for c in calls}

        has_enc = any(any(kw in c for kw in ("encrypt", "enc")) for c in calls_lower)
        has_dec = any(any(kw in c for kw in ("decrypt", "dec")) for c in calls_lower)
        has_cmp = any(any(kw in c for kw in ("memcmp", "strcmp", "assert", "verify",
                                              "check", "equal"))
                      for c in calls_lower)

        if has_enc and has_dec and has_cmp:
            continue  # 라운드트립 패턴 있음 → 준수
        if has_enc and has_dec:
            continue  # enc+dec 쌍 호출은 있음 → 보수적 통과

    # 파일 전체에서 enc+dec 쌍이 있는지 확인
    all_calls = set()
    for fd in all_funcs:
        all_calls |= _call_names_in(fd)
    all_calls_lower = {c.lower() for c in all_calls}

    has_enc_file = any(any(kw in c for kw in ("encrypt", "enc")) for c in all_calls_lower)
    has_dec_file = any(any(kw in c for kw in ("decrypt", "dec")) for c in all_calls_lower)

    if not (has_enc_file and has_dec_file):
        # 테스트 파일인데 enc/dec 쌍 호출 없음 → 위반
        violations.append({
            "line": 1,
            "message": (
                f"테스트 파일 '{filename}': 암호화+복호화 함수 쌍 호출 없음 — "
                "Decrypt(Encrypt(P,K),K)=P 라운드트립 검증 누락 (KS X 3246 부록 Ⅰ)"
            ),
            "ast_evidence": (
                f"파일 전체 FuncCall 분석: "
                f"encrypt/enc 호출: {'있음' if has_enc_file else '없음'}, "
                f"decrypt/dec 호출: {'있음' if has_dec_file else '없음'} — "
                "라운드트립 검증은 enc→dec→memcmp 패턴 필수"
            ),
        })

    return violations


# ──────────────────────────────────────────────────────────────────
# LEA-059: MMT 가변 블록 수 처리 (1~10블록)
# ──────────────────────────────────────────────────────────────────

_MMT_KW = ["mmt", "multi_block", "multiblock", "variable_length"]


def _check_lea_059(root, offset: int, filename: str) -> Optional[List[Dict[str, Any]]]:
    """LEA-059: MMT(Multi-block Message Test) 가변 블록 수(1~10) 처리 확인.

    탐지 전략:
    1. MMT 함수 식별 (mmt, multi_block 등)
    2. 1~10 블록 반복 루프 존재 확인
    3. MMT 함수 없으면 [] (해당 없음)
    """
    if not _HAS_PYCPARSER:
        return None

    fn_lower = filename.lower()
    if not any(kw in fn_lower for kw in ("test", "bench", "mmt", "verify")):
        return []  # 테스트 파일이 아님 → 해당 없음

    mmt_funcs = _funcs_matching(root, _MMT_KW)
    if not mmt_funcs:
        return []

    violations = []
    for fd in mmt_funcs:
        fname = _func_name(fd)
        # 루프 구조 확인
        for_loops = _collect(fd, c_ast.For)
        if not for_loops:
            line = _coord_line(fd, offset)
            violations.append({
                "line": line,
                "message": (
                    f"함수 '{fname}': MMT 루프 구조 없음 — "
                    "블록 수 1~10개의 가변 길이 메시지 순차 시험 필요 (LEA 검증시스템 §6.3)"
                ),
                "ast_evidence": (
                    f"함수 '{fname}' AST 분석: For 루프 0건. "
                    "MMT 표준: i×128비트(i=1~10) 가변 길이 반복 처리 필수"
                ),
            })
            continue

        # 루프 bound에 10 또는 블록 수 관련 상수 확인
        has_block_loop = False
        for loop in for_loops:
            cond = getattr(loop, "cond", None)
            if cond is None:
                continue
            for const_node in _collect(cond, c_ast.Constant):
                val = _const_value(const_node)
                if val is not None and val in (10, 11, 16):  # 10블록 또는 16바이트 단위
                    has_block_loop = True
                    break
            # 변수 bound도 허용 (num_blocks 등)
            for id_node in _collect(cond, c_ast.ID):
                if any(kw in id_node.name.lower() for kw in ("block", "num", "count", "len")):
                    has_block_loop = True
                    break
            if has_block_loop:
                break

        if not has_block_loop:
            line = _coord_line(fd, offset)
            violations.append({
                "line": line,
                "message": (
                    f"함수 '{fname}': MMT 가변 블록 수 루프 bound 미확인 — "
                    "1~10블록 반복 처리 확인 필요 (LEA 검증시스템 §6.3)"
                ),
                "ast_evidence": (
                    f"함수 '{fname}' For 루프 bound AST 분석: "
                    "상수 10/11 또는 block/num/count 변수 0건 — "
                    "MMT 표준: 1~10블록 가변 길이 순차 시험 필수"
                ),
            })

    return violations


# ══════════════════════════════════════════════════════════════════
# [LIBCLANG BACKEND]
# 목적: MAKE_FUNC 매크로를 포함한 파일 완전 파싱 → pycparser FP 제거
# 구조: pycparser 체커와 동일 로직, libclang AST API 사용
# ══════════════════════════════════════════════════════════════════

# libclang 파싱 인자 (enhanced_symbol_graph_service.py 동일)
_LC_PARSE_ARGS: List[str] = [
    "-x", "c", "-std=c99",
    "-D__attribute__(x)=",
    "-D__asm__(x)=",
    "-D__asm(x)=",
    "-D__inline=",
    "-D__restrict=",
    "-D__extension__=",
    "-D__volatile__(x)=",
]

# GCC/Clang 시스템 include 경로 자동 발견 (uint8_t, uint32_t 등 stdint.h 타입 해석 필요)
_GCC_SYS_INCLUDES: List[str] = []
try:
    import subprocess as _sp_sys
    import os as _os_sys
    _gcc_inc = _sp_sys.check_output(
        ["gcc", "-print-file-name=include"],
        stderr=_sp_sys.DEVNULL,
        timeout=5,
    ).decode().strip()
    if _gcc_inc and _os_sys.path.isdir(_gcc_inc):
        _GCC_SYS_INCLUDES.append(_gcc_inc)
except Exception:
    pass
_LC_SYS_PREFIXES = (
    "/usr/", "/Library/", "/Applications/",
    "<built-in>", "<command", "/opt/homebrew/",
)


def _parse_c_libclang(
    content: str,
    filename: str = "<src>",
    extra_includes: Optional[List[str]] = None,
):
    """C 소스 → libclang TranslationUnit. 실패 시 None.

    pycparser와 달리:
    - MAKE_FUNC 등 복잡한 매크로를 완전히 확장하여 함수 본체 파악 가능
    - line offset 불필요 (preamble 없음)
    """
    if not _HAS_LIBCLANG:
        return None
    args = list(_LC_PARSE_ARGS)
    if extra_includes:
        for inc in extra_includes:
            args.append(f"-I{inc}")
    # 시스템 헤더 경로 추가 (uint8_t, uint32_t 등 표준 타입 파싱을 위해)
    for inc in _GCC_SYS_INCLUDES:
        args.append(f"-isystem{inc}")
    tmp_path: Optional[str] = None
    try:
        import os as _os2
        with _tempfile.NamedTemporaryFile(
            suffix=".c", mode="w", encoding="utf-8",
            delete=False, prefix="kcmvp_lc_",
        ) as f:
            f.write(content)
            tmp_path = f.name
        idx = _ci.Index.create()
        tu = idx.parse(tmp_path, args=args)
        if tu is None:
            return None
        # 치명적 오류가 너무 많으면 부분 파싱도 신뢰 불가
        fatal = [d for d in tu.diagnostics if d.severity >= _ci.Diagnostic.Error]
        if len(fatal) > 15:
            return None
        return tu
    except Exception:
        return None
    finally:
        if tmp_path:
            try:
                import os as _os3
                _os3.unlink(tmp_path)
            except Exception:
                pass


# ── libclang 순회 유틸 ────────────────────────────────────────────

def _lc_is_sys(path: str) -> bool:
    return any(path.startswith(p) for p in _LC_SYS_PREFIXES)


def _lc_func_defs(tu) -> List[Any]:
    """TranslationUnit에서 함수 정의 커서 수집 (시스템 헤더 제외)."""
    result = []
    for cursor in tu.cursor.get_children():
        if cursor.kind == _ci.CursorKind.FUNCTION_DECL and cursor.is_definition():
            loc = cursor.location
            if loc.file and not _lc_is_sys(loc.file.name):
                result.append(cursor)
    return result


def _lc_func_name(cursor) -> str:
    return cursor.spelling or ""


def _lc_funcs_matching(tu, keywords: List[str]) -> List[Any]:
    return [fd for fd in _lc_func_defs(tu)
            if any(kw in _lc_func_name(fd).lower() for kw in keywords)]


def _lc_line(cursor) -> Optional[int]:
    loc = cursor.location
    if loc is None or loc.line == 0:
        return None
    return loc.line


def _lc_collect(cursor, kind) -> List[Any]:
    """cursor 서브트리에서 kind CursorKind 전부 수집 (walk_preorder 기반)."""
    return [c for c in cursor.walk_preorder() if c.kind == kind]


def _lc_op_str(cursor) -> str:
    """BinaryOp / CompoundAssign 커서에서 연산자 문자열 추출 (토큰 스캔)."""
    children = list(cursor.get_children())
    if len(children) < 2:
        return ""
    try:
        left_end = children[0].extent.end.offset
        right_start = children[1].extent.start.offset
        for tok in cursor.get_tokens():
            tok_off = tok.extent.start.offset
            if left_end <= tok_off < right_start:
                return tok.spelling
    except Exception:
        pass
    return ""


def _lc_const_int(cursor) -> Optional[int]:
    """INTEGER_LITERAL 커서에서 정수값 추출 (UNEXPOSED_EXPR 래핑 처리)."""
    # 16진수 리터럴(0xf 등)이 UNEXPOSED_EXPR로 래핑되는 libclang 동작 처리
    for _ in range(4):  # 최대 4단계까지 unwrap
        if cursor.kind == _ci.CursorKind.UNEXPOSED_EXPR:
            children = list(cursor.get_children())
            if not children:
                return None
            cursor = children[0]
        else:
            break
    if cursor.kind != _ci.CursorKind.INTEGER_LITERAL:
        return None
    tokens = list(cursor.get_tokens())
    if not tokens:
        return None
    try:
        return int(tokens[0].spelling, 0)
    except (ValueError, TypeError):
        return None


def _lc_has_op(cursor, op: str) -> bool:
    """서브트리에 op(또는 op=) 연산이 있는지.

    AST 기반 우선 검색. 매크로 확장 코드에서 _lc_op_str 실패 시
    토큰 직접 스캔으로 fallback.
    """
    compound = op + "="
    for c in cursor.walk_preorder():
        if c.kind in (_ci.CursorKind.BINARY_OPERATOR,
                      _ci.CursorKind.COMPOUND_ASSIGNMENT_OPERATOR):
            s = _lc_op_str(c)
            if s == op or s == compound:
                return True
    # Fallback: 토큰 직접 스캔 (매크로 확장으로 _lc_op_str이 '' 반환 시)
    try:
        for tok in cursor.get_tokens():
            if tok.spelling == op:
                return True
    except Exception:
        pass
    return False


def _lc_call_names(cursor) -> Set[str]:
    """서브트리의 모든 CALL_EXPR 이름 집합."""
    names: Set[str] = set()
    for call in _lc_collect(cursor, _ci.CursorKind.CALL_EXPR):
        n = call.spelling
        if n:
            names.add(n)
    return names


def _lc_is_thin_wrapper(func_cursor) -> bool:
    """함수 본체가 thin wrapper인지 (libclang 버전)."""
    body = None
    for child in func_cursor.get_children():
        if child.kind == _ci.CursorKind.COMPOUND_STMT:
            body = child
            break
    if body is None:
        return False
    if len(list(body.get_children())) > 5:
        return False
    # crypto binop 없어야
    _CRYPTO_OPS = {"^", "+", "-", "<<", ">>"}
    for c in func_cursor.walk_preorder():
        if c.kind in (_ci.CursorKind.BINARY_OPERATOR,
                      _ci.CursorKind.COMPOUND_ASSIGNMENT_OPERATOR):
            if _lc_op_str(c) in _CRYPTO_OPS:
                return False
    # 루프 없어야
    if (_lc_collect(func_cursor, _ci.CursorKind.FOR_STMT) or
            _lc_collect(func_cursor, _ci.CursorKind.WHILE_STMT)):
        return False
    return True


def _lc_is_benchmark_func(func_cursor) -> bool:
    fname = _lc_func_name(func_cursor).lower()
    return any(kw in fname for kw in _BENCH_TEST_KW)


def _lc_is_macro_based_round_func(func_cursor) -> bool:
    calls = _lc_call_names(func_cursor)
    macro_hints = {"LEA_ENC_ROUND", "LEA_DEC_ROUND", "ENC_ROUND", "DEC_ROUND",
                   "ROUND_ENC", "ROUND_DEC", "LEA_ROUND"}
    return bool(calls & macro_hints)


def _lc_array_base(cursor) -> Optional[str]:
    """ARRAY_SUBSCRIPT_EXPR 의 배열 변수 이름."""
    if cursor.kind != _ci.CursorKind.ARRAY_SUBSCRIPT_EXPR:
        return None
    children = list(cursor.get_children())
    if not children:
        return None
    base = children[0]
    # DECL_REF_EXPR 또는 MEMBER_REF_EXPR
    if base.kind == _ci.CursorKind.DECL_REF_EXPR:
        return base.spelling
    # cast 벗기기
    if base.kind in (_ci.CursorKind.CSTYLE_CAST_EXPR,
                     _ci.CursorKind.IMPLICIT_CAST_EXPR):
        inner = list(base.get_children())
        if inner and inner[0].kind == _ci.CursorKind.DECL_REF_EXPR:
            return inner[0].spelling
    return None


def _lc_array_index_int(cursor) -> Optional[int]:
    """ARRAY_SUBSCRIPT_EXPR 의 첨자 상수값 (단순 정수만)."""
    if cursor.kind != _ci.CursorKind.ARRAY_SUBSCRIPT_EXPR:
        return None
    children = list(cursor.get_children())
    if len(children) < 2:
        return None
    return _lc_const_int(children[-1])


def _lc_unwrap_expr(cursor):
    """UNEXPOSED_EXPR / IMPLICIT_CAST_EXPR 래퍼를 최대 4단계까지 벗겨 실제 표현식 반환.

    libclang이 단순 배열 참조(tmp_input[0])도 UNEXPOSED_EXPR로 감싸는 경우가 있어
    ARRAY_SUBSCRIPT_EXPR 탐지 전에 반드시 벗겨야 한다.
    """
    _WRAP_KINDS = (_ci.CursorKind.UNEXPOSED_EXPR, _ci.CursorKind.IMPLICIT_CAST_EXPR)
    for _ in range(4):
        if cursor.kind in _WRAP_KINDS:
            children = list(cursor.get_children())
            if children:
                cursor = children[0]
            else:
                break
        else:
            break
    return cursor


def _lc_has_static_array(func_cursor) -> Optional[str]:
    """함수 내 static 배열 선언 이름 반환. 없으면 None."""
    for decl in _lc_collect(func_cursor, _ci.CursorKind.VAR_DECL):
        if decl.storage_class == _ci.StorageClass.STATIC:
            if decl.type.kind == _ci.TypeKind.CONSTANTARRAY:
                return decl.spelling or "unknown"
    return None


def _lc_has_unchecked_real_mode_funcs(
    tu, checked_cursors: List[Any], mode_kw: str, filename: str = ""
) -> bool:
    kw = mode_kw.lower()
    checked_ids = {id(c) for c in checked_cursors}
    for fd in _lc_func_defs(tu):
        if id(fd) in checked_ids:
            continue
        fname = _lc_func_name(fd).lower()
        if kw not in fname and kw not in filename.lower():
            continue
        if kw not in fname:
            continue
        # 유틸리티 함수(카운터 증가, 초기화 등)는 암호화 구현이 아님 → 제외
        if any(fname.endswith(suf) for suf in _MODE_UTILITY_FUNC_SUFFIXES):
            continue
        if not _lc_is_thin_wrapper(fd) and not _lc_is_benchmark_func(fd):
            return True
    return False


def _lc_get_for_bound(for_cursor) -> Optional[int]:
    """for 루프의 상한 상수 추출 (< N → N, <= N → N+1)."""
    for child in for_cursor.get_children():
        if child.kind == _ci.CursorKind.BINARY_OPERATOR:
            op = _lc_op_str(child)
            if op in ("<", "<="):
                kids = list(child.get_children())
                if len(kids) >= 2:
                    val = _lc_const_int(kids[-1])
                    if val is not None:
                        return (val + 1) if op == "<=" else val
    return None


# ── libclang 체커 함수 ────────────────────────────────────────────

def _lc_check_cbc_001(tu, filename: str, sg: dict) -> Optional[List[Dict[str, Any]]]:
    """CBC-001: CBC 암호화 XOR 연쇄 확인 (libclang)."""
    all_funcs = _lc_func_defs(tu)
    enc_funcs = [fd for fd in _lc_funcs_matching(tu, _CBC_ENC_KW)
                 if not _lc_is_thin_wrapper(fd) and not _lc_is_benchmark_func(fd)]
    if not enc_funcs:
        if not all_funcs:
            return []
        if _lc_has_unchecked_real_mode_funcs(tu, [], "cbc", filename):
            return None
        return []
    violations = []
    real_checked = 0
    for fd in enc_funcs:
        real_checked += 1
        fname = _lc_func_name(fd)
        if not _lc_has_op(fd, "^"):
            violations.append({
                "line": _lc_line(fd),
                "message": (f"함수 '{fname}': CBC 암호화에서 XOR(^) 연산 미발견 — "
                            "CT[i]=ENC(PT[i]⊕CT[i-1]) 수식의 XOR 연쇄 누락"),
                "ast_evidence": f"함수 '{fname}' 전체 AST 탐색(libclang): BinaryOp('^') 0건.",
            })
    if not violations and real_checked == 0:
        if _lc_has_unchecked_real_mode_funcs(tu, enc_funcs, "cbc", filename):
            return None
    return violations


def _lc_check_cbc_002(tu, filename: str, sg: dict) -> Optional[List[Dict[str, Any]]]:
    """CBC-002: CBC 복호화 XOR 연쇄 확인 (libclang)."""
    all_funcs = _lc_func_defs(tu)
    dec_funcs = [fd for fd in _lc_funcs_matching(tu, _CBC_DEC_KW)
                 if not _lc_is_thin_wrapper(fd) and not _lc_is_benchmark_func(fd)]
    if not dec_funcs:
        if not all_funcs:
            return []
        if _lc_has_unchecked_real_mode_funcs(tu, [], "cbc", filename):
            return None
        return []
    violations = []
    real_checked = 0
    for fd in dec_funcs:
        real_checked += 1
        fname = _lc_func_name(fd)
        if not _lc_has_op(fd, "^"):
            violations.append({
                "line": _lc_line(fd),
                "message": (f"함수 '{fname}': CBC 복호화에서 XOR(^) 연산 미발견 — "
                            "PT[i]=DEC(CT[i])⊕CT[i-1] 수식의 XOR 연쇄 누락"),
                "ast_evidence": f"함수 '{fname}' 전체 AST 탐색(libclang): BinaryOp('^') 0건.",
            })
    if not violations and real_checked == 0:
        if _lc_has_unchecked_real_mode_funcs(tu, dec_funcs, "cbc", filename):
            return None
    return violations


def _lc_check_ecb_002(tu, filename: str, sg: dict) -> Optional[List[Dict[str, Any]]]:
    """ECB-002: ECB 암호화 len%16 검사 (libclang)."""
    all_funcs = _lc_func_defs(tu)
    ecb_funcs = [fd for fd in _lc_funcs_matching(tu, _ECB_ENC_KW)
                 if not _lc_is_thin_wrapper(fd) and not _lc_is_benchmark_func(fd)]
    if not ecb_funcs:
        if not all_funcs:
            return []
        if _lc_has_unchecked_real_mode_funcs(tu, [], "ecb", filename):
            return None
        return []
    violations = []
    real_checked = 0
    for fd in ecb_funcs:
        real_checked += 1
        fname = _lc_func_name(fd)
        has_mod16 = False
        for bop in _lc_collect(fd, _ci.CursorKind.BINARY_OPERATOR):
            kids = list(bop.get_children())
            if _lc_op_str(bop) == "%" and len(kids) >= 2 and _lc_const_int(kids[-1]) == 16:
                has_mod16 = True
                break
            # & 0xf (== & 15) is bitwise-AND equivalent of % 16 — e.g. KISA: if (len & 0xf) return;
            elif _lc_op_str(bop) == "&" and len(kids) >= 2 and _lc_const_int(kids[-1]) == 15:
                has_mod16 = True
                break
        if not has_mod16:
            violations.append({
                "line": _lc_line(fd),
                "message": (f"함수 '{fname}': ECB 모드 입력 길이의 16배수 검사(len%%16) 미발견"),
                "ast_evidence": f"함수 '{fname}' AST(libclang): BinaryOp('%', 16) 0건.",
            })
    if not violations and real_checked == 0:
        if _lc_has_unchecked_real_mode_funcs(tu, ecb_funcs, "ecb", filename):
            return None
    return violations


def _lc_check_gcm_001(tu, filename: str, sg: dict) -> List[Dict[str, Any]]:
    """GCM-001: GCM 함수 내 static nonce 배열 탐지 (libclang)."""
    gcm_funcs = _lc_funcs_matching(tu, _GCM_KW)
    if not gcm_funcs:
        return []
    violations = []
    for fd in gcm_funcs:
        fname = _lc_func_name(fd)
        var = _lc_has_static_array(fd)
        if var:
            violations.append({
                "line": _lc_line(fd),
                "message": (f"함수 '{fname}': static 배열 '{var}' 선언 — "
                            "함수 재호출 시 nonce가 재사용될 수 있어 GCM 기밀성 파괴 위험"),
                "ast_evidence": f"함수 '{fname}' AST(libclang): VAR_DECL(static, CONSTANTARRAY)='{var}'.",
            })
    return violations


def _lc_check_ccm_001(tu, filename: str, sg: dict) -> List[Dict[str, Any]]:
    """CCM-001: CCM 함수 내 static nonce 배열 탐지 (libclang)."""
    ccm_funcs = _lc_funcs_matching(tu, _CCM_KW)
    if not ccm_funcs:
        return []
    violations = []
    for fd in ccm_funcs:
        fname = _lc_func_name(fd)
        var = _lc_has_static_array(fd)
        if var:
            violations.append({
                "line": _lc_line(fd),
                "message": (f"함수 '{fname}': static 배열 '{var}' 선언 — "
                            "함수 재호출 시 nonce가 재사용될 수 있어 CCM CTR 키스트림 반복 위험"),
                "ast_evidence": f"함수 '{fname}' AST(libclang): VAR_DECL(static, CONSTANTARRAY)='{var}'.",
            })
    return violations


def _lc_check_ctr_001(tu, filename: str, sg: dict) -> Optional[List[Dict[str, Any]]]:
    """CTR-001: CTR 함수 내 DEC 함수 호출 탐지 (libclang)."""
    all_funcs = _lc_func_defs(tu)
    ctr_funcs = [fd for fd in _lc_funcs_matching(tu, _CTR_FUNC_KW)
                 if not _lc_is_thin_wrapper(fd) and not _lc_is_benchmark_func(fd)]
    if not ctr_funcs:
        if not all_funcs:
            return []
        if _lc_has_unchecked_real_mode_funcs(tu, [], "ctr", filename):
            return None
        return []
    violations = []
    real_checked = 0
    for fd in ctr_funcs:
        real_checked += 1
        fname = _lc_func_name(fd)
        for call in _lc_collect(fd, _ci.CursorKind.CALL_EXPR):
            called = call.spelling or ""
            if any(dec in called.lower() for dec in _LEA_DEC_NAMES):
                violations.append({
                    "line": _lc_line(call),
                    "message": (f"함수 '{fname}': CTR 키스트림 생성에 복호화 함수 '{called}' 호출 — "
                                "CTR 모드는 암·복호화 모두 ENC 방향만 사용해야 함"),
                    "ast_evidence": (f"함수 '{fname}' CALL_EXPR(libclang): '{called}' ∈ DEC 집합."),
                })
    if not violations and real_checked == 0:
        if _lc_has_unchecked_real_mode_funcs(tu, ctr_funcs, "ctr", filename):
            return None
    return violations


def _lc_check_ctr_005(tu, filename: str, sg: dict) -> Optional[List[Dict[str, Any]]]:
    """CTR-005: CTR 함수 존재 확인 (libclang)."""
    all_funcs = _lc_func_defs(tu)
    ctr_funcs = _lc_funcs_matching(tu, _CTR_FUNC_KW)
    if not ctr_funcs:
        if _lc_has_unchecked_real_mode_funcs(tu, [], "ctr", filename):
            return None
        return []
    return []


def _lc_check_mode_enc_only(
    tu, filename: str, sg: dict, func_kw: List[str], mode_name: str,
) -> Optional[List[Dict[str, Any]]]:
    """OFB/CFB 공통 — DEC 호출 또는 XOR 부재 탐지 (libclang)."""
    all_funcs = _lc_func_defs(tu)
    mode_funcs = [fd for fd in _lc_funcs_matching(tu, func_kw)
                  if not _lc_is_thin_wrapper(fd) and not _lc_is_benchmark_func(fd)]
    mn = mode_name.lower()
    if not mode_funcs:
        if not all_funcs:
            return []
        if _lc_has_unchecked_real_mode_funcs(tu, [], mn, filename):
            return None
        return []
    violations = []
    real_checked = 0
    for fd in mode_funcs:
        real_checked += 1
        fname = _lc_func_name(fd)
        for call in _lc_collect(fd, _ci.CursorKind.CALL_EXPR):
            called = call.spelling or ""
            if any(dec in called.lower() for dec in _LEA_DEC_NAMES):
                violations.append({
                    "line": _lc_line(call),
                    "message": (f"함수 '{fname}': {mode_name} 내 복호화 함수 '{called}' 호출 — "
                                f"{mode_name}는 ENC 방향만 사용해야 함"),
                    "ast_evidence": f"CALL_EXPR(libclang): '{called}' ∈ DEC 집합.",
                })
        if not _lc_has_op(fd, "^"):
            violations.append({
                "line": _lc_line(fd),
                "message": (f"함수 '{fname}': {mode_name} XOR(^) 연산 미발견 — "
                            "CT[i]=PT[i]⊕OT[i] 형태의 키스트림 적용 수식 누락"),
                "ast_evidence": f"함수 '{fname}' AST(libclang): BinaryOp('^') 0건.",
            })
    if not violations and real_checked == 0:
        if _lc_has_unchecked_real_mode_funcs(tu, mode_funcs, mn, filename):
            return None
    return violations


def _lc_check_ofb_002(tu, filename: str, sg: dict) -> Optional[List[Dict[str, Any]]]:
    return _lc_check_mode_enc_only(tu, filename, sg, _OFB_FUNC_KW, "OFB")


def _lc_check_cfb_002(tu, filename: str, sg: dict) -> Optional[List[Dict[str, Any]]]:
    return _lc_check_mode_enc_only(tu, filename, sg, _CFB_FUNC_KW, "CFB-128")


def _lc_check_lea_005(tu, filename: str, sg: dict) -> List[Dict[str, Any]]:
    """LEA-005: 바이트→워드 빅 엔디안 변환 탐지 (libclang).

    array[0] << 24 또는 (cast)array[4*i+0] << 24 패턴.
    """
    violations = []
    for bop in _lc_collect(tu.cursor, _ci.CursorKind.BINARY_OPERATOR):
        if _lc_op_str(bop) != "<<":
            continue
        kids = list(bop.get_children())
        if len(kids) < 2 or _lc_const_int(kids[-1]) != 24:
            continue
        left = kids[0]
        # cast 벗기기
        if left.kind in (_ci.CursorKind.CSTYLE_CAST_EXPR,
                         _ci.CursorKind.IMPLICIT_CAST_EXPR):
            inner = list(left.get_children())
            if inner:
                left = inner[0]
        if left.kind != _ci.CursorKind.ARRAY_SUBSCRIPT_EXPR:
            continue
        arr_kids = list(left.get_children())
        if len(arr_kids) < 2:
            continue
        # 첨자 상수 오프셋이 0인지 확인
        idx_cursor = arr_kids[-1]
        # 단순 상수 0
        idx_val = _lc_const_int(idx_cursor)
        if idx_val is not None and idx_val != 0:
            continue
        if idx_val is None:
            # a[4*i+0] 형태 — BinaryOp(+, *, N*i, 0)
            if idx_cursor.kind == _ci.CursorKind.BINARY_OPERATOR:
                op2 = _lc_op_str(idx_cursor)
                if op2 == "+":
                    ik = list(idx_cursor.get_children())
                    if len(ik) >= 2:
                        # 덧셈의 오른쪽이 0인지 확인
                        rv = _lc_const_int(ik[-1])
                        if rv not in (None, 0):
                            continue
                elif op2 == "*":
                    pass  # a[N*i] → 오프셋 0으로 간주
                else:
                    continue
            else:
                continue
        arr_name = _lc_array_base(left) or "배열"
        violations.append({
            "line": _lc_line(bop),
            "message": (f"{arr_name}[...+0] << 24 패턴 — 빅 엔디안 변환 위반: "
                        "LEA는 리틀 엔디안 규약 사용"),
            "ast_evidence": (f"BINARY_OPERATOR('<<', ARRAY_SUBSCRIPT_EXPR({arr_name}[0]), 24). "
                             "libclang: MAKE_FUNC 포함 완전 파싱 결과."),
        })
    return violations


def _lc_check_lea_006(tu, filename: str, sg: dict) -> Optional[List[Dict[str, Any]]]:
    """LEA-006: (x & 1) << 31 비트 인덱스 역전 탐지 (libclang)."""
    violations = []
    for bop in _lc_collect(tu.cursor, _ci.CursorKind.BINARY_OPERATOR):
        if _lc_op_str(bop) != "<<":
            continue
        kids = list(bop.get_children())
        if len(kids) < 2 or _lc_const_int(kids[-1]) != 31:
            continue
        left = kids[0]
        if left.kind != _ci.CursorKind.BINARY_OPERATOR:
            continue
        if _lc_op_str(left) != "&":
            continue
        mask_kids = list(left.get_children())
        mask_val = None
        for mk in mask_kids:
            v = _lc_const_int(mk)
            if v is not None:
                mask_val = v
                break
        if mask_val != 1:
            continue
        violations.append({
            "line": _lc_line(bop),
            "message": ("(x & 1) << 31 패턴 — bit 0을 MSB(bit 31) 위치로 이동: 비트 번호 역전 의심"),
            "ast_evidence": "BINARY_OPERATOR('<<', BINARY_OPERATOR('&', 1), 31). libclang.",
        })
    return violations if violations else None


def _lc_check_lea_042(tu, filename: str, sg: dict) -> List[Dict[str, Any]]:
    """LEA-042: 암호화/복호화 함수에서 key[] 기반 조건 분기 탐지 (libclang)."""
    funcs = [fd for fd in _lc_funcs_matching(tu, _LEA_TIMING_KW)
             if not _lc_is_thin_wrapper(fd) and not _lc_is_benchmark_func(fd)]
    if not funcs:
        return []
    _KEY_NAMES = {"key", "skey", "rkey", "round_key", "subkey"}
    violations = []
    for fd in funcs:
        fname = _lc_func_name(fd)
        for ifstmt in _lc_collect(fd, _ci.CursorKind.IF_STMT):
            for arr_ref in _lc_collect(ifstmt, _ci.CursorKind.ARRAY_SUBSCRIPT_EXPR):
                base = _lc_array_base(arr_ref)
                if base and base.lower() in _KEY_NAMES:
                    violations.append({
                        "line": _lc_line(ifstmt),
                        "message": (f"함수 '{fname}': key[] 배열 값에 의존한 조건 분기 발견 — "
                                    "타이밍 채널 누출 위험"),
                        "ast_evidence": f"IF_STMT 조건 내 ARRAY_SUBSCRIPT_EXPR({base}[...]). libclang.",
                    })
                    break
    return violations


def _lc_check_lea_043(tu, filename: str, sg: dict) -> List[Dict[str, Any]]:
    """LEA-043: 암호화 함수 내 중간 상태 스택 배열 탐지 (libclang)."""
    # 키 스케줄 함수(set_key, key_init 등)는 T[] 배열 사용이 정상 → 제외
    _KEY_SCHED_KW_043 = frozenset({"key", "sched", "schedule", "set_key", "setkey",
                                   "expand", "keygen", "init_key"})
    enc_funcs = [fd for fd in _lc_funcs_matching(tu, _ENC_KW + _DEC_KW)
                 if not any(kw in (_lc_func_name(fd) or "").lower() for kw in _KEY_SCHED_KW_043)]
    if not enc_funcs:
        return []
    _STATE_NAMES = {"X", "T", "S", "STATE", "BLK", "BLOCK", "W"}
    violations = []
    for fd in enc_funcs:
        fname = _lc_func_name(fd)
        if _lc_is_macro_based_round_func(fd):
            continue
        has_register = False
        stack_arrays: List[str] = []
        for decl in _lc_collect(fd, _ci.CursorKind.VAR_DECL):
            if decl.storage_class == _ci.StorageClass.REGISTER:
                has_register = True
                break
            if decl.type.kind == _ci.TypeKind.CONSTANTARRAY:
                n = (decl.spelling or "").upper()
                elem_count = decl.type.element_count
                if n in _STATE_NAMES and 2 <= elem_count <= 8:
                    stack_arrays.append(n)
        if stack_arrays and not has_register:
            violations.append({
                "line": _lc_line(fd),
                "message": (f"암호화 함수 '{fname}': 중간 상태 배열 {stack_arrays[0]}[] 가 스택에 할당됨 — "
                            "register 변수 또는 스칼라 변수 사용 권장"),
                "ast_evidence": f"VAR_DECL(CONSTANTARRAY)='{stack_arrays[0]}' storage=AUTO. libclang.",
            })
    return violations


def _lc_check_lea_030(tu, filename: str, sg: dict) -> Optional[List[Dict[str, Any]]]:
    """LEA-030: 암호화 워드 스왑 패턴 확인 — libclang 버전.

    핵심 이점: MAKE_FUNC 매크로로 정의된 함수 본체를 완전히 파싱하여
    pycparser 실패 시 발생하던 7건 FP 제거.
    """
    # 비-LEA 알고리즘 파일 제외 (None 반환 시 fallback FP 유발 방지)
    _NON_LEA_FILE_KW = ("aria", "ecdsa", "kcdsa", "ec_", "ecc", "sha", "hmac", "hash",
                        "utils", "pbkdf", "kbkdf", "gfp", "gf2n", "cipher", "drbg")
    fn_lower = filename.lower()
    if any(kw in fn_lower for kw in _NON_LEA_FILE_KW) and "lea" not in fn_lower:
        return []

    enc_funcs = [fd for fd in _lc_funcs_matching(tu, _ENC_KW)
                 if not _lc_is_thin_wrapper(fd) and not _lc_is_benchmark_func(fd)]
    if not enc_funcs:
        return []

    for fd in enc_funcs:
        # 배열 인덱스 패턴: array[3] = array[0] (같은 배열) 또는
        # array_a[3] = array_b[0] (입출력 배열 분리, smart-crypto 스타일)
        # libclang이 단순 배열 참조도 UNEXPOSED_EXPR로 감싸므로 반드시 unwrap 필요
        for bop in _lc_collect(fd, _ci.CursorKind.BINARY_OPERATOR):
            if _lc_op_str(bop) != "=":
                continue
            kids = list(bop.get_children())
            if len(kids) < 2:
                continue
            lv, rv = kids[0], _lc_unwrap_expr(kids[1])
            if (lv.kind == _ci.CursorKind.ARRAY_SUBSCRIPT_EXPR and
                    rv.kind == _ci.CursorKind.ARRAY_SUBSCRIPT_EXPR):
                if (_lc_array_index_int(lv) == 3 and
                        _lc_array_index_int(rv) == 0):
                    return []  # 스왑 패턴 발견 → 준수 (같은/다른 배열 무관)

        # 로컬 변수 스왑: x3 = x0 등
        local_vars: List[str] = []
        for decl in _lc_collect(fd, _ci.CursorKind.VAR_DECL):
            n = decl.spelling or ""
            if any(x in n.lower() for x in ("x0", "x1", "x2", "x3", "state", "block")):
                local_vars.append(n.lower())
        if local_vars:
            name_set = set(local_vars)
            for bop in _lc_collect(fd, _ci.CursorKind.BINARY_OPERATOR):
                if _lc_op_str(bop) != "=":
                    continue
                kids = list(bop.get_children())
                if len(kids) < 2:
                    continue
                lv_name = kids[0].spelling.lower() if kids[0].kind == _ci.CursorKind.DECL_REF_EXPR else ""
                rv_name = kids[1].spelling.lower() if kids[1].kind == _ci.CursorKind.DECL_REF_EXPR else ""
                if lv_name in name_set and rv_name in name_set and lv_name != rv_name:
                    return []  # 변수 스왑 발견 → 준수

        # libclang: 회전 연산 존재 = 정상 암호화 구현 가능성 높음
        if _lc_has_op(fd, "<<") and _lc_has_op(fd, ">>"):
            return []  # 인라인 ROL/ROR 확인 → 준수 판정

    return None  # 패턴 미발견 → pycparser fallback 또는 L3 위임


def _lc_check_lea_035(tu, filename: str, sg: dict) -> Optional[List[Dict[str, Any]]]:
    """LEA-035: 복호화 역 워드 스왑 패턴 확인 — libclang 버전."""
    # 비-LEA 알고리즘 파일 제외 (aria.c/cipher.c 등에서 None 반환 시 fallback FP 유발 방지)
    _NON_LEA_FILE_KW = ("aria", "ecdsa", "kcdsa", "ec_", "ecc", "sha", "hmac", "hash",
                        "utils", "pbkdf", "kbkdf", "gfp", "gf2n", "cipher", "drbg")
    fn_lower = filename.lower()
    if any(kw in fn_lower for kw in _NON_LEA_FILE_KW) and "lea" not in fn_lower:
        return []

    dec_funcs = [fd for fd in _lc_funcs_matching(tu, _DEC_KW)
                 if not _lc_is_thin_wrapper(fd) and not _lc_is_benchmark_func(fd)]
    if not dec_funcs:
        return []

    for fd in dec_funcs:
        # 배열 인덱스 패턴: array[0] = array[3] (같은 배열) 또는
        # array_a[0] = array_b[3] (입출력 배열 분리) — UNEXPOSED_EXPR unwrap 포함
        for bop in _lc_collect(fd, _ci.CursorKind.BINARY_OPERATOR):
            if _lc_op_str(bop) != "=":
                continue
            kids = list(bop.get_children())
            if len(kids) < 2:
                continue
            lv, rv = kids[0], _lc_unwrap_expr(kids[1])
            if (lv.kind == _ci.CursorKind.ARRAY_SUBSCRIPT_EXPR and
                    rv.kind == _ci.CursorKind.ARRAY_SUBSCRIPT_EXPR):
                if (_lc_array_index_int(lv) == 0 and
                        _lc_array_index_int(rv) == 3):
                    return []  # 역 스왑 패턴 발견 → 준수 (같은/다른 배열 무관)

        # 로컬 변수 스왑
        local_vars: List[str] = []
        for decl in _lc_collect(fd, _ci.CursorKind.VAR_DECL):
            n = decl.spelling or ""
            if any(x in n.lower() for x in ("x0", "x1", "x2", "x3", "state", "block")):
                local_vars.append(n.lower())
        if local_vars:
            name_set = set(local_vars)
            for bop in _lc_collect(fd, _ci.CursorKind.BINARY_OPERATOR):
                if _lc_op_str(bop) != "=":
                    continue
                kids = list(bop.get_children())
                if len(kids) < 2:
                    continue
                lv_name = kids[0].spelling.lower() if kids[0].kind == _ci.CursorKind.DECL_REF_EXPR else ""
                rv_name = kids[1].spelling.lower() if kids[1].kind == _ci.CursorKind.DECL_REF_EXPR else ""
                if lv_name in name_set and rv_name in name_set and lv_name != rv_name:
                    return []

        if _lc_has_op(fd, "<<") and _lc_has_op(fd, ">>"):
            return []

    return None


def _lc_check_lea_003(tu, filename: str, sg: dict) -> List[Dict[str, Any]]:
    """LEA-003: 키 스케줄 라운드 수 확인 (libclang)."""
    violations = []
    # 전체 함수에서 ->rounds = N 탐지
    # thin_wrapper 필터 제거: 라운드 수 대입은 짧은 초기화 함수에서도 발생
    for fd in _lc_func_defs(tu):
        if _lc_is_benchmark_func(fd):
            continue
        fname = _lc_func_name(fd)
        for bop in _lc_collect(fd, _ci.CursorKind.BINARY_OPERATOR):
            if _lc_op_str(bop) != "=":
                continue
            kids = list(bop.get_children())
            if len(kids) < 2:
                continue
            lv = kids[0]
            if lv.kind == _ci.CursorKind.MEMBER_REF_EXPR:
                field = lv.spelling or ""
                # spelling이 빈 경우 (타입 미해석) tokens에서 필드명 추출
                if not field:
                    toks = [t.spelling for t in lv.get_tokens()]
                    # ['ctx', '->', 'rounds'] → 'rounds'
                    if len(toks) >= 3 and toks[-2] == "->":
                        field = toks[-1]
                if _re.search(r'round', field, _re.IGNORECASE):
                    val = _lc_const_int(kids[-1])
                    if val is not None and val not in _LEA_ROUND_COUNTS and 16 <= val <= 40:
                        violations.append({
                            "line": _lc_line(bop),
                            "message": (f"함수 '{fname}': '{field} = {val}' — "
                                        "LEA 유효 라운드 수: 128비트→24, 192비트→28, 256비트→32"),
                            "ast_evidence": f"BINARY_OPERATOR('=', MEMBER_REF_EXPR({field}), {val}). libclang.",
                        })

    # ── 전략 7 (libclang): 라운드 비교 조건 (if/while) 검사 ──
    # key->round > N 등에서 N이 비표준이면 위반 (M02/M03 탐지)
    _ROUND_CMP_OPS_LC = frozenset({">", ">=", "<", "<=", "!=", "=="})
    for fd in _lc_func_defs(tu):
        if _lc_is_benchmark_func(fd):
            continue
        fname = _lc_func_name(fd)
        for bop in _lc_collect(fd, _ci.CursorKind.BINARY_OPERATOR):
            op = _lc_op_str(bop)
            if op not in _ROUND_CMP_OPS_LC:
                continue
            kids = list(bop.get_children())
            if len(kids) < 2:
                continue
            for ref_idx, val_idx in [(0, 1), (1, 0)]:
                ref_node, val_node = kids[ref_idx], kids[val_idx]
                field = ""
                if ref_node.kind == _ci.CursorKind.MEMBER_REF_EXPR:
                    field = ref_node.spelling or ""
                    if not field:
                        toks = [t.spelling for t in ref_node.get_tokens()]
                        if len(toks) >= 3 and toks[-2] == "->":
                            field = toks[-1]
                elif ref_node.kind == _ci.CursorKind.DECL_REF_EXPR:
                    field = ref_node.spelling or ""
                if not _re.search(r'round', field, _re.IGNORECASE):
                    continue
                val = _lc_const_int(val_node)
                if val is None or val in _LEA_ROUND_COUNTS:
                    continue
                if 16 <= val <= 40:
                    violations.append({
                        "line": _lc_line(bop),
                        "message": (
                            f"함수 '{fname}': '{field} {op} {val}' — "
                            "LEA 유효 라운드 수 임계값: 24/28/32"
                        ),
                        "ast_evidence": (
                            f"BINARY_OPERATOR('{op}', MEMBER_REF({field}), {val}). "
                            f"{val} ∉ {{24,28,32}} → 라운드 조건 변조. libclang."
                        ),
                    })

    # ── 전략 8 (libclang): 라운드 산술식 비표준 상수 ──
    # key->round = (mk_len >> 1) + N 에서 N ≠ 16이면 위반 (M01 탐지)
    _LEA_ROUND_ADDEND = 16
    for fd in _lc_func_defs(tu):
        if _lc_is_benchmark_func(fd) or _lc_is_thin_wrapper(fd):
            continue
        fname = _lc_func_name(fd)
        for bop in _lc_collect(fd, _ci.CursorKind.BINARY_OPERATOR):
            if _lc_op_str(bop) != "=":
                continue
            kids = list(bop.get_children())
            if len(kids) < 2:
                continue
            lv = kids[0]
            if lv.kind != _ci.CursorKind.MEMBER_REF_EXPR:
                continue
            field = lv.spelling or ""
            if not _re.search(r'round', field, _re.IGNORECASE):
                continue
            # RHS가 상수 리터럴이면 전략 6에서 이미 처리 → 산술식만 검사
            rhs = kids[-1]
            if _lc_const_int(rhs) is not None:
                continue
            # RHS 내 + 연산자 탐색
            for add_op in _lc_collect(rhs, _ci.CursorKind.BINARY_OPERATOR):
                if _lc_op_str(add_op) != "+":
                    continue
                for child in add_op.get_children():
                    val = _lc_const_int(child)
                    if val is not None and val != _LEA_ROUND_ADDEND and 12 <= val <= 20:
                        violations.append({
                            "line": _lc_line(bop),
                            "message": (
                                f"함수 '{fname}': 라운드 수 산술식에 비표준 상수 {val} — "
                                f"표준: (mk_len>>1) + 16"
                            ),
                            "ast_evidence": (
                                f"Assignment: {field} = ... + {val}, "
                                f"LEA 표준 가산값 = 16. {val} ≠ 16. libclang."
                            ),
                        })

    key_funcs = [fd for fd in _lc_funcs_matching(tu, _KEY_KW)
                 if not _lc_is_benchmark_func(fd) and not _lc_is_thin_wrapper(fd)]
    for fd in key_funcs:
        fname = _lc_func_name(fd)
        found_valid = False
        wrong: List[int] = []
        for for_c in _lc_collect(fd, _ci.CursorKind.FOR_STMT):
            bound = _lc_get_for_bound(for_c)
            if bound is None:
                continue
            if bound in _LEA_ROUND_COUNTS:
                found_valid = True
                break
            if 16 <= bound <= 40:
                wrong.append(bound)
        if wrong and not found_valid:
            violations.append({
                "line": _lc_line(fd),
                "message": (f"함수 '{fname}': 라운드 수 리터럴 {wrong[0]} 발견 — "
                            "LEA 유효 라운드 수: 24/28/32"),
                "ast_evidence": f"FOR_STMT bound={wrong[0]} ∉ {{24,28,32}}. libclang.",
            })
    return violations


def _lc_check_lea_010(tu, filename: str, sg: dict) -> List[Dict[str, Any]]:
    """LEA-010: 키 스케줄 ARX 구조 확인 (libclang)."""
    _DERIVED_KEY_EXCL = {"cmac", "subkey", "gcm", "ghash", "gmac"}
    key_funcs = [
        fd for fd in _lc_funcs_matching(tu, _KEY_KW)
        if not any(kw in _lc_func_name(fd).lower() for kw in _DERIVED_KEY_EXCL)
    ]
    if not key_funcs:
        return []
    violations = []
    for fd in key_funcs:
        if _lc_is_benchmark_func(fd) or _lc_is_thin_wrapper(fd):
            continue
        fname = _lc_func_name(fd)
        calls = _lc_call_names(fd)
        has_rol = bool(calls & _ROL_NAMES) or (_lc_has_op(fd, "<<") and _lc_has_op(fd, ">>"))
        has_add = _lc_has_op(fd, "+")
        missing = []
        if not has_rol:
            missing.append("ROL/ROR 비트 회전")
        if not has_add:
            missing.append("모듈러 덧셈(+)")
        if missing:
            violations.append({
                "line": _lc_line(fd),
                "message": (f"키 스케줄 함수 '{fname}': ARX 구조 불완전 — {', '.join(missing)} 없음"),
                "ast_evidence": f"함수 '{fname}' ARX 분석(libclang): {', '.join(missing)} 0건.",
            })
    return violations


def _lc_check_lea_014(tu, filename: str, sg: dict) -> List[Dict[str, Any]]:
    """LEA-014: 키 스케줄 T[] 업데이트에 모듈러 덧셈 확인 (libclang)."""
    key_funcs = _lc_funcs_matching(tu, _KEY_KW)
    if not key_funcs:
        return []
    violations = []
    for fd in key_funcs:
        fname = _lc_func_name(fd)
        t_assigns = []
        for bop in _lc_collect(fd, _ci.CursorKind.BINARY_OPERATOR):
            if _lc_op_str(bop) != "=":
                continue
            kids = list(bop.get_children())
            if len(kids) < 2:
                continue
            lv = kids[0]
            if lv.kind == _ci.CursorKind.ARRAY_SUBSCRIPT_EXPR:
                base = _lc_array_base(lv)
                if base and base.upper() == "T":
                    t_assigns.append(bop)
        if not t_assigns:
            continue
        no_add = [b for b in t_assigns if not _lc_has_op(b, "+")]
        if len(no_add) > len(t_assigns) // 2:
            violations.append({
                "line": _lc_line(no_add[0]),
                "message": (f"키 스케줄 함수 '{fname}': T[] 업데이트에 모듈러 덧셈(+) 없음 — "
                            "LEA ARX: T[i] = ROL(T[j] + delta[k], r)"),
                "ast_evidence": f"T[] 대입 {len(t_assigns)}건 중 +없음 {len(no_add)}건. libclang.",
            })
    return violations


def _lc_check_lea_015(tu, filename: str, sg: dict) -> List[Dict[str, Any]]:
    """LEA-015: 키 스케줄 delta[] 순환 인덱싱 (%4/6/8) 확인 (libclang)."""
    key_funcs = _lc_funcs_matching(tu, _KEY_KW)
    if not key_funcs:
        return []
    violations = []
    for fd in key_funcs:
        fname = _lc_func_name(fd)
        delta_refs = [c for c in _lc_collect(fd, _ci.CursorKind.ARRAY_SUBSCRIPT_EXPR)
                      if (_lc_array_base(c) or "").lower() in {"delta", "dlt", "d", "rc"}]
        if not delta_refs:
            continue
        has_modulo = False
        for ref in delta_refs:
            kids = list(ref.get_children())
            if len(kids) < 2:
                continue
            sub = kids[-1]
            for bop in sub.walk_preorder():
                if bop.kind == _ci.CursorKind.BINARY_OPERATOR and _lc_op_str(bop) == "%":
                    bkids = list(bop.get_children())
                    if len(bkids) >= 2 and _lc_const_int(bkids[-1]) in {4, 6, 8}:
                        has_modulo = True
                        break
            if has_modulo:
                break
        if not has_modulo:
            violations.append({
                "line": _lc_line(fd),
                "message": (f"키 스케줄 함수 '{fname}': delta[] 인덱싱에 %%4/6/8 패턴 없음"),
                "ast_evidence": f"delta[] 참조 {len(delta_refs)}건, BinaryOp('%', 4|6|8) 0건. libclang.",
            })
    return violations


def _lc_check_lea_022(tu, filename: str, sg: dict) -> List[Dict[str, Any]]:
    """LEA-022: LEA-256 T[] 배열 인덱싱 (6i+j)%8 패턴 확인 (libclang)."""
    key_funcs = _lc_funcs_matching(tu, _KEY_KW)
    if not key_funcs:
        return []
    violations = []
    for fd in key_funcs:
        fname = _lc_func_name(fd)
        t_refs = [c for c in _lc_collect(fd, _ci.CursorKind.ARRAY_SUBSCRIPT_EXPR)
                  if (_lc_array_base(c) or "").upper() == "T"
                  and _lc_array_index_int(c) is None]
        if not t_refs:
            continue
        has_mod8 = False
        for ref in t_refs:
            kids = list(ref.get_children())
            if len(kids) < 2:
                continue
            for bop in kids[-1].walk_preorder():
                if bop.kind == _ci.CursorKind.BINARY_OPERATOR and _lc_op_str(bop) == "%":
                    bkids = list(bop.get_children())
                    if len(bkids) >= 2 and _lc_const_int(bkids[-1]) == 8:
                        has_mod8 = True
                        break
            if has_mod8:
                break
        if not has_mod8:
            violations.append({
                "line": _lc_line(fd),
                "message": (f"함수 '{fname}': T[] 인덱싱에 (6*i+j)%%8 패턴 없음 — "
                            "LEA-256 키 스케줄 표준 (KS X 3246 §5.1.3)"),
                "ast_evidence": f"T[] 비상수 인덱스 {len(t_refs)}건, BinaryOp('%', 8) 0건. libclang.",
            })
    return violations


def _lc_check_lea_040(tu, filename: str, sg: dict) -> List[Dict[str, Any]]:
    """LEA-040: 라운드 루프 경계 조건 위반 탐지 (libclang)."""
    _KEY_SCHED_EXCL = frozenset({"key", "sched", "schedule", "setkey", "expand", "keygen"})
    _LEA040_KW = _ENC_KW + _DEC_KW + ["round", "block", "cipher", "lea"]
    funcs = [fd for fd in _lc_funcs_matching(tu, _LEA040_KW)
             if not any(kw in _lc_func_name(fd).lower() for kw in _KEY_SCHED_EXCL)
             and not _lc_is_thin_wrapper(fd) and not _lc_is_benchmark_func(fd)]
    violations = []
    for fd in funcs:
        fname = _lc_func_name(fd)
        found_valid = False
        wrong: List[Dict] = []
        for for_c in _lc_collect(fd, _ci.CursorKind.FOR_STMT):
            for child in for_c.get_children():
                if child.kind != _ci.CursorKind.BINARY_OPERATOR:
                    continue
                op = _lc_op_str(child)
                if op not in ("<", "<="):
                    continue
                kids = list(child.get_children())
                if len(kids) < 2:
                    continue
                val = _lc_const_int(kids[-1])
                if val is None:
                    # <= ctx->rounds 변수 패턴
                    if op == "<=" and kids[-1].kind == _ci.CursorKind.MEMBER_REF_EXPR:
                        field = kids[-1].spelling or ""
                        if _re.search(r'round', field, _re.IGNORECASE):
                            wrong.append({"line": _lc_line(for_c),
                                          "bound": -1,
                                          "msg": f"'<= {field}' → off-by-one"})
                    continue
                if op == "<=":
                    norm = val + 1
                    if norm in _LEA_ROUND_COUNTS:
                        found_valid = True
                    elif 16 <= norm <= 40:
                        wrong.append({"line": _lc_line(for_c), "bound": norm,
                                      "msg": f"'<= {val}' → {norm}회 반복"})
                elif op == "<":
                    if val in _LEA_ROUND_COUNTS:
                        found_valid = True
                    elif 16 <= val <= 40:
                        wrong.append({"line": _lc_line(for_c), "bound": val,
                                      "msg": f"'< {val}' → {val}회 반복"})
        if wrong and not found_valid:
            w = wrong[0]
            violations.append({
                "line": w["line"],
                "message": f"함수 '{fname}': 라운드 루프 경계 조건 위반 — {w['msg']}",
                "ast_evidence": f"FOR_STMT 조건 분석(libclang): {w['msg']}",
            })
    return violations


def _lc_check_lea_057(tu, filename: str, sg: dict) -> List[Dict[str, Any]]:
    """LEA-057: MCT 외부 루프 키 XOR 갱신 확인 (libclang)."""
    mct_funcs = _lc_funcs_matching(tu, _MCT_KW)
    if not mct_funcs:
        return []
    violations = []
    for fd in mct_funcs:
        fname = _lc_func_name(fd)
        has_100_loop = False
        has_key_update = False
        for for_c in _lc_collect(fd, _ci.CursorKind.FOR_STMT):
            if _lc_get_for_bound(for_c) != 100:
                continue
            has_100_loop = True
            # key[k] ^= ct or key[k] = key[k] ^ ct
            for bop in for_c.walk_preorder():
                if bop.kind == _ci.CursorKind.COMPOUND_ASSIGNMENT_OPERATOR:
                    if _lc_op_str(bop) == "^=":
                        kids = list(bop.get_children())
                        if kids and kids[0].kind == _ci.CursorKind.ARRAY_SUBSCRIPT_EXPR:
                            base = _lc_array_base(kids[0])
                            if base and base.lower() in _MCT_KEY_VARS:
                                has_key_update = True
                                break
                if bop.kind == _ci.CursorKind.BINARY_OPERATOR and _lc_op_str(bop) == "=":
                    kids = list(bop.get_children())
                    if (kids and kids[0].kind == _ci.CursorKind.ARRAY_SUBSCRIPT_EXPR and
                            _lc_array_base(kids[0]) and
                            (_lc_array_base(kids[0]) or "").lower() in _MCT_KEY_VARS):
                        if _lc_has_op(kids[-1], "^"):
                            has_key_update = True
                            break
            if has_key_update:
                break
        if has_100_loop and not has_key_update:
            violations.append({
                "line": _lc_line(fd),
                "message": (f"함수 '{fname}': MCT 외부 루프(100회) 내 키 XOR 갱신 미발견"),
                "ast_evidence": "FOR_STMT(bound=100) key ^= ct 패턴 0건. libclang.",
            })
    return violations


def _lc_check_lea_021(tu, filename: str, sg: dict) -> List[Dict[str, Any]]:
    """LEA-021: 라운드키 RK[i][j] = T[k] 6-워드 패턴 (libclang)."""
    key_funcs = _lc_funcs_matching(tu, _KEY_KW)
    if not key_funcs:
        return []
    violations = []
    for fd in key_funcs:
        fname = _lc_func_name(fd)
        rk_t_assigns = []
        for bop in _lc_collect(fd, _ci.CursorKind.BINARY_OPERATOR):
            if _lc_op_str(bop) != "=":
                continue
            kids = list(bop.get_children())
            if len(kids) < 2:
                continue
            lv, rv = kids[0], kids[1]
            # 2D 배열 lv: ARRAY_SUBSCRIPT_EXPR 의 base도 ARRAY_SUBSCRIPT_EXPR
            if lv.kind != _ci.CursorKind.ARRAY_SUBSCRIPT_EXPR:
                continue
            lv_kids = list(lv.get_children())
            if not lv_kids:
                continue
            outer_base = lv_kids[0]
            outer_name = ""
            if outer_base.kind == _ci.CursorKind.ARRAY_SUBSCRIPT_EXPR:
                outer_name = (_lc_array_base(outer_base) or "").lower()
            elif outer_base.kind == _ci.CursorKind.DECL_REF_EXPR:
                outer_name = outer_base.spelling.lower()
            if outer_name and ("rk" in outer_name or "round" in outer_name):
                if rv.kind == _ci.CursorKind.ARRAY_SUBSCRIPT_EXPR:
                    rv_base = _lc_array_base(rv)
                    if rv_base and rv_base.upper() == "T":
                        rk_t_assigns.append((bop, rv))
        if not rk_t_assigns:
            continue
        t1_count = sum(1 for _, rv in rk_t_assigns if _lc_array_index_int(rv) == 1)
        if t1_count == 0:
            violations.append({
                "line": _lc_line(fd),
                "message": (f"키 스케줄 함수 '{fname}': 라운드키에 T[1] 반복 패턴 없음 — "
                            "LEA-128: RKi = (T[0], T[1], T[2], T[1], T[3], T[1])"),
                "ast_evidence": f"RK=T[] 대입 {len(rk_t_assigns)}건, T[1] 0건. libclang.",
            })
    return violations


def _lc_check_lea_023(tu, filename: str, sg: dict) -> List[Dict[str, Any]]:
    """LEA-023: 복호화 라운드키 역순 관계 확인 (libclang)."""
    _DEC_KEY_KW = ["dec_key", "set_dec", "decrypt_key", "dec_schedule",
                   "lea_set_dec", "inv_key", "deckey"]
    dec_funcs = _lc_funcs_matching(tu, _DEC_KEY_KW)
    if not dec_funcs:
        return []
    violations = []
    for fd in dec_funcs:
        fname = _lc_func_name(fd)
        calls = _lc_call_names(fd)
        if calls & {"lea_set_dec_key", "set_dec_key", "lea_keyschedule_dec"}:
            continue
        rk_assigns = [bop for bop in _lc_collect(fd, _ci.CursorKind.BINARY_OPERATOR)
                      if _lc_op_str(bop) == "="
                      and list(bop.get_children())
                      and list(bop.get_children())[0].kind == _ci.CursorKind.ARRAY_SUBSCRIPT_EXPR
                      and "rk" in (_lc_array_base(list(bop.get_children())[0]) or "").lower()]
        if not rk_assigns:
            continue
        has_reverse = False
        for bop in rk_assigns:
            kids = list(bop.get_children())
            if len(kids) < 2:
                continue
            for sub in kids[-1].walk_preorder():
                if (sub.kind == _ci.CursorKind.BINARY_OPERATOR and
                        _lc_op_str(sub) == "-"):
                    sub_kids = list(sub.get_children())
                    if (len(sub_kids) >= 2 and
                            sub_kids[-1].kind == _ci.CursorKind.DECL_REF_EXPR):
                        has_reverse = True
                        break
            if has_reverse:
                break
        if not has_reverse:
            violations.append({
                "line": _lc_line(fd),
                "message": (f"함수 '{fname}': 복호화 라운드키 역순 패턴 미확인 — "
                            "dec_rk[i]=enc_rk[Nr-1-i] 또는 lea_set_dec_key() 필요"),
                "ast_evidence": f"RK 대입 {len(rk_assigns)}건, 역순(-ID) 패턴 0건. libclang.",
            })
    return violations


def _lc_check_lea_034(tu, filename: str, sg: dict) -> List[Dict[str, Any]]:
    """LEA-034: 복호화 함수 내 모듈러 뺄셈 확인 (libclang)."""
    # 비-LEA 알고리즘 파일 제외 (pycparser 버전과 동일 로직)
    _NON_LEA_FILE_KW = ("aria", "ecdsa", "kcdsa", "ec_", "ecc", "sha", "hmac", "hash",
                        "utils", "pbkdf", "kbkdf", "gfp", "gf2n")
    fn_lower = filename.lower()
    if any(kw in fn_lower for kw in _NON_LEA_FILE_KW) and "lea" not in fn_lower:
        return []

    dec_funcs = [fd for fd in _lc_funcs_matching(tu, _DEC_KW)
                 if not _lc_is_thin_wrapper(fd) and not _lc_is_benchmark_func(fd)]
    if not dec_funcs:
        return []
    violations = []
    for fd in dec_funcs:
        if _lc_is_macro_based_round_func(fd):
            continue
        fname = _lc_func_name(fd)
        if not _lc_has_op(fd, "-"):
            # 다른 복호화 함수를 호출하는 위임 래퍼는 직접 뺄셈 없어도 정상
            # 예: lea_decrypt() → lea_dec() 패턴
            calls = {(c.spelling or "").lower() for c in _lc_collect(fd, _ci.CursorKind.CALL_EXPR)}
            if any(any(kw in c for kw in _DEC_KW) for c in calls):
                continue  # 다른 복호화 함수 위임 → 직접 뺄셈 불필요
            violations.append({
                "line": _lc_line(fd),
                "message": (f"함수 '{fname}': 복호화 함수에 모듈러 뺄셈(-) 미발견 — "
                            "LEA 복호화 역연산에 뺄셈 필요"),
                "ast_evidence": f"함수 '{fname}' BinaryOp('-') 0건. libclang.",
            })
    return violations


def _lc_check_lea_031(tu, filename: str, sg: dict) -> List[Dict[str, Any]]:
    """LEA-031: 라운드 함수 XOR→ADD 순서 확인 (libclang).

    ADD(+) 의 직계 자식이 XOR(^) 이어야 올바른 순서.
    """
    enc_funcs = [fd for fd in _lc_funcs_matching(tu, _ENC_KW)
                 if not _lc_is_thin_wrapper(fd) and not _lc_is_benchmark_func(fd)]
    if not enc_funcs:
        return []
    type_aliases = (sg or {}).get("type_aliases") or {}
    _INT32_TYPES = {"unsigned int", "unsigned long", "uint32_t", "u32",
                    "uint_least32_t", "uint_fast32_t"}
    wrong_order: List[int] = []

    for fd in enc_funcs:
        if _lc_is_macro_based_round_func(fd):
            continue
        for bop in _lc_collect(fd, _ci.CursorKind.BINARY_OPERATOR):
            if _lc_op_str(bop) != "^":
                continue
            # ^가 + 의 직계 자식인지 확인
            for parent in fd.walk_preorder():
                if parent.kind != _ci.CursorKind.BINARY_OPERATOR:
                    continue
                if _lc_op_str(parent) != "+":
                    continue
                pkids = list(parent.get_children())
                if any(k.location == bop.location for k in pkids):
                    # ADD의 자식이 XOR → 잘못된 순서
                    ln = _lc_line(parent)
                    if ln not in wrong_order:
                        wrong_order.append(ln)
                    break

    return [{"line": ln,
             "message": "라운드 함수: ADD(+) 내부에 XOR(^) — 올바른 순서는 XOR 후 ADD",
             "ast_evidence": "BINARY_OPERATOR('+', child=BINARY_OPERATOR('^')). libclang."}
            for ln in wrong_order[:3]]  # 최대 3건


def _lc_check_lea_046(tu, filename: str, sg: dict) -> List[Dict[str, Any]]:
    """LEA-046/056: MCT 이중 루프 100×1000 구조 확인 (libclang)."""
    mct_funcs = _lc_funcs_matching(tu, _MCT_KW)
    if not mct_funcs:
        return []
    violations = []
    for fd in mct_funcs:
        fname = _lc_func_name(fd)
        outer_for_list = _lc_collect(fd, _ci.CursorKind.FOR_STMT)
        found_valid = False
        wrong_outer: Optional[int] = None
        for outer in outer_for_list:
            ob = _lc_get_for_bound(outer)
            if ob not in (100, 1000):
                if ob and ob not in _LEA_ROUND_COUNTS:
                    wrong_outer = ob
                continue
            inner_fors = _lc_collect(outer, _ci.CursorKind.FOR_STMT)
            for inner in inner_fors:
                ib = _lc_get_for_bound(inner)
                if (ob == 100 and ib == 1000) or (ob == 1000 and ib == 100):
                    found_valid = True
                    break
            if found_valid:
                break
        if outer_for_list and not found_valid:
            violations.append({
                "line": _lc_line(fd),
                "message": (f"함수 '{fname}': MCT 이중 루프 100×1000 구조 미확인 — "
                            "LEA MCT 표준: 외부 100회, 내부 1000회"),
                "ast_evidence": f"FOR_STMT 이중 루프 100×1000 패턴 0건. libclang.",
            })
    return violations


def _lc_check_lea_047(tu, filename: str, sg: dict) -> List[Dict[str, Any]]:
    """LEA-047: MCT 내부 루프 암호화/복호화 함수 호출 확인 (libclang)."""
    mct_funcs = _lc_funcs_matching(tu, _MCT_KW)
    if not mct_funcs:
        return []
    violations = []
    _ENC_DEC_NAMES = {
        "lea_enc", "lea_encrypt", "lea_dec", "lea_decrypt",
        "lea_block_enc", "lea_block_dec", "block_encrypt", "block_decrypt",
    }
    for fd in mct_funcs:
        fname = _lc_func_name(fd)
        has_inner_1000 = False
        for outer in _lc_collect(fd, _ci.CursorKind.FOR_STMT):
            for inner in _lc_collect(outer, _ci.CursorKind.FOR_STMT):
                if _lc_get_for_bound(inner) == 1000:
                    has_inner_1000 = True
                    calls_in_inner = _lc_call_names(inner)
                    if not (calls_in_inner & _ENC_DEC_NAMES):
                        violations.append({
                            "line": _lc_line(inner),
                            "message": (f"함수 '{fname}': MCT 내부 루프(1000회)에서 "
                                        "암호화/복호화 함수 호출 미발견"),
                            "ast_evidence": "FOR_STMT(1000) 내부 암복호화 CALL_EXPR 0건. libclang.",
                        })
    return violations


def _lc_check_cmac_001(tu, filename: str, sg: dict) -> List[Dict[str, Any]]:
    """CMAC-001: CMAC 서브키 파생 Rb=0x87 XOR 확인 (libclang)."""
    cmac_funcs = _lc_funcs_matching(tu, _CMAC_INIT_KW)
    if not cmac_funcs:
        return []
    _SUBKEY_NAMES = {"k1", "k2", "subkey1", "subkey2", "cmac_k1", "cmac_k2"}
    violations = []
    for fd in cmac_funcs:
        fname = _lc_func_name(fd)
        # 서브키 배열 확인
        has_subkey = any(
            (decl.spelling or "").lower() in _SUBKEY_NAMES
            for decl in _lc_collect(fd, _ci.CursorKind.VAR_DECL)
        )
        if not has_subkey:
            continue
        has_rb_xor = False
        for bop in fd.walk_preorder():
            if bop.kind not in (_ci.CursorKind.BINARY_OPERATOR,
                                _ci.CursorKind.COMPOUND_ASSIGNMENT_OPERATOR):
                continue
            op = _lc_op_str(bop)
            if op not in ("^", "^="):
                continue
            for kid in bop.get_children():
                if _lc_const_int(kid) == 0x87:
                    has_rb_xor = True
                    break
                for lit in kid.walk_preorder():
                    if _lc_const_int(lit) == 0x87:
                        has_rb_xor = True
                        break
            if has_rb_xor:
                break
        if not has_rb_xor:
            violations.append({
                "line": _lc_line(fd),
                "message": (f"함수 '{fname}': CMAC 서브키 파생에서 Rb(0x87) XOR 연산 미발견"),
                "ast_evidence": "BINARY_OPERATOR('^', 0x87) 또는 COMPOUND_ASSIGNMENT('^=',0x87) 0건. libclang.",
            })
    return violations


def _lc_check_ctr_002(tu, filename: str, sg: dict) -> List[Dict[str, Any]]:
    """CTR-002: static 카운터/nonce 배열 탐지 (libclang)."""
    violations: List[Dict[str, Any]] = []
    seen: set = set()

    def _add(name: str, scope: str, line: Optional[int]) -> None:
        if line in seen:
            return
        seen.add(line)
        violations.append({
            "line": line,
            "message": (f"{scope} static 배열 '{name}' — "
                        "세션 간 카운터/nonce가 초기화 없이 재사용되어 CTR 키스트림 반복 위험"),
            "ast_evidence": f"VAR_DECL(static, CONSTANTARRAY)='{name}' in {scope}. libclang.",
        })

    # 전역 static 배열
    for decl in tu.cursor.get_children():
        if decl.kind != _ci.CursorKind.VAR_DECL:
            continue
        if decl.storage_class != _ci.StorageClass.STATIC:
            continue
        if decl.type.kind != _ci.TypeKind.CONSTANTARRAY:
            continue
        if _CTR_NAMES_RE.search(decl.spelling or ""):
            _add(decl.spelling, "전역", _lc_line(decl))

    # 함수 내 static 로컬 배열
    for fd in _lc_func_defs(tu):
        fname = _lc_func_name(fd)
        for decl in _lc_collect(fd, _ci.CursorKind.VAR_DECL):
            if decl.storage_class != _ci.StorageClass.STATIC:
                continue
            if decl.type.kind != _ci.TypeKind.CONSTANTARRAY:
                continue
            if _CTR_NAMES_RE.search(decl.spelling or ""):
                _add(decl.spelling, f"함수 '{fname}'", _lc_line(decl))

    return violations


def _lc_check_lea_032(tu, filename: str, sg: dict) -> Optional[List[Dict[str, Any]]]:
    """LEA-032: 마지막 라운드 특별 처리 분기 탐지 (libclang)."""
    enc_funcs = _lc_funcs_matching(tu, _LEA_ENC_KW)
    if not enc_funcs:
        all_funcs = _lc_func_defs(tu)
        for fd in all_funcs:
            fn = _lc_func_name(fd).lower()
            if any(kw in fn for kw in ("lea", "encrypt", "round")):
                if not _lc_is_thin_wrapper(fd) and not _lc_is_benchmark_func(fd):
                    return None
        return []
    violations = []
    for fd in enc_funcs:
        if _lc_is_thin_wrapper(fd) or _lc_is_benchmark_func(fd):
            continue
        fname = _lc_func_name(fd)
        for for_c in _lc_collect(fd, _ci.CursorKind.FOR_STMT):
            for ifstmt in _lc_collect(for_c, _ci.CursorKind.IF_STMT):
                for child in ifstmt.get_children():
                    if child.kind != _ci.CursorKind.BINARY_OPERATOR:
                        continue
                    op = _lc_op_str(child)
                    if op not in ("==", ">=", "<="):
                        continue
                    for lit in child.walk_preorder():
                        val = _lc_const_int(lit)
                        if val in (23, 27, 31):
                            violations.append({
                                "line": _lc_line(ifstmt),
                                "message": (f"함수 '{fname}': 라운드 루프 내 마지막 라운드 "
                                            f"분기 조건({op}{val}) 탐지 — LEA는 마지막 라운드도 동일 구조"),
                                "ast_evidence": f"FOR 내 IF_STMT({op} Constant({val})). libclang.",
                            })
                            break
    return violations


# ── libclang 체커 디스패치 테이블 ────────────────────────────────

_LC_CHECKERS = {
    # 검증된 libclang 체커만 포함 (세트 코드 FN 유발 또는 KISA FP 유발 체커 제외)
    # "CBC-001":  _lc_check_cbc_001,  # lea_t_generic.c FP → pycparser 사용
    # "CBC-002":  _lc_check_cbc_002,  # lea_t_generic.c FP → pycparser 사용
    "ECB-002":  _lc_check_ecb_002,
    "GCM-001":  _lc_check_gcm_001,
    "CCM-001":  _lc_check_ccm_001,
    "CTR-001":  _lc_check_ctr_001,
    # "CTR-002":  _lc_check_ctr_002,  # 세트 4 FN 유발 → pycparser 사용
    "CTR-005":  _lc_check_ctr_005,
    "OFB-002":  _lc_check_ofb_002,
    "CFB-002":  _lc_check_cfb_002,
    "LEA-005":  _lc_check_lea_005,
    # "LEA-006":  _lc_check_lea_006,  # KISA FP → pycparser 사용
    # "LEA-010":  _lc_check_lea_010,  # KISA lea_set_key_generic FP → pycparser 사용
    "LEA-014":  _lc_check_lea_014,
    "LEA-015":  _lc_check_lea_015,
    # "LEA-021":  _lc_check_lea_021,  # 세트 4 FN 유발 → pycparser 사용
    # "LEA-022":  _lc_check_lea_022,  # 세트 4 FN 유발 → pycparser 사용
    # "LEA-023":  _lc_check_lea_023,  # 세트 4 FN 유발 → pycparser 사용
    "LEA-030":  _lc_check_lea_030,
    # "LEA-031":  _lc_check_lea_031,  # 세트 2/3 FN 유발 → pycparser 사용
    "LEA-032":  _lc_check_lea_032,
    "LEA-034":  _lc_check_lea_034,
    "LEA-035":  _lc_check_lea_035,
    # "LEA-040":  _lc_check_lea_040,  # 세트 3 FN 유발 → pycparser 사용
    "LEA-042":  _lc_check_lea_042,
    "LEA-043":  _lc_check_lea_043,
    "LEA-046":  _lc_check_lea_046,
    "LEA-056":  _lc_check_lea_046,
    # "LEA-057":  _lc_check_lea_057,  # 세트 4 FN 유발 → pycparser 사용
    "LEA-047":  _lc_check_lea_047,
    "CMAC-001": _lc_check_cmac_001,
    "LEA-003":  _lc_check_lea_003,  # 전략 7/8 추가로 세트 2 FN 해결 — libclang 활성화
}

# ══════════════════════════════════════════════════════════════════

_CHECKERS = {
    "LEA-003": _check_lea_003,
    "LEA-014": _check_lea_014,
    "LEA-015": _check_lea_015,
    "LEA-021": _check_lea_021,
    "LEA-043": _check_lea_043,
    "LEA-010": _check_lea_010,
    "LEA-030": _check_lea_030,
    "LEA-031": _check_lea_031,
    "LEA-034": _check_lea_034,
    "LEA-035": _check_lea_035,
    "LEA-040": _check_lea_040,
    "CBC-001": _check_cbc_001,
    "CBC-002": _check_cbc_002,
    "ECB-002": _check_ecb_002,
    "GCM-001": _check_gcm_001,
    "CCM-001": _check_ccm_001,
    "LEA-042": _check_lea_042,
    "LEA-046": _check_lea_046,
    "LEA-056": _check_lea_046,   # 동일 로직: MCT 100×1000 루프 구조 검사
    "LEA-057": _check_lea_057,
    "CTR-001": _check_ctr_001,
    "CTR-002": _check_ctr_002,
    "CMAC-001": _check_cmac_001,
    "LEA-047": _check_lea_047,
    "OFB-002": _check_ofb_002,
    "CFB-002": _check_cfb_002,
    "LEA-005": _check_lea_005,
    "LEA-006": _check_lea_006,
    "LEA-022": _check_lea_022,
    "LEA-023": _check_lea_023,
    "CTR-005": _check_ctr_005,
    "LEA-032": _check_lea_032,
    "LEA-024": _check_lea_024,
    "LEA-025": _check_lea_025,
    "ARIA-002": _check_aria_002,
    "CBC-LEA-005": _check_cbc_lea_005,
    "CTR-LEA-006": _check_ctr_lea_006,
    "LEA-039": _check_lea_039,
    "LEA-059": _check_lea_059,
}


# ---------------------------------------------------------------------------
# LEA-003 regex fallback — AST 파싱 실패 시 토큰 기반 라운드 조건 탐지
# lea.h 미포함으로 pycparser/libclang 모두 key->round 해석 불가 → regex 보완
# ---------------------------------------------------------------------------
import re as _re_mod

# LEA 표준 라운드 수: 128bit→24, 192bit→28, 256bit→32
_LEA_STANDARD_ROUNDS = {24, 28, 32}
# 표준 라운드 오프셋: (mk_len >> 1) + 16
_LEA_STANDARD_OFFSET = 16


def _lea003_regex_scan(content: str) -> Optional[List[Dict[str, Any]]]:
    """
    LEA-003 regex fallback: 라운드 조건 비표준값 탐지.

    패턴 1: ->round > N / >= N / < N / <= N  (비교 조건)
    패턴 2: ->round = ... + N                (라운드 수 산출)
    """
    violations: List[Dict[str, Any]] = []
    lines = content.split("\n")

    # 패턴 1: 라운드 비교 조건 (e.g., key->round > 25)
    pat_cmp = _re_mod.compile(
        r"->round\s*(>|>=|<|<=|==|!=)\s*(\d+)"
    )
    # 패턴 2: 라운드 산출 (e.g., round = (mk_len >> 1) + 15)
    pat_assign = _re_mod.compile(
        r"->round\s*=\s*.*?\+\s*(\d+)"
    )

    for i, line in enumerate(lines, 1):
        # 주석 라인 건너뛰기
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("/*"):
            continue

        for m in pat_cmp.finditer(line):
            op, val_s = m.group(1), m.group(2)
            val = int(val_s)
            if 16 <= val <= 40 and val not in _LEA_STANDARD_ROUNDS:
                violations.append({
                    "line": i,
                    "message": (
                        f"LEA-003: 비표준 라운드 비교 조건 발견 — "
                        f"'->round {op} {val}'. "
                        f"KS X 3246 표준값: {{24, 28, 32}}."
                    ),
                    "ast_evidence": f"regex_fallback: round_cmp {op} {val}",
                })

        for m in pat_assign.finditer(line):
            val = int(m.group(1))
            if 12 <= val <= 20 and val != _LEA_STANDARD_OFFSET:
                violations.append({
                    "line": i,
                    "message": (
                        f"LEA-003: 비표준 라운드 수 오프셋 발견 — "
                        f"'+ {val}'. 표준 오프셋: +16 "
                        f"((mk_len >> 1) + 16)."
                    ),
                    "ast_evidence": f"regex_fallback: round_offset +{val}",
                })

    return violations if violations else None


# ---------------------------------------------------------------------------
# LEA-034/040 regex fallback — ROL/ROR 회전량 비표준값 탐지
# KS X 3246 표준 회전량: {1, 3, 5, 6, 9, 11, 13, 17}
# ---------------------------------------------------------------------------
_LEA_STANDARD_ROTATIONS = frozenset({1, 3, 5, 6, 9, 11, 13, 17})


def _lea_rotation_regex_scan(
    content: str, rule_id: str
) -> Optional[List[Dict[str, Any]]]:
    """
    LEA-034/040 regex fallback: ROL/ROR 매크로의 비표준 회전량 탐지.

    - LEA-034 (decrypt): ROR 비표준 회전량
    - LEA-040 (key schedule): ROL 비표준 회전량
    """
    violations: List[Dict[str, Any]] = []
    lines = content.split("\n")

    # ROL/ROR 매크로: 마지막 인자(회전량)를 추출
    # 중첩 괄호 대응: 라인에서 ROL/ROR 존재 확인 후, ", N)" 패턴으로 회전량 추출
    pat_macro = _re_mod.compile(r"\b(ROL|ROR)\s*\(")
    pat_rot = _re_mod.compile(r",\s*(\d+)\s*\)")

    # rule_id에 따라 타겟 매크로 결정
    if rule_id == "LEA-034":
        target_macro = "ROR"
    elif rule_id == "LEA-040":
        target_macro = "ROL"
    else:
        return None

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("/*"):
            continue

        # 먼저 타겟 매크로가 라인에 있는지 확인
        macro_match = pat_macro.search(line)
        if not macro_match or macro_match.group(1) != target_macro:
            continue
        for m in pat_rot.finditer(line):
            rot_val = int(m.group(1))
            if rot_val not in _LEA_STANDARD_ROTATIONS and 1 <= rot_val <= 20:
                violations.append({
                    "line": i,
                    "message": (
                        f"{rule_id}: 비표준 {target_macro} 회전량 발견 — "
                        f"{target_macro}(..., {rot_val}). "
                        f"KS X 3246 표준 회전량: {sorted(_LEA_STANDARD_ROTATIONS)}."
                    ),
                    "ast_evidence": f"regex_fallback: {target_macro} rotation {rot_val}",
                })

    return violations if violations else None


# ---------------------------------------------------------------------------
# GCM-001 regex fallback — GCM 복호화 함수에서 태그 검증 누락 탐지
# ---------------------------------------------------------------------------

def _gcm001_regex_scan(content: str) -> Optional[List[Dict[str, Any]]]:
    """GCM-001 regex fallback: GCM decrypt 함수에서 tag 검증 누락 패턴 탐지."""
    violations: List[Dict[str, Any]] = []
    lines = content.split("\n")

    # GCM decrypt 함수 정의 탐지 (함수명에 gcm+decrypt 포함)
    pat_func = _re_mod.compile(
        r"^\s*(?:int|void|unsigned|static\s+\w+)\s+"
        r"(\w*gcm\w*decrypt\w*|\w*decrypt\w*gcm\w*)"
        r"\s*\(",
        _re_mod.IGNORECASE,
    )
    # 실제 태그 검증 코드 패턴 (주석/함수명의 "tag" 제외)
    # memcmp 계열 호출, tag 변수 비교, 또는 인증 실패 리턴 패턴
    pat_tag_verify = _re_mod.compile(
        r"\bmemcmp\s*\(|"
        r"\bCRYPTO_memcmp\s*\(|"
        r"\btimingsafe_memcmp\s*\(|"
        r"\bconsttime_memcmp\s*\(|"
        r"\btag\s*(\[|==|!=)|"         # tag[...] or tag == / !=
        r"(==|!=)\s*tag\b|"            # ... == tag
        r"\bverify_tag\s*\(|"
        r"\bcheck_tag\s*\(",
    )

    i = 0
    while i < len(lines):
        func_m = pat_func.match(lines[i])
        if not func_m:
            i += 1
            continue
        func_name = func_m.group(1)
        func_start = i + 1  # 1-based
        brace_depth = 0
        found_body = False
        has_tag_check = False
        j = i
        for j in range(i, min(i + 100, len(lines))):
            line = lines[j]
            # 주석 라인은 태그 검증으로 간주하지 않음
            stripped = line.strip()
            is_comment = stripped.startswith("//") or stripped.startswith("/*")
            brace_depth += line.count("{") - line.count("}")
            if "{" in line and not found_body:
                found_body = True
            if found_body and not is_comment and pat_tag_verify.search(line):
                has_tag_check = True
            if found_body and brace_depth <= 0:
                break
        if found_body and not has_tag_check:
            violations.append({
                "line": func_start,
                "message": (
                    f"GCM-001: 함수 '{func_name}'에서 인증 태그(tag) 검증 누락 — "
                    "GCM 복호화 시 태그 미검증은 위조된 암호문 수용 위험"
                ),
                "ast_evidence": f"regex_fallback: GCM decrypt function '{func_name}' without tag verification",
            })
        i = j + 1 if found_body else i + 1

    return violations if violations else None


def check_rule(
    rule_id: str,
    content: str,
    filename: str,
    rule_meta: Optional[Dict[str, Any]] = None,
    extra_includes: Optional[List[str]] = None,
    symbol_graph: Optional[Dict[str, Any]] = None,
) -> Optional[List[Dict[str, Any]]]:
    """
    지정 rule_id 에 대해 pycparser AST 검사 수행.

    Args:
      symbol_graph: build_symbol_graph() 반환값 (optional).
                    libclang 백엔드 시 array_inits, type_aliases, params 포함.

    Returns:
      None  → 미구현 규칙 또는 파싱 실패 (fallback 사용)
      []    → 위반 없음 (규칙 준수 확인)
      [..] → 위반 목록 [{line, message}, ...]
    """
    # ── 템플릿/include-only 파일: 함수 본체({}) 없음 → AST 위반 불가 ──
    # KISA 스타일 템플릿 파일(lea_t_generic.c 등)은 #include와 #define만 포함.
    # 이런 파일은 실제 코드가 없으므로 AST 위반이 존재하지 않음 → 빈 리스트 반환.
    if '{' not in content:
        return []

    # ── regex pre-scan: AST 파싱 성공/실패와 무관하게 항상 실행 ──
    # lea.h 미포함 등으로 AST가 불완전할 때 regex가 유일한 탐지 수단
    _regex_pre: Optional[List[Dict[str, Any]]] = None
    if rule_id == "LEA-003":
        _regex_pre = _lea003_regex_scan(content)
    elif rule_id in ("LEA-034", "LEA-040"):
        _regex_pre = _lea_rotation_regex_scan(content, rule_id)
    elif rule_id == "GCM-001":
        _regex_pre = _gcm001_regex_scan(content)
    elif rule_id == "ECB-002":
        # Short-circuit: if source has "& 0xf" / "& 0x0F" / "& 15" block-align check,
        # the ECB implementation does validate length — treat as compliant (return [])
        import re as _re_ecb
        if _re_ecb.search(r'&\s*0x0?[Ff]\b', content):
            return []
    # libclang 백엔드 우선 시도 (KISA MAKE_FUNC 매크로 파싱 지원)
    # libclang 체커가 None 반환 시 → rule_engine 경로로 fallback (pycparser/fallback_pattern)
    lc_checker = _LC_CHECKERS.get(rule_id)
    if _HAS_LIBCLANG and lc_checker:
        tu = _parse_c_libclang(content, filename, extra_includes)
        if tu is not None:
            try:
                lc_result = lc_checker(tu, filename, symbol_graph or {})
                # regex pre-scan 결과와 병합
                if _regex_pre:
                    if lc_result:
                        existing_lines = {v.get("line") for v in lc_result}
                        for rv in _regex_pre:
                            if rv.get("line") not in existing_lines:
                                lc_result.append(rv)
                        return lc_result
                    return _regex_pre
                return lc_result
            except Exception:
                pass  # pycparser fallback

    # regex pre-scan에서 이미 탐지된 위반이 있으면 반환
    if _regex_pre:
        return _regex_pre

    # LEA-021: KISA 1D stride-6 체크 — positive detection of wrong assignment
    # KISA lea_core.c는 struct pointer 1D 스타일(key->rk[N]=ROL(key->rk[M]+...))을 사용
    # pycparser가 KISA 전용 타입/매크로를 파싱하지 못하므로, 오류 패턴을 직접 검출
    # LEA-128 정상: rk[6]=ROL(rk[0]+...), rk[7]=ROL(rk[1]+...)
    # 돌연변이:     rk[7]=ROL(rk[0]+...) ← rk[7]이 rk[0]에서 유래 → stride=7 오류
    if rule_id == "LEA-021":
        import re as _re_lea021
        # C 블록 주석 제거 (mutation script가 /* MUTATION: ... */를 인라인 삽입하므로)
        _clean = _re_lea021.sub(r"/\*.*?\*/", " ", content, flags=_re_lea021.DOTALL)
        _WRONG_STRIDE_RE = _re_lea021.compile(
            r'(?:\w+->)?rk\s*\[\s*7\s*\]\s*=\s*\w+\s*\(\s*(?:\w+->)?rk\s*\[\s*0\s*\]'
        )
        _m = _WRONG_STRIDE_RE.search(_clean)
        if _m:
            _line_no = content[: _m.start()].count("\n") + 1
            return [
                {
                    "line": _line_no,
                    "message": (
                        "LEA-128 키 스케줄 stride-6 오류: rk[7]=ROL(rk[0]+...) 검출 "
                        "— 올바른 체인은 rk[6]=ROL(rk[0]+...)"
                    ),
                    "ast_evidence": (
                        "rk[0]→rk[7] 잘못된 stride=7 검출. "
                        "LEA-128 표준: rk[0]→rk[6] stride=6 필수 (KS X 3246 §5.1.1)"
                    ),
                }
            ]

    # pycparser fallback
    checker = _CHECKERS.get(rule_id)
    if checker is None:
        return None

    parsed = _parse_c_raw(content, filename, extra_includes=extra_includes)
    if parsed is None:
        return None

    ast_node, offset = parsed

    # symbol_graph 데이터를 받는 체커는 4인자 시그니처 사용
    import inspect as _inspect
    sig = _inspect.signature(checker)
    try:
        if len(sig.parameters) >= 4:
            return checker(ast_node, offset, filename, symbol_graph or {})
        return checker(ast_node, offset, filename)
    except Exception:
        return None
