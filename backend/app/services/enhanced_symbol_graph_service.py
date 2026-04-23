"""
향상된 심볼 그래프 서비스 (libclang 기반).

기존 symbol_graph_service.py 대비 추가 정보:
  - 정확한 end_line (cursor.extent.end.line — 닫는 '}' 기준)
  - USR (Unified Symbol Resolution) — 크로스 파일 정확 링킹
  - 함수 파라미터 타입/이름
  - return_type
  - type_aliases  : {alias: underlying}  (uint32_t → unsigned int 등)
  - array_inits   : {varname: {type, size, values}}  (S-box, delta 상수)
  - backend 필드  : "libclang" | "pycparser"

기존 스키마 키(definitions, calls, call_graph, files_with_clearing_call)는
그대로 유지되어 rule_engine_service 등 기존 소비자에 영향 없음.

libclang 미설치 또는 파싱 실패 시 None 반환 → 호출자가 레거시로 fallback.
"""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ── libclang 가용성 확인 ───────────────────────────────────────────
try:
    import clang.cindex as _ci  # pip install libclang

    _HAS_LIBCLANG = True
except ImportError:
    _HAS_LIBCLANG = False

# ── 제거 함수 이름 (COM-001) ─────────────────────────────────────
_CLEARING_NAMES = {
    "memset", "SecureZeroMemory", "explicit_bzero", "RtlSecureZeroMemory",
    "secure_clear", "clear_key", "secure_free_key", "wipe_buffer",
    "memset_s", "memset_explicit",
    "__builtin___memset_chk",  # pycparser/GCC가 memset을 확장하는 내부 형태
}

# ── 시스템 경로 (심볼 수집 제외) ────────────────────────────────
_SYS_PREFIXES = ("/usr/", "/Library/", "/Applications/", "<built-in>",
                 "<command", "/opt/homebrew/")


# ══════════════════════════════════════════════════════════════════
# 공개 API
# ══════════════════════════════════════════════════════════════════

def build_enhanced_symbol_graph(
    preprocess_result: Dict[str, Any],
    src_root: Optional[Path] = None,
) -> Optional[Dict[str, Any]]:
    """
    libclang 기반 향상된 심볼 그래프.

    Returns:
        향상된 심볼 그래프 dict, 또는 libclang 미설치/실패 시 None.
    """
    if not _HAS_LIBCLANG:
        return None

    files = preprocess_result.get("files") or []
    # .c 파일 경로 수집
    c_paths: List[Path] = []
    for item in files:
        p = item.get("path") or ""
        if p.endswith((".c", ".h")):
            resolved = Path(p) if Path(p).is_absolute() else (
                (src_root / p) if src_root else Path(p)
            )
            if resolved.is_file():
                c_paths.append(resolved)

    if not c_paths:
        return None

    # include 경로: 제출 파일들이 있는 디렉터리들
    include_dirs = list({str(p.parent) for p in c_paths})

    try:
        return _run_libclang_analysis(c_paths, include_dirs)
    except Exception:
        return None


# ══════════════════════════════════════════════════════════════════
# 내부 구현
# ══════════════════════════════════════════════════════════════════

def _is_system_path(path: str) -> bool:
    return any(path.startswith(p) for p in _SYS_PREFIXES)


def _run_libclang_analysis(
    c_paths: List[Path],
    include_dirs: List[str],
) -> Optional[Dict[str, Any]]:
    """libclang으로 파일 목록 분석 → 향상된 심볼 그래프."""

    idx = _ci.Index.create()
    args = [
        "-x", "c", "-std=c99",
        "-D__attribute__(x)=",
        "-D__asm__(x)=",
        "-D__asm(x)=",
        "-D__inline=",
        "-D__restrict=",
        "-D__extension__=",
        "-D__volatile__(x)=",
    ] + [f"-I{d}" for d in include_dirs]

    # 파일별 수집 결과
    definitions: Dict[str, List[Dict[str, Any]]] = {}
    calls: List[Dict[str, Any]] = []
    type_aliases: Dict[str, str] = {}
    array_inits: Dict[str, Dict[str, Any]] = {}
    files_with_clearing: List[str] = []

    parsed_any = False

    for src in c_paths:
        filepath = str(src)
        try:
            tu = idx.parse(
                filepath,
                args=args,
                options=_ci.TranslationUnit.PARSE_SKIP_FUNCTION_BODIES
                        if src.suffix == ".h"
                        else 0,
            )
        except Exception:
            continue

        if tu is None:
            continue

        # 파싱 에러가 치명적이면 skip
        fatal_errors = [d for d in tu.diagnostics
                        if d.severity >= _ci.Diagnostic.Error]
        # 에러가 있어도 부분 결과를 활용 (치명적 에러 50% 이상이면 skip)
        if len(fatal_errors) > 10:
            continue

        parsed_any = True
        has_clearing = False

        for cursor in tu.cursor.walk_preorder():
            loc = cursor.location
            if loc.file is None:
                continue
            loc_path = loc.file.name
            # 시스템 헤더 제외
            if _is_system_path(loc_path):
                continue

            kind = cursor.kind

            # ── 함수 정의 ──────────────────────────────────────
            if kind == _ci.CursorKind.FUNCTION_DECL and cursor.is_definition():
                name = cursor.spelling
                if not name:
                    continue
                params = [
                    {"name": p.spelling, "type": p.type.spelling}
                    for p in cursor.get_arguments()
                ]
                entry = {
                    "file": loc_path,
                    "line": loc.line,
                    "end_line": cursor.extent.end.line,  # 닫는 } 정확
                    "usr": cursor.get_usr(),
                    "params": params,
                    "return_type": cursor.result_type.spelling,
                }
                definitions.setdefault(name, []).append(entry)

            # ── 함수 호출 ──────────────────────────────────────
            elif kind == _ci.CursorKind.CALL_EXPR:
                callee_cursor = cursor.referenced
                callee_name = (
                    callee_cursor.spelling if callee_cursor else cursor.spelling
                )
                if not callee_name:
                    continue
                callee_usr = (
                    callee_cursor.get_usr() if callee_cursor else ""
                )
                call_entry = {
                    "caller_file": loc_path,
                    "caller_line": loc.line,
                    "callee_name": callee_name,
                    "callee_usr": callee_usr,
                }
                calls.append(call_entry)
                if callee_name in _CLEARING_NAMES:
                    has_clearing = True

            # ── typedef ────────────────────────────────────────
            elif kind == _ci.CursorKind.TYPEDEF_DECL:
                alias = cursor.spelling
                underlying = cursor.underlying_typedef_type.spelling
                if alias and underlying and alias != underlying:
                    type_aliases[alias] = underlying

            # ── static const 배열 (상수 초기화값) ──────────────
            elif kind == _ci.CursorKind.VAR_DECL:
                typ = cursor.type
                if typ.kind == _ci.TypeKind.CONSTANTARRAY:
                    vals = _extract_array_init_values(cursor)
                    if vals:
                        array_inits[cursor.spelling] = {
                            "file": loc_path,
                            "type": typ.element_type.spelling,
                            "size": typ.element_count,
                            "values": vals,
                        }

        if has_clearing:
            files_with_clearing.append(filepath)

    if not parsed_any:
        return None

    # ── USR 기반 call_graph 연결 ────────────────────────────────
    # USR 역인덱스: usr → (file, line)
    usr_to_def: Dict[str, Dict[str, Any]] = {}
    name_to_def: Dict[str, Dict[str, Any]] = {}
    for name, defs in definitions.items():
        for d in defs:
            if d.get("usr"):
                usr_to_def[d["usr"]] = d
            name_to_def[name] = d  # 이름 기반 fallback

    call_graph: List[Dict[str, Any]] = []
    for c in calls:
        callee_name = c["callee_name"]
        callee_usr = c.get("callee_usr", "")

        # USR 우선, 없으면 이름 기반
        def_entry = (
            usr_to_def.get(callee_usr)
            or name_to_def.get(callee_name)
        )
        call_graph.append({
            "caller_file": c["caller_file"],
            "caller_line": c["caller_line"],
            "callee_name": callee_name,
            "callee_usr": callee_usr,
            "defined_in": def_entry["file"] if def_entry else None,
            "def_line": def_entry["line"] if def_entry else None,
        })

    return {
        # ── 기존 schema 호환 키 ──
        "definitions": definitions,
        "calls": [
            {"caller_file": c["caller_file"],
             "caller_line": c["caller_line"],
             "callee_name": c["callee_name"]}
            for c in calls
        ],
        "call_graph": call_graph,
        "files_with_clearing_call": files_with_clearing,
        # ── 신규 향상 키 ──
        "type_aliases": type_aliases,
        "array_inits": array_inits,
        "backend": "libclang",
    }


def _extract_array_init_values(var_decl_cursor) -> List[str]:
    """
    VAR_DECL 커서에서 배열 초기화값 추출.
    INIT_LIST_EXPR → INTEGER_LITERAL / UNEXPOSED_EXPR 자식 노드의 첫 토큰.
    """
    values: List[str] = []
    for child in var_decl_cursor.get_children():
        if child.kind == _ci.CursorKind.INIT_LIST_EXPR:
            for elem in child.get_children():
                tok_list = [t.spelling for t in _first_tokens(elem, n=1)]
                if tok_list:
                    values.append(tok_list[0])
            break
    return values


def _first_tokens(cursor, n: int = 1):
    """커서 서브트리에서 처음 n개 토큰."""
    count = 0
    for tok in cursor.get_tokens():
        yield tok
        count += 1
        if count >= n:
            break
