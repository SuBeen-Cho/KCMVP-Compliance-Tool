"""
심볼 연결: 파일별 AST에서 정의/호출을 수집해 크로스 파일 호출 그래프 생성.
- preprocess_result.files[].ast 의 functions, file_calls 를 사용.
- 결과: definitions(함수별 정의 위치), calls(호출 목록), call_graph(연결된 호출 흐름).

향상 경로:
  libclang 설치 시 → enhanced_symbol_graph_service 우선 사용
    (타입 해석, 정확한 end_line, USR 크로스 파일 링킹, array_inits)
  libclang 미설치 또는 실패 시 → 기존 pycparser 기반 로직 fallback
"""
from typing import Dict, List, Any, Optional


def build_symbol_graph(
    preprocess_result: Dict[str, Any],
    src_root=None,
) -> Dict[str, Any]:
    """
    전처리 결과에서 정의·호출을 수집하고 이름으로 연결해 "파일 전체 흐름" 그래프 생성.

    Returns:
        {
            "definitions": { "함수이름": [ {"file": path, "line": int, "end_line": int,
                                           "usr": str (libclang 시), "params": [...] (libclang 시)}, ... ] },
            "calls": [ {"caller_file": path, "caller_line": int, "callee_name": str}, ... ],
            "call_graph": [ {"caller_file": path, "caller_line": int, "callee_name": str,
                             "defined_in": path 또는 null, "def_line": int 또는 null}, ... ],
            "type_aliases": {alias: underlying} (libclang 시),
            "array_inits":  {varname: {type, size, values}} (libclang 시),
            "backend": "libclang" | "pycparser",
        }
    """
    # ── libclang 향상 경로 ─────────────────────────────────────
    try:
        from app.services.enhanced_symbol_graph_service import build_enhanced_symbol_graph
        enhanced = build_enhanced_symbol_graph(preprocess_result, src_root=src_root)
        if enhanced is not None:
            return enhanced
    except Exception:
        pass

    # ── pycparser 기반 fallback (기존 로직) ────────────────────
    definitions: Dict[str, List[Dict[str, Any]]] = {}
    calls: List[Dict[str, Any]] = []
    call_graph: List[Dict[str, Any]] = []

    files = preprocess_result.get("files") or []
    for item in files:
        file_path = item.get("path") or ""
        ast = item.get("ast") or {}
        if not isinstance(ast, dict):
            continue
        for func in ast.get("functions") or []:
            if not isinstance(func, dict):
                continue
            name = func.get("name")
            if not name:
                continue
            line = func.get("line")
            end_line = func.get("end_line") or line
            if name not in definitions:
                definitions[name] = []
            definitions[name].append({
                "file": file_path,
                "line": line,
                "end_line": end_line,
            })

    for item in files:
        file_path = item.get("path") or ""
        ast = item.get("ast") or {}
        if not isinstance(ast, dict):
            continue
        for call in ast.get("file_calls") or []:
            if not isinstance(call, dict):
                continue
            callee_name = call.get("name")
            if not callee_name:
                continue
            caller_line = call.get("line")
            calls.append({
                "caller_file": file_path,
                "caller_line": caller_line,
                "callee_name": callee_name,
            })
            defs = definitions.get(callee_name)
            defined_in: Optional[str] = None
            def_line: Optional[int] = None
            if defs:
                defined_in = defs[0].get("file")
                def_line = defs[0].get("line")
            call_graph.append({
                "caller_file": file_path,
                "caller_line": caller_line,
                "callee_name": callee_name,
                "defined_in": defined_in,
                "def_line": def_line,
            })

    return {
        "definitions": definitions,
        "calls": calls,
        "call_graph": call_graph,
        "files_with_clearing_call": _files_with_clearing_call(files),
        "type_aliases": {},
        "array_inits": {},
        "backend": "pycparser",
    }


# COM-001 등에서 인정하는 "제거" 함수 이름 (symbol_graph에서 어떤 파일이 직접 제거 호출을 하는지 표시용)
_CLEARING_NAMES = {
    "memset_s", "SecureZeroMemory", "explicit_bzero", "RtlSecureZeroMemory",
    "secure_clear", "clear_key", "secure_free_key", "wipe_buffer",
    "lea_module_zeroize", "OPENSSL_cleanse", "sodium_memzero", "memset_explicit",
}


def _files_with_clearing_call(files: List[Dict[str, Any]]) -> List[str]:
    """file_calls에 제거용 함수 이름이 하나라도 있는 파일 path 목록."""
    result: List[str] = []
    for item in files:
        ast = item.get("ast") or {}
        path = item.get("path") or ""
        if not path:
            continue
        for call in ast.get("file_calls") or []:
            name = (call.get("name") if isinstance(call, dict) else None)
            if name and name in _CLEARING_NAMES:
                result.append(path)
                break
    return result
