"""
PreprocessService: 전처리 및 AST 생성.
- 파일 필터(.c, .h, .cpp 등) → AST 파싱 → 파일별 구조화 데이터 출력.
- AST 스키마: { "language", "functions": [ { "name", "line", "end_line", "calls": [...] } ], "file_calls": [ { "name", "line" } ] }

libclang 설치 시: AST 파싱을 건너뛰고 파일 읽기 + 라인 분리만 수행.
  (AST 분석은 ast_checker_service와 enhanced_symbol_graph_service가 libclang으로 직접 수행)
libclang 미설치 시: pycparser로 AST 파싱 (symbol_graph fallback용).
"""
import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

# ── libclang 가용성 확인 ──
# libclang이 있으면 AST 파싱은 downstream(ast_checker, symbol_graph)에서 직접 수행하므로
# preprocess 단계에서는 파일 읽기만 하면 된다.
try:
    import clang.cindex as _ci  # noqa: F401
    _HAS_LIBCLANG = True
except ImportError:
    _HAS_LIBCLANG = False

SOURCE_EXTENSIONS = {".c", ".h", ".cpp", ".hpp", ".py"}

# pycparser 파싱을 위한 표준 라이브러리 타입·함수 fake 선언.
# 실제 C 전처리기(gcc -E) 없이 파싱하기 위해 필요한 최소 선언만 포함한다.
_PYCPARSER_PREAMBLE = """\
typedef int size_t;
typedef int ssize_t;
typedef int ptrdiff_t;
typedef int off_t;
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
typedef char int8_t;
typedef short int16_t;
typedef int int32_t;
typedef long long int64_t;
typedef int bool;
typedef int BOOL;
typedef int FILE;
typedef int va_list;
void *memset(void *, int, size_t);
void *memcpy(void *, const void *, size_t);
int memcmp(const void *, const void *, size_t);
int printf(const char *, ...);
int fprintf(FILE *, const char *, ...);
int sprintf(char *, const char *, ...);
int snprintf(char *, size_t, const char *, ...);
size_t strlen(const char *);
char *strcpy(char *, const char *);
char *strncpy(char *, const char *, size_t);
int strcmp(const char *, const char *);
int strncmp(const char *, const char *, size_t);
void free(void *);
void *malloc(size_t);
void *calloc(size_t, size_t);
void *realloc(void *, size_t);
void abort(void);
void exit(int);
"""


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


def _extract_macro_func_decls(text: str) -> str:
    """#define FUNC(args) ... 패턴을 찾아 pycparser용 fake 함수 선언으로 변환."""
    decls: set = set()
    for m in re.finditer(r'#\s*define\s+(\w+)\s*\(([^)]*)\)', text):
        name = m.group(1)
        params = [p.strip() for p in m.group(2).split(',') if p.strip()]
        plist = ', '.join(f'int {p}' for p in params) if params else 'void'
        decls.add(f'int {name}({plist});')
    return '\n'.join(sorted(decls)) + '\n' if decls else ''


def _process_header_content(text: str) -> str:
    """주석 제거된 헤더 내용에서 typedef/struct/선언은 유지하고
    전처리 지시어는 빈 줄로 치환한다.

    변환 규칙:
    - #define NAME NUMBER/HEX  →  enum { NAME = VALUE };  (배열 크기 등에 사용)
    - #define NAME IDENTIFIER  →  typedef IDENTIFIER NAME;
    - extern "C" { ... }       →  제거 (pycparser는 C만 지원)
    - 나머지 #지시어            →  빈 줄
    """
    # extern "C" { ... } 전체 블록 제거 (C++ 전용 구문)
    text = re.sub(r'extern\s+"C"\s*\{', '', text)
    # extern "C" 블록의 닫는 괄호가 단독으로 있을 때 제거
    # (#ifdef __cplusplus 가드 내부의 standalone } 대상)
    # 단순하게: extern "C" { 제거 후 남는 중괄호 개수를 맞추기 위해
    # 오픈/클로즈 브레이스 균형을 확인하는 대신,
    # 헤더 전체에서 중괄호 열기/닫기를 세어서 불일치 시 마지막 } 제거
    lines = text.splitlines()
    out: list = []
    in_multiline_define = False
    for line in lines:
        stripped = line.lstrip()
        # 멀티라인 매크로 계속 줄 처리
        if in_multiline_define:
            out.append('')
            in_multiline_define = line.rstrip().endswith('\\')
            continue
        if not stripped.startswith('#'):
            out.append(line)
            continue
        # 멀티라인 매크로 시작: 줄 끝이 \ 인 경우
        if line.rstrip().endswith('\\'):
            in_multiline_define = True
            out.append('')
            continue
        # #define NAME NUMBER or 0xHEX → enum { NAME = VALUE };
        m_num = re.match(r'#\s*define\s+([A-Za-z_]\w*)\s+(0[xX][0-9a-fA-F]+|\d+)\s*$', stripped)
        if m_num and not m_num.group(1).startswith('_'):
            out.append(f'enum {{ {m_num.group(1)} = {m_num.group(2)} }};')
            continue
        # #define NAME IDENTIFIER → typedef IDENTIFIER NAME;
        m_id = re.match(r'#\s*define\s+([A-Za-z_]\w*)\s+([A-Za-z_]\w*)\s*$', stripped)
        if m_id and not m_id.group(1).startswith('_'):
            out.append(f'typedef {m_id.group(2)} {m_id.group(1)};')
            continue
        out.append('')
    result = '\n'.join(out)
    # 중괄호 균형 맞추기: extern "C" { 제거로 인한 불일치 교정
    # 여는 괄호보다 닫는 괄호가 많으면, 단독 줄의 } 를 순서대로 제거
    open_count = result.count('{')
    close_count = result.count('}')
    if close_count > open_count:
        excess = close_count - open_count
        fixed_lines = result.splitlines()
        removed = 0
        for i in range(len(fixed_lines) - 1, -1, -1):
            if removed >= excess:
                break
            if fixed_lines[i].strip() == '}':
                fixed_lines[i] = ''
                removed += 1
        result = '\n'.join(fixed_lines)
    return result


def _resolve_headers(content: str, job_root: Path) -> Tuple[str, str]:
    """소스 파일의 #include "local.h" 를 탐색하여 헤더를 읽고
    pycparser가 이해할 수 있는 형태로 가공한다.
    Returns: (processed_header_code, macro_func_declarations)
    """
    includes = re.findall(r'#\s*include\s+"([^"]+)"', content)
    header_parts: list = []
    macro_parts: list = []
    seen: set = set()

    def _process_include(inc_name: str):
        if inc_name in seen:
            return
        seen.add(inc_name)
        for h_file in job_root.rglob(inc_name):
            try:
                h_raw = h_file.read_text(encoding="utf-8", errors="replace")
                h_clean = _strip_c_comments(h_raw)
                macro_parts.append(_extract_macro_func_decls(h_clean))
                sub_includes = re.findall(r'#\s*include\s+"([^"]+)"', h_clean)
                for sub in sub_includes:
                    _process_include(sub)
                header_parts.append(_process_header_content(h_clean))
            except Exception:
                pass
            break

    for inc in includes:
        _process_include(inc)

    return '\n'.join(header_parts), '\n'.join(macro_parts)


# ── AST 노드 유틸 ──

def _get_line(node) -> Optional[int]:
    """pycparser 노드의 줄 번호 (1-based)."""
    if node is None:
        return None
    coord = getattr(node, "coord", None)
    if coord is None:
        return None
    return getattr(coord, "line", None)


def _extract_calls_from_ast(ast_node, line_offset: int = 0) -> List[Dict[str, Any]]:
    """c_ast 노드 서브트리에서 함수 호출 (name, line) 수집.
    line_offset 이하의 줄(preamble 영역)은 건너뛴다."""
    calls: List[Dict[str, Any]] = []
    try:
        from pycparser import c_ast
    except ImportError:
        return calls

    class FuncCallVisitor(c_ast.NodeVisitor):
        def visit_FuncCall(self, node):
            name = None
            if hasattr(node, "name") and node.name is not None:
                if hasattr(node.name, "name"):
                    name = node.name.name
                elif hasattr(node.name, "declname"):
                    name = getattr(node.name, "declname", None)
            if name and isinstance(name, str):
                raw_line = _get_line(node) or 0
                if raw_line > line_offset:
                    calls.append({"name": name, "line": raw_line - line_offset})
            self.generic_visit(node)

    try:
        FuncCallVisitor().visit(ast_node)
    except Exception:
        pass
    return calls


def _build_c_ast_schema(ast_root, content: str, line_offset: int = 0) -> Dict[str, Any]:
    """pycparser AST → 우리 스키마.
    line_offset: preamble 줄 수 (원본 소스 줄 번호 = AST 줄 번호 - offset)"""
    from pycparser import c_ast

    functions: List[Dict[str, Any]] = []
    file_calls: List[Dict[str, Any]] = []

    class FuncDefVisitor(c_ast.NodeVisitor):
        def visit_FuncDef(self, node: c_ast.FuncDef):
            name = None
            if hasattr(node, "decl") and node.decl is not None and hasattr(node.decl, "name"):
                name = node.decl.name
            if not name:
                self.generic_visit(node)
                return

            raw_line = _get_line(node) or 0
            if raw_line <= line_offset:
                self.generic_visit(node)
                return

            line = raw_line - line_offset
            end_line = line
            if hasattr(node, "body") and node.body is not None:
                raw_end = _get_line(node.body) or raw_line
                end_line = max(line, raw_end - line_offset)
                if hasattr(node.body, "block_items") and node.body.block_items:
                    for child in node.body.block_items:
                        el = _get_line(child)
                        if el is not None and el > line_offset:
                            end_line = max(end_line, el - line_offset)

            calls = _extract_calls_from_ast(node, line_offset)
            for c in calls:
                file_calls.append(c)
            functions.append({
                "name": name,
                "line": line,
                "end_line": end_line,
                "calls": calls,
            })
            self.generic_visit(node)

    try:
        FuncDefVisitor().visit(ast_root)
    except Exception:
        pass

    if not file_calls and ast_root is not None:
        file_calls = _extract_calls_from_ast(ast_root, line_offset)

    return {
        "language": "c",
        "functions": functions,
        "file_calls": file_calls,
    }


def _parse_c_with_gcc(
    content: str,
    filename: str,
    file_path: Optional[Path] = None,
    job_root: Optional[Path] = None,
) -> Optional[Dict[str, Any]]:
    """gcc -E 전처리 후 pycparser 파싱 → AST 스키마 반환.

    ast_checker_service._parse_with_gcc 와 동일한 전략이지만,
    여기서는 _build_c_ast_schema 까지 수행하여 functions/file_calls 스키마를 반환한다.
    gcc/clang 없는 환경에서는 None 반환.
    """
    import shutil
    import subprocess
    import tempfile
    import os

    compiler = shutil.which("gcc") or shutil.which("clang")
    if not compiler:
        return None

    try:
        from pycparser import c_parser
    except ImportError:
        return None

    # include 경로 수집
    include_dirs: List[str] = []
    if file_path:
        include_dirs.append(str(file_path.parent))
    if job_root:
        seen: set = set()
        for h in job_root.rglob("*.h"):
            d = str(h.parent)
            if d not in seen:
                seen.add(d)
                include_dirs.append(d)

    with tempfile.NamedTemporaryFile(suffix=".c", mode="w", encoding="utf-8", delete=False) as f:
        f.write(content)
        tmp_path = f.name

    try:
        cmd = [
            compiler, "-E", "-x", "c",
            "-D__attribute__(x)=", "-D__asm__(x)=",
            "-D__inline=", "-D__restrict=", "-D__extension__=",
        ]
        for d in include_dirs:
            cmd += [f"-I{d}"]
        cmd.append(tmp_path)

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        if result.returncode != 0:
            return None

        # 시스템 경로 제외, 프로젝트 코드만 추출
        _SYS = ("/usr/", "/Library/", "/Applications/", "<built-in>", "<command")
        lines_out = result.stdout.splitlines()
        in_project = True
        extracted: List[str] = []
        for ln in lines_out:
            if ln.startswith("#"):
                m = re.match(r'^# \d+ "([^"]+)"', ln)
                if m:
                    in_project = not any(m.group(1).startswith(p) for p in _SYS)
            elif in_project:
                extracted.append(ln)

        project_code = "\n".join(extracted)
        if not project_code.strip():
            return None

        preamble = _PYCPARSER_PREAMBLE
        offset = preamble.count("\n")
        parser = c_parser.CParser()
        ast = parser.parse(preamble + project_code, filename=filename)
        if ast is not None:
            return _build_c_ast_schema(ast, content, line_offset=offset)
    except Exception:
        pass
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass

    return None


def _parse_c_file(
    content: str,
    filename: str,
    job_root: Optional[Path] = None,
    file_path: Optional[Path] = None,
) -> Optional[Dict[str, Any]]:
    """C 소스를 파싱해 AST 스키마 반환.
    4단계 시도:
      0) gcc -E 전처리 (가장 정확 — include/macro 완전 처리)
      1) 전체 전처리 (헤더 텍스트 직접 삽입 + 공통 타입 + 매크로)
      2) 간단 전처리 (공통 타입 + 소스 내 매크로만)
      3) 최소 전처리 (주석/전처리 제거만)
    """
    try:
        from pycparser import c_parser
    except ImportError:
        return None

    # ── 시도 0: gcc -E (실제 환경에서 가장 정확) ──
    if file_path:
        result = _parse_c_with_gcc(content, filename, file_path=file_path, job_root=job_root)
        if result is not None:
            return result

    no_comments = _strip_c_comments(content)

    # 전처리 지시어를 빈 줄로 치환 (멀티라인 매크로 연속 줄 포함)
    src_lines: list = []
    in_define = False
    for line in no_comments.splitlines():
        stripped = line.lstrip()
        if in_define:
            src_lines.append('')
            in_define = line.rstrip().endswith('\\')
        elif stripped.startswith('#'):
            src_lines.append('')
            in_define = line.rstrip().endswith('\\')
        else:
            src_lines.append(line)
    source_clean = '\n'.join(src_lines)

    src_macro_decls = _extract_macro_func_decls(no_comments)

    parser = c_parser.CParser()

    # ── 시도 1: 헤더 해석 포함 전체 전처리 ──
    if job_root and file_path:
        try:
            header_code, hdr_macro_decls = _resolve_headers(content, job_root)
            all_macros = src_macro_decls + hdr_macro_decls
            preamble = _PYCPARSER_PREAMBLE + header_code + '\n' + all_macros
            offset = preamble.count('\n')
            to_parse = preamble + source_clean
            if to_parse.strip():
                ast = parser.parse(to_parse, filename=filename)
                if ast is not None:
                    return _build_c_ast_schema(ast, content, line_offset=offset)
        except Exception:
            pass

    # ── 시도 2: 공통 타입 + 소스 매크로만 ──
    try:
        preamble2 = _PYCPARSER_PREAMBLE + src_macro_decls
        offset2 = preamble2.count('\n')
        to_parse2 = preamble2 + source_clean
        if to_parse2.strip():
            ast = parser.parse(to_parse2, filename=filename)
            if ast is not None:
                return _build_c_ast_schema(ast, content, line_offset=offset2)
    except Exception:
        pass

    # ── 시도 3: 최소 전처리 (preamble 없음) ──
    try:
        if source_clean.strip():
            ast = parser.parse(source_clean, filename=filename)
            if ast is not None:
                return _build_c_ast_schema(ast, content, line_offset=0)
    except Exception:
        pass

    return None


# ── 파일 탐색 / 전처리 진입점 ──

def list_source_files(root: Path) -> List[Path]:
    """분석 대상 소스 파일 목록 (확장자 필터)."""
    files: list = []
    for ext in SOURCE_EXTENSIONS:
        files.extend(root.rglob(f"*{ext}"))
    return [f for f in files if f.is_file()]


def build_ast_for_file(file_path: Path, job_root: Path, content: Optional[str] = None) -> Dict[str, Any]:
    """단일 파일에 대해 AST(또는 구조화된 표현) 생성."""
    try:
        rel = file_path.resolve().relative_to(job_root.resolve())
        path_display = str(rel).replace("\\", "/")
    except ValueError:
        path_display = str(file_path)

    raw_content = content
    if raw_content is None:
        try:
            raw_content = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return {"path": path_display, "ast": {}, "lines": [], "errors": ["read_failed"]}

    lines = raw_content.splitlines() if raw_content else []
    ext = file_path.suffix.lower()

    ast_data: Dict[str, Any] = {}
    per_file_errors: List[str] = []
    if ext in (".c", ".h"):
        if _HAS_LIBCLANG:
            # libclang 설치 시: pycparser AST 파싱 생략.
            # AST 분석은 ast_checker_service(libclang)와
            # enhanced_symbol_graph_service(libclang)가 직접 수행한다.
            ast_data = {}
        else:
            # libclang 미설치 시: pycparser fallback (symbol_graph 등에서 필요)
            ast_data = _parse_c_file(
                raw_content, file_path.name,
                job_root=job_root, file_path=file_path,
            ) or {}
            if not ast_data:
                per_file_errors.append("c_parse_failed")
    elif ext == ".py":
        try:
            import ast as py_ast
            tree = py_ast.parse(raw_content)
            funcs: list = []
            file_calls: list = []
            for node in py_ast.walk(tree):
                if isinstance(node, py_ast.FunctionDef):
                    funcs.append({
                        "name": node.name,
                        "line": node.lineno,
                        "end_line": getattr(node, "end_lineno", node.lineno),
                        "calls": [],
                    })
                if isinstance(node, py_ast.Call):
                    name = None
                    if isinstance(node.func, py_ast.Name):
                        name = node.func.id
                    if name:
                        file_calls.append({"name": name, "line": node.lineno})
            ast_data = {"language": "python", "functions": funcs, "file_calls": file_calls}
        except Exception:
            ast_data = {}
            per_file_errors.append("python_parse_failed")

    return {
        "path": path_display,
        "ast": ast_data,
        "lines": lines,
        "errors": per_file_errors,
    }


def run_preprocess(job_root: Path) -> Dict[str, Any]:
    """job 루트 전체 전처리."""
    files = list_source_files(job_root)
    result: Dict[str, Any] = {"files": [], "errors": []}
    for fp in files:
        try:
            result["files"].append(build_ast_for_file(fp, job_root))
        except Exception as e:
            result["errors"].append({"file": str(fp), "error": str(e)})
    return result
