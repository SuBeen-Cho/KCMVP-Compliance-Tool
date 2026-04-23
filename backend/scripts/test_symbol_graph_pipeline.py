"""
전체 파이프라인 테스트: 전처리 → 심볼 그래프 → 룰 엔진.
- "모듈 전체"가 파일별 AST + symbol_graph(정의/호출 연결)로 잘 담기는지 검증.
- symbol_graph.json 구조, call_graph 연결, COM-001 크로스파일 판정 확인.
"""
import json
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

from app.services.upload_service import create_job_from_upload, get_job_root
from app.services.preprocess_service import run_preprocess
from app.services.symbol_graph_service import build_symbol_graph
from app.services.rule_engine_service import run_rule_engine

RULES_DIR = BACKEND / "rules"
ZIP_PATH = BACKEND / "testdata" / "ast_test.zip"


def main():
    if not ZIP_PATH.is_file():
        print("먼저 scripts/create_ast_test_zip.py 를 실행하세요.")
        return 1

    content = ZIP_PATH.read_bytes()
    job_id = create_job_from_upload(content, "ast_test.zip")
    root = get_job_root(job_id)

    print("=== 1. 전처리 (파일별 AST) ===")
    preprocess_result = run_preprocess(root)
    files = preprocess_result.get("files", [])
    print("  files:", len(files))
    for f in files:
        path = f.get("path", "")
        ast = f.get("ast") or {}
        has_ast = bool(ast and (ast.get("functions") or ast.get("file_calls")))
        print("    ", path, "AST:", "OK" if has_ast else "empty")

    print("\n=== 2. 심볼 그래프 (모듈 전체 흐름) ===")
    symbol_graph = build_symbol_graph(preprocess_result)
    definitions = symbol_graph.get("definitions") or {}
    call_graph = symbol_graph.get("call_graph") or []
    files_with_clearing = symbol_graph.get("files_with_clearing_call") or []

    print("  definitions 함수 수:", len(definitions))
    print("  call_graph 엣지 수:", len(call_graph))
    print("  files_with_clearing_call:", files_with_clearing)

    # 기대: secure_clear가 src/secure_clear.c에 정의
    defs_secure_clear = definitions.get("secure_clear") or []
    ok = True
    if not defs_secure_clear:
        print("  FAIL: definitions['secure_clear'] 없음")
        ok = False
    else:
        files_def = [d.get("file") for d in defs_secure_clear]
        if "src/secure_clear.c" not in files_def:
            print("  FAIL: secure_clear 정의가 src/secure_clear.c에 있어야 함. 실제:", files_def)
            ok = False
        else:
            print("  OK: secure_clear 정의 위치 =", files_def)

    # 기대: uses_secure_clear.c -> secure_clear -> defined_in = src/secure_clear.c
    edge_uses = [e for e in call_graph if e.get("caller_file") == "src/uses_secure_clear.c" and e.get("callee_name") == "secure_clear"]
    if not edge_uses:
        print("  FAIL: call_graph에 src/uses_secure_clear.c -> secure_clear 엣지 없음")
        ok = False
    else:
        e = edge_uses[0]
        if e.get("defined_in") != "src/secure_clear.c":
            print("  FAIL: defined_in 기대 src/secure_clear.c, 실제:", e.get("defined_in"))
            ok = False
        else:
            print("  OK: uses_secure_clear.c -> secure_clear -> defined_in = src/secure_clear.c")

    # 기대: secure_clear.c는 memset을 쓰므로 files_with_clearing_call에 포함
    if "src/secure_clear.c" not in files_with_clearing:
        print("  FAIL: src/secure_clear.c가 files_with_clearing_call에 있어야 함 (memset 사용)")
        ok = False
    else:
        print("  OK: src/secure_clear.c가 제거 호출 포함 파일 목록에 있음")

    print("\n=== 3. 룰 엔진 (symbol_graph 전달) ===")
    violations = run_rule_engine(
        preprocess_result, RULES_DIR, job_root=root, symbol_graph=symbol_graph
    )
    com001_files = [v["file"] for v in violations if v.get("rule_id") == "COM-001"]
    print("  COM-001 위반 파일:", com001_files)

    # 기대: uses_secure_clear.c는 COM-001 위반이 아님 (다른 파일에서 secure_clear로 제거)
    if "src/uses_secure_clear.c" in com001_files:
        print("  FAIL: src/uses_secure_clear.c는 COM-001 위반이 아니어야 함 (secure_clear 호출 → 정의 파일에 memset)")
        ok = False
    else:
        print("  OK: uses_secure_clear.c는 COM-001 비위반 (크로스파일 인정)")

    expected_com001 = {"src/no_clear.c", "src/hardcoded_key.c", "include/secure_clear.h"}
    if set(com001_files) != expected_com001:
        print("  FAIL: COM-001 위반 집합 기대", expected_com001, "실제", set(com001_files))
        ok = False
    else:
        print("  OK: COM-001 위반 집합 일치")

    # 저장 (API와 동일하게)
    (root / "preprocess_result.json").write_text(
        json.dumps(preprocess_result, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    (root / "symbol_graph.json").write_text(
        json.dumps(symbol_graph, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    (root / "violations.json").write_text(
        json.dumps(violations, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print("\n  저장됨: preprocess_result.json, symbol_graph.json, violations.json")

    if ok:
        print("\n=== 결과: 전체 파이프라인 정상 동작 (파일별 AST + 심볼 연결 → 모듈 흐름 반영) ===")
    else:
        print("\n=== 결과: 일부 검증 실패 ===")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
