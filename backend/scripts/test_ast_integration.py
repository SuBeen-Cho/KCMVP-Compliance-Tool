"""
AST 전처리 + 룰 엔진 통합 테스트.
- testdata/ast_test.zip 을 업로드하여 job 생성 후 전처리·룰 엔진 실행.
- COM-001 위반은 src/no_clear.c 만 나와야 하고, 나머지 .c는 비위반 기대.
"""
import json
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

from app.services.upload_service import create_job_from_upload, get_job_root
from app.services.preprocess_service import run_preprocess
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

    print("job_id:", job_id)
    print("run_preprocess...")
    preprocess_result = run_preprocess(root)
    print("  files:", len(preprocess_result.get("files", [])))
    print("  errors:", len(preprocess_result.get("errors", [])))

    for f in preprocess_result.get("files", []):
        path = f.get("path", "")
        ast = f.get("ast") or {}
        has_ast = bool(ast and (ast.get("functions") or ast.get("file_calls")))
        print("  -", path, "AST:", "OK" if has_ast else "empty")

    print("run_rule_engine...")
    violations = run_rule_engine(preprocess_result, RULES_DIR, job_root=root)
    print("  violations count:", len(violations))

    # 전처리 결과·위반 저장 (해당 job_id로 API/UI에서 조회 가능)
    (root / "preprocess_result.json").write_text(
        json.dumps(preprocess_result, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    (root / "violations.json").write_text(
        json.dumps(violations, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    com001_files = [v["file"] for v in violations if v.get("rule_id") == "COM-001"]
    com003_files = [v["file"] for v in violations if v.get("rule_id") == "COM-003"]

    print("  COM-001 위반 파일:", com001_files)
    print("  COM-003 위반 파일:", com003_files)

    # 기대: COM-001은 no_clear.c, hardcoded_key.c(제거 없음), include/secure_clear.h(AST 비어 있어 정규식만 적용)
    expected_com001 = ["src/no_clear.c", "src/hardcoded_key.c", "include/secure_clear.h"]
    ok = True
    for f in expected_com001:
        if f not in com001_files:
            print("  FAIL: 기대 COM-001 위반 없음:", f)
            ok = False
    if set(com001_files) != set(expected_com001):
        print("  FAIL: COM-001 위반 집합 불일치. 기대:", expected_com001, "실제:", com001_files)
        ok = False
    if "src/hardcoded_key.c" not in com003_files:
        print("  FAIL: 기대 COM-003 위반 없음: src/hardcoded_key.c")
        ok = False

    if ok:
        print("  기대대로 동작함.")
    else:
        print("  일부 실패.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
