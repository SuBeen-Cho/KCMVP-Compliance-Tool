"""
L1 COM-001 동작 확인: upload → preprocess → run_rule_engine → violations 출력.
실행: backend 폴더에서
  ./venv/bin/python scripts/test_l1.py testdata/sample.zip
"""
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))
RULES_DIR = BACKEND / "rules"

from app.services.upload_service import create_job_from_upload, get_job_root
from app.services.preprocess_service import run_preprocess
from app.services.rule_engine_service import run_rule_engine


def main():
    zip_path = BACKEND / "testdata" / "sample.zip"
    if not zip_path.exists():
        print("testdata/sample.zip 없음. create_sample_zip.py 먼저 실행하세요.")
        sys.exit(1)
    zip_bytes = zip_path.read_bytes()

    job_id = create_job_from_upload(zip_bytes, "sample.zip")
    root = get_job_root(job_id)
    preprocess_result = run_preprocess(root)
    violations = run_rule_engine(preprocess_result, RULES_DIR, job_root=root)

    print("job_id:", job_id)
    print("preprocess file_count:", len(preprocess_result.get("files", [])))
    print("violations_count:", len(violations))
    for v in violations:
        print(" ", v.get("rule_id"), v.get("file"), v.get("message"))
    if not violations:
        print("(위반 없음 - sample.zip에 memset 등이 있으면 0건일 수 있음)")


if __name__ == "__main__":
    main()
