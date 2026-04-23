"""
upload_service ZIP 압축 해제 동작 확인용 스크립트.

예시 ZIP 파일로 테스트하려면:
  1) 예시 ZIP 생성 (한 번만): ./venv/bin/python scripts/create_sample_zip.py
  2) 테스트 실행: ./venv/bin/python scripts/test_upload.py testdata/sample.zip

인자 없이 실행하면 메모리에서 만든 더미 ZIP으로 테스트합니다.
  ./venv/bin/python scripts/test_upload.py
"""
import io
import zipfile
import sys
from pathlib import Path

# backend 폴더를 기준으로 하므로, 스크립트는 backend 안에서 실행해야 함
BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

from app.services.upload_service import create_job_from_upload, get_job_root


def make_test_zip_bytes() -> bytes:
    """테스트용 ZIP 내용을 바이트로 만듦 (실제 ZIP 파일 없이)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("src/main.c", b"// test\n#include <stdio.h>\nint main() { return 0; }\n")
        zf.writestr("src/lea.c", b"// LEA placeholder\nvoid lea_encrypt() {}\n")
        zf.writestr("include/lea.h", b"#ifndef LEA_H\n#define LEA_H\nvoid lea_encrypt();\n#endif\n")
    return buf.getvalue()


def main():
    # 인자로 ZIP 경로가 주어지면 그 파일 사용, 없으면 메모리에서 생성
    if len(sys.argv) >= 2:
        zip_path = Path(sys.argv[1])
        if not zip_path.is_absolute():
            zip_path = (BACKEND / zip_path).resolve()
        if not zip_path.exists():
            print("파일 없음:", zip_path)
            print("예시 ZIP을 먼저 만드세요: ./venv/bin/python scripts/create_sample_zip.py")
            sys.exit(1)
        print("1. ZIP 파일 사용:", zip_path)
        zip_bytes = zip_path.read_bytes()
        print("   바이트 수:", len(zip_bytes))
    else:
        print("1. 테스트용 ZIP 내용 생성 중...")
        zip_bytes = make_test_zip_bytes()
        print("   완료 (바이트 수:", len(zip_bytes), ")")

    print("2. create_job_from_upload 호출 중...")
    job_id = create_job_from_upload(zip_bytes, "sample.zip")
    print("   job_id:", job_id)

    root = get_job_root(job_id)
    print("3. 압축 해제된 폴더:", root.resolve())
    print("   폴더 존재 여부:", root.exists())

    print("4. 폴더 안에 있는 파일/폴더 목록:")
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root)
        kind = "dir " if p.is_dir() else "file"
        print("   ", kind, " ", rel)

    print("\n-> 위처럼 파일들이 나오면 ZIP 압축 해제가 정상 동작한 것입니다.")


if __name__ == "__main__":
    main()
