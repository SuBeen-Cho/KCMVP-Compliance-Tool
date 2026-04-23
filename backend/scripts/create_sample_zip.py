"""
예시용 ZIP 파일 생성 스크립트.
- backend/testdata/sample.zip 을 만듦 (테스트용 C 소스 몇 개 포함).
- 한 번만 실행: ./venv/bin/python scripts/create_sample_zip.py
"""
import zipfile
from pathlib import Path

# backend/scripts/ 기준이므로 상위가 backend
BACKEND = Path(__file__).resolve().parent.parent
OUT_DIR = BACKEND / "testdata"
ZIP_PATH = OUT_DIR / "sample.zip"

CONTENTS = {
    "src/main.c": b"#include <stdio.h>\n#include \"lea.h\"\n\nint main(void) {\n    unsigned char key[16] = {0};\n    unsigned char plain[16] = {0};\n    unsigned char cipher[16] = {0};\n    lea_encrypt(key, plain, cipher);\n    return 0;\n}\n",
    "src/lea.c": b"#include \"lea.h\"\n#include <string.h>\n\nvoid lea_encrypt(const unsigned char* key, const unsigned char* plain, unsigned char* cipher) {\n    (void)key;\n    (void)plain;\n    (void)cipher;\n}\n",
    "include/lea.h": b"#ifndef LEA_H\n#define LEA_H\n\nvoid lea_encrypt(const unsigned char* key, const unsigned char* plain, unsigned char* cipher);\n\n#endif\n",
}


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(ZIP_PATH, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, data in CONTENTS.items():
            zf.writestr(path, data)
    print("생성됨:", ZIP_PATH.resolve())
    print("안에 들어 있는 파일:", list(CONTENTS.keys()))


if __name__ == "__main__":
    main()
