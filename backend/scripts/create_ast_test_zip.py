"""
AST 및 COM-001/COM-003 탐지 테스트용 ZIP 생성.
- backend/testdata/ast_test.zip 생성.
- 다양한 케이스: COM-001 위반/비위반, COM-003 위반, secure_clear 래퍼 등.
- #include 없이 작성해 pycparser 파싱 성공률을 높임.

실행 (backend 디렉터리에서):
  python scripts/create_ast_test_zip.py
"""
import zipfile
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
OUT_DIR = BACKEND / "testdata"
OUT_DIR.mkdir(parents=True, exist_ok=True)
ZIP_PATH = OUT_DIR / "ast_test.zip"

CONTENTS = {
    "src/no_clear.c": """
void use_key_no_clear(void) {
    unsigned char key[16];
    unsigned char buf[32];
    do_something(key);
    do_encrypt(buf);
}
""",
    "src/has_memset.c": """
void use_key_ok(void) {
    unsigned char key[16];
    load_key(key);
    do_encrypt(key);
    memset(key, 0, sizeof(key));
}
""",
    "src/uses_secure_clear.c": """
void use_key_via_wrapper(void) {
    unsigned char key[16];
    load_key(key);
    do_encrypt(key);
    secure_clear(key, 16);
}
""",
    "src/secure_clear.c": """
void secure_clear(unsigned char* buf, unsigned int len) {
    unsigned int i;
    for (i = 0; i < len; i++) buf[i] = 0;
}
void secure_clear_memset(unsigned char* buf, unsigned int len) {
    memset(buf, 0, len);
}
""",
    "src/hardcoded_key.c": """
static const unsigned char KEY[16] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
};
void use_hardcoded(void) {
    encrypt_block(KEY);
}
""",
    "src/has_explicit_bzero.c": """
void cleanup(void) {
    unsigned char secret[32];
    get_secret(secret);
    explicit_bzero(secret, sizeof(secret));
}
""",
    "include/secure_clear.h": """
#ifndef SECURE_CLEAR_H
#define SECURE_CLEAR_H
void secure_clear(unsigned char* buf, unsigned int len);
#endif
""",
}


def main() -> None:
    with zipfile.ZipFile(ZIP_PATH, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, data in CONTENTS.items():
            zf.writestr(path, data.encode("utf-8"))
    print("생성됨:", ZIP_PATH.resolve())
    print("파일 목록:", list(CONTENTS.keys()))
    print("기대 COM-001 위반: src/no_clear.c")
    print("기대 COM-001 비위반: has_memset, has_explicit_bzero, uses_secure_clear, secure_clear")
    print("기대 COM-003 위반: src/hardcoded_key.c")


if __name__ == "__main__":
    main()
