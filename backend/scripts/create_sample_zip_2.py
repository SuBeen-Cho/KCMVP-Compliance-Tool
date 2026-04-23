"""
보다 복잡한 예시용 ZIP 파일 생성 스크립트.
- backend/testdata/testdata_2.zip 을 만듦.
- 일부 파일은 COM-001(잔존 정보 제거) + COM-003(하드코딩 키/IV) 위반이 섞여 있음.

실행 예시 (backend 디렉터리에서):
  ./venv/bin/python scripts/create_sample_zip_2.py
"""

import zipfile
from pathlib import Path

# backend/scripts/ 기준이므로 상위가 backend
BACKEND = Path(__file__).resolve().parent.parent
OUT_DIR = BACKEND / "testdata"
ZIP_PATH = OUT_DIR / "testdata_2.zip"

# COM-001: 잔존 정보 제거 없음 (memset/explicit_bzero 등 호출 전혀 없음)
# COM-003: 하드코딩된 키/IV 패턴 (0x.., 0x.. 형태 8개 이상)
# 주의: 아래 C 소스들은 UTF-8 문자열로 정의하고, writestr 시점에 인코딩합니다.
CONTENTS = {
    # 키가 하드코딩되어 있고, 어떤 정리 코드도 호출하지 않는 예제
    "src/key_storage.c": """#include <stdint.h>

// COM-003: 하드코딩된 키 (예제용)
static const uint8_t HARD_CODED_KEY[16] = {
    0x01, 0x23, 0x45, 0x67,
    0x89, 0xAB, 0xCD, 0xEF,
    0xFE, 0xDC, 0xBA, 0x98,
    0x76, 0x54, 0x32, 0x10
};

void use_key(void) {
    // TODO: HARD_CODED_KEY를 사용하는 코드 (예제)
}
""",
    # 세션 키/버퍼를 사용하지만, 사용 후 memset 등의 잔존 정보 제거를 하지 않는 예제
    "src/session.c": """#include <stdint.h>
#include <string.h>

void process_session(const uint8_t* input, uint8_t* output) {
    uint8_t session_key[16] = {0};
    uint8_t buffer[32] = {0};

    // 임의의 연산 (예제)
    for (int i = 0; i < 16; ++i) {
        session_key[i] = (uint8_t)(i * 3u);
    }
    for (int i = 0; i < 32; ++i) {
        buffer[i] = (uint8_t)(input[i % 16] ^ session_key[i % 16]);
    }

    // 결과 복사
    for (int i = 0; i < 32; ++i) {
        output[i] = buffer[i];
    }

    // COM-001 위반: session_key/buffer에 대해 memset 등으로 잔존 정보 제거를 하지 않음
}
""",
    # 잔존 정보 제거를 올바르게 수행하는 예제 (참고용, 위반이 없어야 함)
    "src/secure_clear.c": """#include <stdint.h>
#include <string.h>

void secure_process(const uint8_t* input, uint8_t* output) {
    uint8_t key[16] = {0};

    // ... 키 사용 ...
    for (int i = 0; i < 16; ++i) {
        key[i] = (uint8_t)(input[i] ^ 0xAAu);
        output[i] = key[i];
    }

    // COM-001 예외: 사용 후 명시적으로 잔존 정보 제거
    memset(key, 0, sizeof(key));
}
""",
    # 간단한 헤더 파일
    "include/session.h": """#ifndef SESSION_H
#define SESSION_H

#include <stdint.h>

void process_session(const uint8_t* input, uint8_t* output);
void secure_process(const uint8_t* input, uint8_t* output);

#endif
""",
}


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(ZIP_PATH, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, data in CONTENTS.items():
            # UTF-8로 인코딩하여 저장
            zf.writestr(path, data.encode("utf-8"))
    print("생성됨:", ZIP_PATH.resolve())
    print("안에 들어 있는 파일:")
    for key in CONTENTS.keys():
        print(" -", key)
    print()
    print("대략 기대되는 위반:")
    print(" - COM-001 (잔존 정보 제거): src/key_storage.c, src/session.c")
    print(" - COM-003 (하드코딩된 키/IV): src/key_storage.c")
    print(" - secure_clear.c는 COM-001에서 예외(정상 동작 예제)로 동작해야 함.")


if __name__ == "__main__":
    main()

