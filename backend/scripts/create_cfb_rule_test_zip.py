"""
CFB-LEA-001 전용 테스트 ZIP 생성기.

목표
- mode/cfb.yaml 의 CFB-LEA-001 (pattern_type=missing, scope=project)이
  실제로 잘 동작하는지 단독으로 확인한다.

생성되는 ZIP
- backend/testdata/cfb_rule_fail.zip : lea_cfb128_* 심볼이 전혀 없음 → CFB-LEA-001 위반 기대
- backend/testdata/cfb_rule_pass.zip : lea_cfb128_enc/dec 심볼 포함 → CFB-LEA-001 통과 기대
"""

from __future__ import annotations

import zipfile
from pathlib import Path


BACKEND = Path(__file__).resolve().parent.parent
OUT_DIR = BACKEND / "testdata"
OUT_DIR.mkdir(parents=True, exist_ok=True)

ZIP_FAIL = OUT_DIR / "cfb_rule_fail.zip"
ZIP_PASS = OUT_DIR / "cfb_rule_pass.zip"


def _write_zip(zip_path: Path, *, variant: str) -> None:
    is_fail = variant == "fail"

    # lea_locl.h: 최소 헤더만 제공
    locl_h = (
        "#ifndef LEA_LOCL_H\n"
        "#define LEA_LOCL_H\n"
        "/* empty - CFB rule test only */\n"
        "#endif\n"
    )

    if is_fail:
        c_source = """#include \"lea_locl.h\"

/* CFB-LEA-001 위반 케이스: CFB-128용 전용 API 심볼이 전혀 없음 */

void dummy(void) {
    /* no CFB API here */
}
"""
    else:
        c_source = """#include \"lea_locl.h\"

/* CFB-LEA-001 통과 케이스: lea_cfb128_enc/dec 심볼 존재 */

void lea_cfb128_enc(void);
void lea_cfb128_dec(void);

void dummy(void) {
    lea_cfb128_enc();
}
"""

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("include/lea_locl.h", locl_h)
        zf.writestr("src/cfb_rule_test.c", c_source)


def main() -> None:
    _write_zip(ZIP_FAIL, variant="fail")
    _write_zip(ZIP_PASS, variant="pass")
    print("✅ 생성됨:")
    print(" -", ZIP_FAIL)
    print(" -", ZIP_PASS)


if __name__ == "__main__":
    main()

