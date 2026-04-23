"""
LEA 모드 룰셋(모드/공통) 판정용 테스트 ZIP 생성.

목표
- L1 룰 엔진(run_rule_engine)이 실제로 적용하는 pattern_type("missing", "regex")에 대해
  CCM/GCM/CFB/OFB/CMAC 관련 룰이 기대한 대로 위반으로 잡히는지 확인한다.
- semantic pattern_type 룰은 현재 L1 룰 엔진에서 제외되므로, 테스트 기대 위반 집합은
  regex/missing 위주로 구성한다.

생성되는 ZIP
- backend/testdata/lea_mode_rules_fail_v2.zip  : 새로 추가한 룰을 일부러 위반(정상 제외)
- backend/testdata/lea_mode_rules_pass_v2.zip  : 위반하지 않음(참조/문자열만 포함)

실행
  cd backend
  python scripts/create_lea_mode_rules_test_zip.py
"""

from __future__ import annotations

import zipfile
from pathlib import Path


BACKEND = Path(__file__).resolve().parent.parent
OUT_DIR = BACKEND / "testdata"
OUT_DIR.mkdir(parents=True, exist_ok=True)

ZIP_FAIL = OUT_DIR / "lea_mode_rules_fail_v2.zip"
ZIP_PASS = OUT_DIR / "lea_mode_rules_pass_v2.zip"


def _build_stub_c_source(*, variant: str) -> str:
    """
    variant:
      - "fail": CCM/GCM/OFB 길이/IV 값은 일부러 범위 밖 + 모드 API 문자열/온라인 API 문자열은 생략
      - "pass": CCM/GCM/OFB 길이/IV 값 정상 + 모드 API 문자열/온라인 API 문자열 포함
    """

    if variant not in {"fail", "pass"}:
        raise ValueError("variant must be 'fail' or 'pass'")

    is_fail = variant == "fail"

    # CCM-002 / CCM-003 (regex 위반 유도)
    ccm_nonce_len = 6 if is_fail else 12  # 7~13 범위 밖 / 안
    ccm_tag_len = 5 if is_fail else 8     # {4,6,8,10,12,14,16} 범위 밖 / 안

    # GCM-002 (regex 위반 유도): 규칙 패턴이 "invalid 길이"만 매칭하도록 작성되어 있어
    #  - fail: 0~3 또는 >=17 값만 넣으면 위반이 잡힌다
    gcm_t_len = 3 if is_fail else 16

    # OFB-001 (regex 위반 유도): OFB는 iv[16]만 허용, 그 외 길이는 위반이 잡힘
    ofb_iv_len = 15 if is_fail else 16

    include_online_api = not is_fail  # COM-006( missing ) 통과용

    # 모드 API missing 규칙들 통과/위반 여부
    include_ccm_api = not is_fail
    include_gcm_api = not is_fail
    include_gcm_ghash_accel = not is_fail  # GCM-LEA-002 통과용
    # CFB API는 개별 파일(src/cfb_*.c)에서만 통제한다.
    include_cfb_api = False
    include_ofb_api = not is_fail
    include_cmac_api = not is_fail

    # COM-001 통과용: AST file_calls를 통해 memset_s 호출을 인식
    # - semantic 규칙은 L1에서 제외되므로 COM-001만 확실히 맞춘다.
    # - 이 함수는 코드 문법만 맞추면 parse가 되며, file_calls에 "memset_s"가 포함된다.

    # DELTA 상수(LEA-011 missing 통과용)
    # COM-003은 (0x....,){8,} 패턴만 잡도록 되어 있어, 여기서는 상수 1개만 넣어
    # COM-003 오탐을 피한다(엔진은 LEA-011을 "하나라도 있으면 통과"로 처리).
    delta_one = "0xc3efe9db"

    # KAT/MMT/MCT 파일명 패턴(LEA-048/LEA-058 missing 통과용) - 주석으로만 넣어도 re.search에 걸린다.
    # (요구사항 문자열의 형상만 맞추면 됨)
    kat_files = "\n".join(
        [
            "LEA128ECBKAT.req",
            "LEA128ECBKAT.rsp",
            "LEA128CBCKAT.req",
            "LEA128CBCKAT.rsp",
            "LEA128CTRKAT.req",
            "LEA128CTRKAT.rsp",
            "LEA128OFBKAT.req",
            "LEA128OFBKAT.rsp",
            "LEA128CFBKAT.req",
            "LEA128CFBKAT.rsp",
            # LEA-048/058 패턴은 'LEA[키길이][모드명][시험유형].ext' 형태를 기대
            # -> MMT/MCT는 모드 뒤에 그대로 붙는다.
            "LEA128ECBMMT.req",
            "LEA128ECBMMT.rsp",
            "LEA128ECBMCT.req",
            "LEA128ECBMCT.rsp",
        ]
    )

    # LEA-011은 δ[0]~δ[7] 누락을 "missing"으로 요구하지만,
    # 현재 L1 엔진은 alternation 패턴이므로(특정 상수 중 하나라도 있으면) 하나만 포함해도 통과한다.
    # 테스트는 "우리 목적(모드 룰 활성 확인)"에 초점을 맞추므로 이 정도로 충분하다.

    ccm_api_prototypes = ""
    if include_ccm_api:
        ccm_api_prototypes = "\nvoid lea_ccm_enc(void); void lea_ccm_dec(void);"

    gcm_api_prototypes = ""
    gcm_ghash_token = ""
    if include_gcm_api:
        gcm_api_prototypes = (
            "\nvoid lea_gcm_init(void);"
            "\nvoid lea_gcm_set_ctr(void);"
            "\nvoid lea_gcm_set_aad(void);"
            "\nvoid lea_gcm_encrypt(void);"
            "\nvoid lea_gcm_decrypt(void);"
            "\nvoid lea_gcm_final(void);"
        )
    if include_gcm_ghash_accel:
        gcm_ghash_token = "\n// ghash accel token: lea_gcm_pclmul\nvoid lea_gcm_pclmul(void);"

    cfb_api_prototypes = ""

    ofb_api_prototypes = ""
    if include_ofb_api:
        ofb_api_prototypes = "\nvoid lea_ofb_enc(void); void lea_ofb_dec(void);"

    cmac_api_prototypes = ""
    if include_cmac_api:
        cmac_api_prototypes = "\nvoid lea_cmac_init(void); void lea_cmac_update(void); void lea_cmac_final(void);"

    online_api = ""
    if include_online_api:
        online_api = (
            "\nvoid lea_online_init(void);"
            "\nvoid lea_online_update(void);"
            "\nvoid lea_online_final(void);"
        )

    # 모든 missing/regex(LEA-041 포함)는 content 기반 검색이라,
    # 문법을 해치지 않는 범위에서 "토큰/문자열"을 많이 삽입한다.
    # 주의: LEA-041은 s_box 토큰이 나오면 위반이 되므로 "s_box" 문자열은 금지한다.
    src = f"""\
#include "lea_locl.h"
#include <stdint.h>
#include <string.h>

// ================
// [공통] COM-001 통과를 위한 제거 함수 호출(= memset_s)
// ================
void clear_secret(void) {{
    unsigned char secret[32];
    // AST file_calls에 memset_s가 들어가게 하기 위함
    memset_s(secret, 0, sizeof(secret));
}}

// ================
// [LEA] missing 규칙 통과용 최소 토큰/구조
// ================
// LEA-001: block_size/len/length = 128
int block_len = 128;

// LEA-002: mk_len/key_len/keyLen = 16/24/32
unsigned int mk_len = 16;

// LEA-007: K[16|24|32]
unsigned char K[16];

// LEA-008: X[4]
uint32_t X[4];

// LEA-009: rk/RK[6]
uint32_t rk[6];

// LEA-004: uint32_t ... (rk|round_key|X|T|state|block|delta) 컨텍스트
uint32_t T[6];
uint32_t state[4];
uint32_t delta_arr[1] = {{{delta_one}}}; // LEA-011 매칭용 상수 1개만 포함(오탐 방지)

// LEA-012: 766995 문자열 존재
// 766995

// LEA-013: T = K 또는 memcpy(T, K
void lea_key_schedule_stub(unsigned char *mk) {{
    (void)mk;
    // pattern: memcpy(T, K
    memcpy(T, K, sizeof(K));
}}

// LEA 회전/워드 연산 패턴 토큰들(문법을 해치지 않기 위해 주석으로만 제공)
/*
  ROL1 ROL3 ROL6 ROL9 ROL11 ROL13 ROL17
  ROR5 ROR3 ROR9
  X = P; X = C; C = X; P = X_Nr;
*/

// LEA-051: lea_set_key 토큰
    // LEA-052 missing 패턴은 `.*`가 DOTALL 없이 동작하므로
    // `typedef/struct`와 `LEA_KEY` 사이가 같은 줄이어야 매칭이 됩니다.
    typedef struct {{ uint32_t rk[6]; unsigned int round; }} LEA_KEY;

int lea_set_key(LEA_KEY *key, const unsigned char *mk, unsigned int mk_len) {{
    (void)key;
    (void)mk;
    // LEA-053: return -N (음수 반환)
    return -1;
}}

// LEA-055: SIMD 심볼 토큰
// lea_t_sse2

// LEA-048/LEA-058: KAT/MMT/MCT 파일명 패턴 존재
/*
{kat_files}
*/

// ================
// [모드] 우리의 목적: L1 엔진의 regex/missing을 잡기 위한 문자열/값 삽입
// ================

// CCM-002: Nonce 길이(7~13 이외 위반)
unsigned int n_len = {ccm_nonce_len};

// CCM-003: Tag 길이(허용 집합 이외 위반)
unsigned int tag_len = {ccm_tag_len};

// GCM-002: tag 길이 invalid (규칙 패턴이 invalid 길이만 매칭하도록 작성됨)
unsigned int t_len = {gcm_t_len};

// OFB-001: iv 길이(16 이외 위반)
unsigned char iv[{ofb_iv_len}];

// ----------------
// [모드 API missing 규칙] pass/fail에 따라 "토큰" 포함/제외
// ----------------
{ccm_api_prototypes}
{gcm_api_prototypes}
{gcm_ghash_token}
{cfb_api_prototypes}
{ofb_api_prototypes}
{cmac_api_prototypes}

// ----------------
// [온라인 API missing 규칙] pass/fail에 따라 포함/제외(COM-006)
// ----------------
{online_api}

"""

    return src


def _build_mode_only_snippets(*, variant: str) -> dict[str, str]:
    """
    모드별로 더 잘게 쪼갠 테스트용 C 파일들.

    - fail:
      - 각 파일이 "해당 룰만" 위반하도록 값/토큰을 구성
    - pass:
      - 같은 토큰이지만 허용 범위 안으로 맞춰 위반이 발생하지 않도록 구성
    """
    is_fail = variant == "fail"

    # CCM: Nonce/Tag 길이
    ccm_bad = """#include <stdint.h>
unsigned int ccm_nonce_len = 6;   /* 7~13 범위 밖 → CCM-002 */
unsigned int ccm_tag_len = 5;     /* {4,6,8,10,12,14,16} 밖 → CCM-003 */
"""
    ccm_good = """#include <stdint.h>
unsigned int ccm_nonce_len = 12;  /* 7~13 범위 내 */
unsigned int ccm_tag_len = 8;     /* 허용 집합 내 */
"""

    # GCM: Tag 길이 / API 명칭 / GHASH 가속 토큰
    gcm_bad = """#include <stdint.h>
unsigned int gcm_tag_len = 3;   /* 4~16 밖 → GCM-002 */
"""
    gcm_good = """#include <stdint.h>
unsigned int gcm_tag_len = 16;  /* 4~16 범위 내 */
void lea_gcm_init(void);
void lea_gcm_set_ctr(void);
void lea_gcm_set_aad(void);
void lea_gcm_encrypt(void);
void lea_gcm_decrypt(void);
void lea_gcm_final(void);
/* GCM-LEA-002 통과용 토큰 */
void lea_gcm_pclmul(void);
"""

    # CFB: API 명칭
    cfb_bad = """#include <stdint.h>
/* intentionally no lea_cfb128_enc/dec → CFB-LEA-001 위반 */
"""
    cfb_good = """#include <stdint.h>
void lea_cfb128_enc(void);
void lea_cfb128_dec(void);
"""

    # OFB: IV 길이 / API 명칭
    ofb_bad = """#include <stdint.h>
unsigned char ofb_iv[15]; /* 16 이 아님 → OFB-001 */
"""
    ofb_good = """#include <stdint.h>
unsigned char ofb_iv[16];
void lea_ofb_enc(void);
void lea_ofb_dec(void);
"""

    # CMAC: API 명칭
    cmac_bad = """#include <stdint.h>
/* lea_cmac_* 심볼 없음 → CMAC-LEA-001 위반 기대 */
"""
    cmac_good = """#include <stdint.h>
void lea_cmac_init(void);
void lea_cmac_update(void);
void lea_cmac_final(void);
"""

    # 온라인 API(COM-006)
    online_bad = """#include <stdint.h>
/* lea_online_* 심볼 없음 → COM-006 위반 기대 */
"""
    online_good = """#include <stdint.h>
void lea_online_init(void);
void lea_online_update(void);
void lea_online_final(void);
"""

    if is_fail:
        return {
            "src/ccm_bad.c": ccm_bad,
            "src/gcm_bad.c": gcm_bad,
            "src/cfb_bad.c": cfb_bad,
            "src/ofb_bad.c": ofb_bad,
            "src/cmac_bad.c": cmac_bad,
            "src/online_bad.c": online_bad,
        }
    else:
        return {
            "src/ccm_good.c": ccm_good,
            "src/gcm_good.c": gcm_good,
            "src/cfb_good.c": cfb_good,
            "src/ofb_good.c": ofb_good,
            "src/cmac_good.c": cmac_good,
            "src/online_good.c": online_good,
        }


def _write_zip(zip_path: Path, *, variant: str) -> None:
    c_source = _build_stub_c_source(variant=variant)
    mode_snippets = _build_mode_only_snippets(variant=variant)

    # lea_locl.h는 실제로 존재할 필요는 없지만(규칙은 content re.search),
    # preprocess header resolve를 단순화하기 위해 최소 파일을 같이 넣는다.
    locl_h = (
        "#ifndef LEA_LOCL_H\n"
        "#define LEA_LOCL_H\n"
        "/* empty - tests only */\n"
        "#endif\n"
    )

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("include/lea_locl.h", locl_h)
        # 알고리즘/공통 + 모드 전체 토큰이 들어있는 메인 스텁
        zf.writestr("src/lea_mode_rules_stub.c", c_source)
        # 모드별로 더 잘게 분리된 파일들
        for rel_path, content in mode_snippets.items():
            zf.writestr(rel_path, content)


def main() -> None:
    _write_zip(ZIP_FAIL, variant="fail")
    _write_zip(ZIP_PASS, variant="pass")
    print("✅ 생성됨:")
    print(" -", ZIP_FAIL)
    print(" -", ZIP_PASS)


if __name__ == "__main__":
    main()

