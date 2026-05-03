#!/usr/bin/env python3
"""
0_KCMVP 원본 코드 기반 Mutation Train 데이터셋 생성기
=====================================================
원본 파일(0_KCMVP.zip)을 메모리에서 읽어 특정 위반을 삽입,
세트 5~7 ZIP + 정답지_위반목록.md 를 생성한다.
원본 파일은 절대 수정하지 않는다.

생성 세트:
  세트 5: LEA 키스케줄 위반(LEA-016, LEA-011) + CBC 암호화 IV XOR 생략(CBC-001)
  세트 6: LEA 라운드함수 위반(LEA-027, LEA-028) + CTR 카운터 고정(CTR-002)
  세트 7: CBC 복호화 IV XOR 생략(CBC-002) + 하드코딩 키(COM-003) + CTR 방향 오류(CTR-001)

Usage:
    cd backend
    python scripts/create_mutation_sets.py
"""

import sys, os, zipfile, io, shutil
from pathlib import Path

BACKEND_ROOT = Path(__file__).parent.parent
KCMVP_ROOT   = BACKEND_ROOT.parent.parent  # KCMVP/
SET_BASE     = KCMVP_ROOT / "스크립트" / "코드 - 설계서 세트"
ORIG_ZIP     = BACKEND_ROOT.parent / "0_KCMVP.zip"   # KCMVP/Kcmvp_main_보완/0_KCMVP.zip


# ═══════════════════════════════════════════════════════════════════
# 1. 원본 파일 로드: 0_KCMVP.zip → smart-crypto-master.zip → 파일맵
# ═══════════════════════════════════════════════════════════════════

def load_original_files() -> dict[str, bytes]:
    """0_KCMVP.zip → smart-crypto-master.zip → 전체 파일 맵 반환."""
    files: dict[str, bytes] = {}
    with zipfile.ZipFile(ORIG_ZIP) as outer:
        inner_data = outer.read("smart-crypto-master.zip")
    with zipfile.ZipFile(io.BytesIO(inner_data)) as inner:
        for name in inner.namelist():
            if not name.endswith("/"):
                files[name] = inner.read(name)
    return files


# ═══════════════════════════════════════════════════════════════════
# 2. Base 레이어: 원본에 이미 존재하는 위반에 [위반: RULE-ID] 주석 추가
#    (평가 스크립트의 GT 자동 추출이 주석 파싱 기반이므로 필수)
# ═══════════════════════════════════════════════════════════════════

def apply_base_violations(files: dict[str, bytes]) -> dict[str, bytes]:
    """원본 violations를 주석으로 표기한 사본을 반환."""
    result = dict(files)  # shallow copy of references

    def patch(key: str, old: str, new: str) -> None:
        if key not in result:
            print(f"  [WARN] 파일 없음: {key}")
            return
        text = result[key].decode("utf-8", errors="replace")
        if old not in text:
            print(f"  [WARN] 패턴 미발견: {key!r} ← {old!r}")
            return
        result[key] = text.replace(old, new, 1).encode("utf-8")

    # COM-004: ec_kcdsa.c srand 3곳 (파일이 \r\n 줄바꿈 사용)
    if "src/ec_kcdsa.c" in result:
        text = result["src/ec_kcdsa.c"].decode("utf-8", errors="replace")
        SRAND = "srand((unsigned)time(NULL));"
        comments = [
            " /* [위반: COM-004] 비암호학적 RNG (KKEY) */",
            " /* [위반: COM-004] 비암호학적 RNG (서명 nonce) */",
            " /* [위반: COM-004] 비암호학적 RNG (private key) */",
        ]
        out = []
        replaced = 0
        search_from = 0
        while replaced < 3:
            idx = text.find(SRAND, search_from)
            if idx < 0:
                break
            out.append(text[search_from:idx + len(SRAND)])
            out.append(comments[replaced])
            search_from = idx + len(SRAND)
            replaced += 1
        out.append(text[search_from:])
        result["src/ec_kcdsa.c"] = "".join(out).encode("utf-8")

    # COM-001 + LEA-044: lea.c lea_free 빈 스텁
    patch("src/lea.c",
          "void lea_free(lea_context *ctx)\n{\n  //ctx zeroization\n}",
          "void lea_free(lea_context *ctx)\n{\n  //ctx zeroization /* [위반: COM-001] [위반: LEA-044] ctx 제로화 없음 */\n}",
    )

    # COM-001: aria.c — aria_init memset
    patch("src/aria.c",
          "memset(ctx, 0, sizeof(aria_context));",
          "memset(ctx, 0, sizeof(aria_context)); /* [위반: COM-001] memset_s/smc_zeroize 미사용 */",
    )

    # COM-001: ctrdrbg.c — 첫 번째 memset
    patch("src/ctrdrbg.c",
          "memset(inputblock, 0x00, MAX_V_LEN_IN_BYTES);",
          "memset(inputblock, 0x00, MAX_V_LEN_IN_BYTES); /* [위반: COM-001] memset_s 미사용 */",
    )

    # COM-001: hmacdrbg.c — memset Key
    patch("src/hmacdrbg.c",
          "memset(state->Key, 0x00, MAX_KEY_LEN_IN_BYTES);",
          "memset(state->Key, 0x00, MAX_KEY_LEN_IN_BYTES); /* [위반: COM-001] memset_s 미사용 */",
    )

    # COM-001: pbkdf.c — memset T
    patch("src/pbkdf.c",
          "memset(T, 0x00, 64);",
          "memset(T, 0x00, 64); /* [위반: COM-001] memset_s 미사용 */",
    )

    # LEA-048: test_lea.c — 첫 .txt 파일 참조
    patch("test/test_lea.c",
          '"tv/lea/LEA128(ECB)KAT.txt"',
          '"tv/lea/LEA128(ECB)KAT.txt" /* [위반: LEA-048] .req/.rsp 아닌 .txt 사용 */',
    )

    # LEA-062: test_lea.c — main 함수 마지막에 주석 추가
    patch("test/test_lea.c",
          'printf("[INFO] LEA test ALL passed.\\n");\n}',
          'printf("[INFO] LEA test ALL passed.\\n");\n  /* [위반: LEA-062] Variable Key/Text KAT 미구현 */\n}',
    )

    return result


# ═══════════════════════════════════════════════════════════════════
# 3. 세트별 Mutation 정의
# ═══════════════════════════════════════════════════════════════════

def mutation_set_5(files: dict[str, bytes]) -> dict[str, bytes]:
    """
    세트 5: LEA 키스케줄 + CBC 암호화 위반
      - LEA-016: key schedule ROL1 → ROL2 (case 24)
      - LEA-011: delta[4] 상수 변조
      - CBC-001: CBC 암호화 첫 블록 IV XOR 생략
    """
    result = dict(files)

    def patch(key, old, new):
        text = result[key].decode("utf-8", errors="replace")
        assert old in text, f"패턴 미발견: {key} ← {old!r}"
        result[key] = text.replace(old, new, 1).encode("utf-8")

    # LEA-016: case 24에서 T[0] ROL1 → ROL2
    patch("src/lea.c",
          "T[0] = ROTL(1,  (T[0]+ (ROTL((i),delta[i%4]))    %4294967296));",
          "T[0] = ROTL(2,  (T[0]+ (ROTL((i),delta[i%4]))    %4294967296)); /* [위반: LEA-016] ROL1이어야 함 */",
    )

    # LEA-011: delta[4] 변조
    patch("src/lea.c",
          "const unsigned int delta[8] = {0xc3efe9db,0x44626b02,0x79e27c8a,0x78df30ec,0x715ea49e,0xc785da0a,0xe04ef22a,0xe5c40957};",
          "const unsigned int delta[8] = {0xc3efe9db,0x44626b02,0x79e27c8a,0x78df30ec,0xDEADBEEF /* [위반: LEA-011] δ[4] 변조 */,0xc785da0a,0xe04ef22a,0xe5c40957};",
    )

    # CBC-001: 암호화 첫 블록 IV XOR 생략 → 평문 직접 암호화
    patch("src/cipher.c",
          "xor_array(temp_in, iv, in, CIPHER_BLOCKSIZE);",
          "memcpy(temp_in, in, CIPHER_BLOCKSIZE); /* [위반: CBC-001] IV XOR 없이 평문 직접 암호화 */",
    )

    return result


def mutation_set_6(files: dict[str, bytes]) -> dict[str, bytes]:
    """
    세트 6: LEA 라운드 함수 + CTR 카운터 위반
      - LEA-027: 암호화 ROL9 → ROL8
      - LEA-028: 암호화 ROR5 → ROR4
      - CTR-002: ctr_increase 제거 → 매 블록 동일 카운터
    """
    result = dict(files)

    def patch(key, old, new):
        text = result[key].decode("utf-8", errors="replace")
        assert old in text, f"패턴 미발견: {key} ← {old!r}"
        result[key] = text.replace(old, new, 1).encode("utf-8")

    # LEA-027: lea_enc ROL9 → ROL8
    patch("src/lea.c",
          "tmp[0] = ROTL(9, (tmp_input[0]^ctx->rk[i][0]) + ((tmp_input[1]^ctx->rk[i][1]) % 4294967296));",
          "tmp[0] = ROTL(8, (tmp_input[0]^ctx->rk[i][0]) + ((tmp_input[1]^ctx->rk[i][1]) % 4294967296)); /* [위반: LEA-027] ROL9이어야 함 */",
    )

    # LEA-028: lea_enc ROR5 → ROR4
    patch("src/lea.c",
          "tmp[1] = ROTR(5, (tmp_input[1]^ctx->rk[i][2]) + ((tmp_input[2]^ctx->rk[i][3]) % 4294967296));",
          "tmp[1] = ROTR(4, (tmp_input[1]^ctx->rk[i][2]) + ((tmp_input[2]^ctx->rk[i][3]) % 4294967296)); /* [위반: LEA-028] ROR5이어야 함 */",
    )

    # CTR-002: ctr_increase 제거 → 고정 카운터
    patch("src/cipher.c",
          "if (i != 0)\n      ctr_increase(ctr);",
          "/* [위반: CTR-002] ctr_increase 제거 — 매 블록 동일 카운터 사용 */",
    )

    return result


def mutation_set_7(files: dict[str, bytes]) -> dict[str, bytes]:
    """
    세트 7: CBC 복호화 + 하드코딩 + CTR 방향 위반
      - CBC-002: CBC 복호화 첫 블록 IV XOR 생략
      - COM-003: 하드코딩 고정 키 삽입
      - CTR-001: CTR 키스트림 생성에 decrypt 함수 사용
    """
    result = dict(files)

    def patch(key, old, new):
        text = result[key].decode("utf-8", errors="replace")
        assert old in text, f"패턴 미발견: {key} ← {old!r}"
        result[key] = text.replace(old, new, 1).encode("utf-8")

    # CBC-002: 복호화 첫 블록 IV XOR 생략
    patch("src/cipher.c",
          "crypt(out, in, key, key_len);\n        xor_array(out, out, iv, CIPHER_BLOCKSIZE);",
          "crypt(out, in, key, key_len);\n        /* [위반: CBC-002] IV XOR 없이 복호화 — 첫 블록 오류 */",
    )

    # COM-003: lea.c 상단에 하드코딩 고정 키 삽입
    patch("src/lea.c",
          '#include "lea.h"\n',
          '#include "lea.h"\n\n/* [위반: COM-003] 고정 테스트 키 하드코딩 */\nstatic const uint8_t HARDCODED_TEST_KEY[16] = {\n    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78,\n    0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0\n};\n',
    )

    # CTR-001: cipher_ctr에서 encrypt 대신 decrypt 사용
    #   crypt(out, ctr, key, key_len) → lea_decrypt(out, ctr, key, key_len)
    #   실제로는 crypt 함수 포인터를 그대로 쓰므로 개념상 위반 시연:
    #   CTR 모드는 항상 블록 암호의 encrypt를 써야 하나 여기서는
    #   lea_decrypt로 키스트림 생성 — 표준 위반
    patch("src/cipher.c",
          "cipher_ctr(out, in, in_len, key, key_len, iv, iv_len, lea_encrypt);",
          "cipher_ctr(out, in, in_len, key, key_len, iv, iv_len, lea_decrypt); /* [위반: CTR-001] CTR은 항상 encrypt로 키스트림 생성해야 함 */",
    )

    return result


# ═══════════════════════════════════════════════════════════════════
# 4. ZIP 패키징
# ═══════════════════════════════════════════════════════════════════

def pack_zip(files: dict[str, bytes], out_path: Path) -> None:
    """파일 맵을 kcmvp_combined.zip 형식으로 패키징."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in sorted(files.items()):
            zf.writestr(name, data)
    print(f"  → ZIP 생성: {out_path}  ({out_path.stat().st_size:,} bytes)")


# ═══════════════════════════════════════════════════════════════════
# 5. 정답지_위반목록.md 생성
# ═══════════════════════════════════════════════════════════════════

ORIG_VIOLATIONS = """
### 1. [COM-004] — ec_kcdsa.c
> KCDSA 키·서명 nonce 생성에 srand(time)+rand() 사용 (3개소)

### 2. [COM-001] — aria.c
> aria_init()에서 memset만 사용, smc_zeroize 미호출

### 3. [COM-001] — ctrdrbg.c
> CTR-DRBG 내부 상태 memset만 사용

### 4. [COM-001] — hmacdrbg.c
> HMAC-DRBG Key/V memset만 사용

### 5. [COM-001] — lea.c
> lea_free()에 zeroize 코드 없음 (빈 스텁)

### 6. [COM-001] — pbkdf.c
> 파생 키 T에 memset만 사용

### 7. [LEA-044] — lea.c
> lea_free() 빈 스텁: ctx zeroization 주석만 존재

### 8. [LEA-048] — test_lea.c
> .txt 확장자 테스트 벡터 파일 사용 (.req/.rsp 미사용)

### 9. [LEA-062] — test_lea.c
> Variable Key/Text KAT 미구현
"""

SET_SPECIFIC = {
    5: """
### 10. [LEA-016] — lea.c
> 키 스케줄 128비트 case에서 T[0] 갱신 ROL1 → ROL2 사용

### 11. [LEA-011] — lea.c
> delta 상수 δ[4] 표준값(0x715ea49e) → 0xDEADBEEF 변조

### 12. [CBC-001] — cipher.c
> CBC 암호화 첫 블록에서 IV XOR 생략, 평문 직접 암호화
""",
    6: """
### 10. [LEA-027] — lea.c
> 암호화 라운드 tmp[0] 계산 ROL9 → ROL8 오류

### 11. [LEA-028] — lea.c
> 암호화 라운드 tmp[1] 계산 ROR5 → ROR4 오류

### 12. [CTR-002] — cipher.c
> CTR 모드 ctr_increase 제거 — 매 블록 동일 카운터 사용
""",
    7: """
### 10. [CBC-002] — cipher.c
> CBC 복호화 첫 블록에서 IV XOR 생략

### 11. [COM-003] — lea.c
> 하드코딩 고정 테스트 키(HARDCODED_TEST_KEY) 소스 내 삽입

### 12. [CTR-001] — cipher.c
> CTR 키스트림 생성에 lea_decrypt 사용 (표준: lea_encrypt 사용)
""",
}


def write_gt(set_num: int, out_path: Path) -> None:
    """정답지_위반목록.md 생성."""
    content = f"# 세트 {set_num} 정답지 위반 목록\n\n"
    content += "## 코드 원본 violations (0_KCMVP 기반)\n"
    content += ORIG_VIOLATIONS
    content += f"\n## 세트 {set_num} 추가 mutations\n"
    content += SET_SPECIFIC[set_num]
    out_path.write_text(content, encoding="utf-8")
    print(f"  → GT 생성: {out_path}")


# ═══════════════════════════════════════════════════════════════════
# 6. 메인
# ═══════════════════════════════════════════════════════════════════

MUTATIONS = {
    5: mutation_set_5,
    6: mutation_set_6,
    7: mutation_set_7,
}


def main():
    print("=" * 60)
    print("Mutation 데이터셋 생성기")
    print(f"원본: {ORIG_ZIP}")
    print(f"출력: {SET_BASE}")
    print("=" * 60)

    if not ORIG_ZIP.exists():
        print(f"[ERROR] 원본 ZIP 없음: {ORIG_ZIP}")
        sys.exit(1)

    print("\n[1/3] 원본 파일 로드 중...")
    originals = load_original_files()
    print(f"  {len(originals)}개 파일 로드 완료")

    print("\n[2/3] Base 레이어 적용 (원본 violations 주석 표기)...")
    base = apply_base_violations(originals)

    for set_num, mutator in MUTATIONS.items():
        print(f"\n[세트 {set_num}] {mutator.__doc__.strip().splitlines()[0]}")
        out_dir = SET_BASE / f"세트 {set_num}"

        mutated = mutator(base)
        pack_zip(mutated, out_dir / "kcmvp_combined.zip")
        write_gt(set_num, out_dir / "정답지_위반목록.md")

    print("\n" + "=" * 60)
    print("완료. 생성된 세트:")
    for n in MUTATIONS:
        d = SET_BASE / f"세트 {n}"
        print(f"  세트 {n}: {d}")
    print("\n평가 실행:")
    print("  cd backend && python scripts/evaluate_real_sets.py --no-l3")


if __name__ == "__main__":
    main()
