"""
KCMVP 정확도 테스트 데이터 v5 — AST 구조 체커 확장판
v4 전체 + CBC-001/002, ECB-002 AST 구조 검사 케이스 추가
- 총 54건: P(위반) 31건 + N(정상) 23건
"""
import zipfile, io, os

# ─────────────────────────────────────────────────────
# v4 데이터 그대로 임포트
# ─────────────────────────────────────────────────────
from create_accuracy_test_v4 import (
    VIOLATIONS_GCM_EXT_C,
    VIOLATIONS_CBC_EXT_C,
    VIOLATIONS_CTR_EXT_C,
    VIOLATIONS_MISC_EXT_C,
    SAFE_CODE_V4_C,
)

# ─────────────────────────────────────────────────────
# 파일 6: violations_cbc_struct.c  (CBC/ECB 구조 위반 — P29~P31)
# ─────────────────────────────────────────────────────
VIOLATIONS_CBC_STRUCT_C = r"""
#include <stdint.h>
#include <string.h>
#include "lea.h"

/* ===== P29: CBC-001 — CBC 암호화에서 XOR 연쇄 없음 ===== */
/* 위반: CT[i]=ENC(PT[i]) 만 수행. CT[i-1]과 XOR(^) 없음 */
void p29_cbc_enc_no_xor(const LEA_KEY *ctx, const uint8_t *pt,
                         uint8_t *ct, size_t len) {
    size_t i;
    for (i = 0; i < len; i += 16) {
        lea_encrypt(ctx, pt + i, ct + i);
        /* 위반: 이전 암호문 블록과 XOR 없이 단순 암호화 */
    }
}

/* ===== P30: CBC-002 — CBC 복호화에서 XOR 연쇄 없음 ===== */
/* 위반: PT[i]=DEC(CT[i]) 만 수행. CT[i-1]과 XOR(^) 없음 */
void p30_cbc_decrypt_no_xor(const LEA_KEY *ctx, const uint8_t *ct,
                              uint8_t *pt, size_t len) {
    size_t i;
    for (i = 0; i < len; i += 16) {
        lea_cbc_decrypt(ctx, ct + i, pt + i, 16, NULL);
        /* 위반: 이전 암호문 블록과 XOR 없이 단순 복호화 */
    }
}

/* ===== P31: ECB-002 — ECB 암호화에서 len%16 검사 없음 ===== */
/* 위반: 입력 길이의 16배수 여부 확인 없이 블록 단위 암호화 */
int p31_ecb_encrypt_no_check(const LEA_KEY *ctx, const uint8_t *pt,
                               uint8_t *ct, size_t len) {
    size_t i;
    /* 위반: len % 16 검사 없음 */
    for (i = 0; i < len; i += 16) {
        lea_encrypt(ctx, pt + i, ct + i);
    }
    return 0;
}
"""

# ─────────────────────────────────────────────────────
# 파일 7: safe_code_v5.c  (AST 구조 정상 코드 — N21~N23)
# ─────────────────────────────────────────────────────
SAFE_CODE_V5_C = r"""
#include <stdint.h>
#include <string.h>
#include "lea.h"

/* ===== N21: CBC-001 — CBC 암호화에서 올바른 XOR 연쇄 ===== */
void n21_cbc_enc_with_xor(const LEA_KEY *ctx, const uint8_t *pt,
                            uint8_t *ct, size_t len, const uint8_t *iv) {
    uint8_t block[16];
    const uint8_t *prev = iv;
    size_t i;
    int j;
    for (i = 0; i < len; i += 16) {
        for (j = 0; j < 16; j++) block[j] = pt[i + j] ^ prev[j]; /* XOR */
        lea_encrypt(ctx, block, ct + i);
        prev = ct + i;
    }
}

/* ===== N22: CBC-002 — CBC 복호화에서 올바른 XOR 연쇄 ===== */
void n22_cbc_decrypt_with_xor(const LEA_KEY *ctx, const uint8_t *ct,
                                uint8_t *pt, size_t len, const uint8_t *iv) {
    uint8_t block[16];
    const uint8_t *prev = iv;
    size_t i;
    int j;
    for (i = 0; i < len; i += 16) {
        lea_cbc_decrypt(ctx, ct + i, block, 16, iv);
        for (j = 0; j < 16; j++) pt[i + j] = block[j] ^ prev[j]; /* XOR */
        prev = ct + i;
    }
}

/* ===== N23: ECB-002 — ECB 암호화에서 len%16 검사 있음 ===== */
int n23_ecb_encrypt_with_check(const LEA_KEY *ctx, const uint8_t *pt,
                                 uint8_t *ct, size_t len) {
    size_t i;
    if (len % 16 != 0) return -1;   /* 정상: 16배수 검사 */
    for (i = 0; i < len; i += 16) {
        lea_encrypt(ctx, pt + i, ct + i);
    }
    return 0;
}
"""

# ─────────────────────────────────────────────────────
# v4 헤더 (lea.h) 그대로 재사용
# ─────────────────────────────────────────────────────
LEA_H = r"""
#ifndef LEA_H
#define LEA_H
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

typedef struct { uint32_t rk[8][32]; } LEA_KEY;
typedef struct { uint32_t state[4]; int initialized; uint8_t J0[16]; } LEA_GCM_CTX;

int  lea_set_key(LEA_KEY *ctx, const uint8_t *key, int key_bits);
void lea_encrypt(const LEA_KEY *ctx, const uint8_t *pt, uint8_t *ct);
int  lea_cbc_encrypt(const LEA_KEY *ctx, const uint8_t *pt, uint8_t *ct,
                     size_t len, const uint8_t *iv);
int  lea_cbc_decrypt(const LEA_KEY *ctx, const uint8_t *ct, uint8_t *pt,
                     size_t len, const uint8_t *iv);
int  lea_ctr_encrypt(const LEA_KEY *ctx, const uint8_t *pt, uint8_t *ct,
                     size_t len, uint8_t *counter);
int  lea_gcm_init(LEA_GCM_CTX *ctx, const uint8_t *key, int key_bits);
int  lea_gcm_set_ctr(LEA_GCM_CTX *ctx, const uint8_t *nonce);
int  lea_gcm_encrypt(LEA_GCM_CTX *ctx, const uint8_t *pt, uint8_t *ct,
                     size_t len, const uint8_t *nonce, uint8_t *tag, int tag_len);
int  lea_gcm_decrypt(LEA_GCM_CTX *ctx, const uint8_t *ct, uint8_t *pt,
                     size_t len, const uint8_t *nonce, uint8_t *tag);
int  lea_gcm_final(LEA_GCM_CTX *ctx, const uint8_t *tag_in, uint8_t *tag_out,
                   size_t tag_len);
int  lea_ccm_encrypt(const LEA_KEY *ctx, const uint8_t *pt, uint8_t *ct,
                     size_t len, const uint8_t *nonce, uint8_t *tag,
                     int nonce_len, int tag_len);
int  lea_ccm_decrypt(const LEA_KEY *ctx, const uint8_t *ct, uint8_t *pt,
                     size_t len, const uint8_t *nonce, const uint8_t *tag,
                     int nonce_len, int tag_len);
int  lea_ofb_encrypt(const LEA_KEY *ctx, const uint8_t *pt, uint8_t *ct,
                     size_t len, uint8_t *iv);
int  lea_cfb128_encrypt(const LEA_KEY *ctx, const uint8_t *pt, uint8_t *ct,
                        size_t len, uint8_t *iv);
int  lea_cmac_generate_subkeys(const LEA_KEY *ctx, uint8_t *K1, uint8_t *K2);
int  lea_cmac_compute(const LEA_KEY *ctx, const uint8_t *msg, size_t len,
                      const uint8_t *K1, const uint8_t *K2, uint8_t *mac);
int  lea_online_init(void *ctx);
int  lea_online_update(void *ctx, const uint8_t *data, size_t len);
int  lea_online_final(void *ctx, uint8_t *out, size_t *out_len);
void secure_clear(void *buf, size_t len);
void explicit_bzero(void *buf, size_t len);
int  getrandom(void *buf, size_t len, unsigned int flags);
int  crypto_memcmp(const void *a, const void *b, size_t len);
int  verify_pkcs7(const uint8_t *buf, size_t len);

#define INVALID_PADDING 0x01

#endif /* LEA_H */
"""

# ─────────────────────────────────────────────────────
# Ground Truth (54건 = v4 48건 + v5 추가 6건)
# ─────────────────────────────────────────────────────
GROUND_TRUTH = """# Accuracy Test v5 — Ground Truth (54건)
# v4(48건) + AST 구조 체커 확장(6건)
# Format: file | label | expected_rule_id | description

## violations_gcm_ext.c (P = 위반, 7건)
violations_gcm_ext.c | P | GCM-002 | P01: tag_len=3 (4 미만)
violations_gcm_ext.c | P | GCM-002 | P02: tag_len=20 (16 초과)
violations_gcm_ext.c | P | GCM-003 | P03: set_ctr 먼저 호출 후 init (순서 위반)
violations_gcm_ext.c | P | GCM-004 | P04: 인증 실패 시 0 반환 (−1 미반환)
violations_gcm_ext.c | P | GCM-005 | P05: nonce/key 제로화 누락
violations_gcm_ext.c | P | GCM-004 | P06: tag_mismatch 처리 누락
violations_gcm_ext.c | P | GCM-002 | P07: t_len=2 (4 미만)

## violations_cbc_ext.c (P = 위반, 6건)
violations_cbc_ext.c | P | CBC-003 | P08: rand()로 IV 생성 (CSPRNG 미사용)
violations_cbc_ext.c | P | CBC-004 | P09: IV/키 사용 후 제로화 누락
violations_cbc_ext.c | P | CBC-005 | P10: printf로 padding 오류 상세 노출
violations_cbc_ext.c | P | CBC-061 | P11: iv[8] — 8바이트 IV (16 필요)
violations_cbc_ext.c | P | CBC-061 | P12: iv[32] — 32바이트 IV (16 필요)
violations_cbc_ext.c | P | CBC-005 | P13: return -INVALID_PADDING 상수 노출

## violations_ctr_ext.c (P = 위반, 9건)
violations_ctr_ext.c | P | CTR-003 | P14: rand()로 nonce 생성 (CSPRNG 미사용)
violations_ctr_ext.c | P | CTR-004 | P15: 카운터/키 제로화 누락
violations_ctr_ext.c | P | CTR-LEA-001 | P16: ctr[8] — 8바이트 카운터 (16 필요)
violations_ctr_ext.c | P | CCM-002 | P17: Nlen=6 (7 미만)
violations_ctr_ext.c | P | CCM-002 | P18: nonce_len=14 (13 초과)
violations_ctr_ext.c | P | CCM-003 | P19: Tlen=5 (허용값 아님)
violations_ctr_ext.c | P | CCM-003 | P20: t_len=2 (4 미만)
violations_ctr_ext.c | P | CCM-004 | P21: 인증 실패 시 평문 미폐기
violations_ctr_ext.c | P | OFB-001 | P22: iv[8] — 8바이트 IV (16 필요)

## violations_misc_ext.c (P = 위반, 6건)
violations_misc_ext.c | P | CFB-001 | P23: rand()로 CFB IV 생성
violations_misc_ext.c | P | CMAC-002 | P24: memcmp으로 태그 비교 (타이밍 취약)
violations_misc_ext.c | P | CMAC-003 | P25: K1/K2 사용 후 제로화 누락
violations_misc_ext.c | P | COM-002 | P26: lea_set_key/lea_cbc_encrypt 반환값 무시
violations_misc_ext.c | P | LEA-041 | P27: sbox[] 배열 사용 (ARX 원칙 위반)
violations_misc_ext.c | P | CMAC-002 | P28: strcmp로 MAC 비교 (타이밍 취약)

## violations_cbc_struct.c (P = 위반, 3건) — AST 구조 체커
violations_cbc_struct.c | P | CBC-001 | P29: CBC 암호화에서 XOR(^) 연쇄 없음
violations_cbc_struct.c | P | CBC-002 | P30: CBC 복호화에서 XOR(^) 연쇄 없음
violations_cbc_struct.c | P | ECB-002 | P31: ECB 암호화 len%16 검사 없음

## safe_code_v4.c (N = 정상 코드, 20건)
safe_code_v4.c | N | GCM-002 | N01: tag_len=16 정상
safe_code_v4.c | N | GCM-002 | N02: t_len=12 정상
safe_code_v4.c | N | GCM-004 | N03: 인증 실패 시 -1 반환 정상
safe_code_v4.c | N | GCM-005 | N04: explicit_bzero로 올바른 제로화
safe_code_v4.c | N | CBC-061 | N05: iv[16] 정상 크기
safe_code_v4.c | N | CBC-005 | N06: return -1만 반환 (정보 미노출)
safe_code_v4.c | N | CTR-LEA-001 | N07: ctr[16] 정상 크기
safe_code_v4.c | N | CCM-002 | N08: Nlen=8 정상 (7~13 범위)
safe_code_v4.c | N | CCM-003 | N09: Tlen=8 정상 ({4,6,8,...,16} 중 하나)
safe_code_v4.c | N | CCM-004 | N10: memset(pt,0,len) 인증 실패 시 처리
safe_code_v4.c | N | OFB-001 | N11: iv[16] 정상 크기
safe_code_v4.c | N | CMAC-002 | N12: crypto_memcmp 상수 시간 비교
safe_code_v4.c | N | CMAC-003 | N13: K1/K2 explicit_bzero 올바른 제로화
safe_code_v4.c | N | COM-002 | N14: 모든 반환값 검사 (ret < 0 체크)
safe_code_v4.c | N | LEA-041 | N15: ARX 연산만 사용 (S-box 없음)
safe_code_v4.c | N | CBC-003 | N16: getrandom으로 IV 생성
safe_code_v4.c | N | CTR-003 | N17: getrandom으로 nonce 생성
safe_code_v4.c | N | CCM-002 | N18: nonce_len=13 정상 (최대)
safe_code_v4.c | N | GCM-003 | N19: init→set_ctr→encrypt→final 올바른 순서
safe_code_v4.c | N | CFB-001 | N20: getrandom으로 CFB IV 생성

## safe_code_v5.c (N = 정상 코드, 3건) — AST 구조 정상
safe_code_v5.c | N | CBC-001 | N21: CBC 암호화에서 XOR 연쇄 있음 (정상)
safe_code_v5.c | N | CBC-002 | N22: CBC 복호화에서 XOR 연쇄 있음 (정상)
safe_code_v5.c | N | ECB-002 | N23: ECB len%16 검사 있음 (정상)
"""


def create_zip():
    output_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        "testdata", "accuracy_test_v5.zip"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("src/violations_gcm_ext.c",    VIOLATIONS_GCM_EXT_C)
        zf.writestr("src/violations_cbc_ext.c",    VIOLATIONS_CBC_EXT_C)
        zf.writestr("src/violations_ctr_ext.c",    VIOLATIONS_CTR_EXT_C)
        zf.writestr("src/violations_misc_ext.c",   VIOLATIONS_MISC_EXT_C)
        zf.writestr("src/violations_cbc_struct.c", VIOLATIONS_CBC_STRUCT_C)
        zf.writestr("src/safe_code_v4.c",          SAFE_CODE_V4_C)
        zf.writestr("src/safe_code_v5.c",          SAFE_CODE_V5_C)
        zf.writestr("include/lea.h",               LEA_H)
        zf.writestr("GROUND_TRUTH.md",             GROUND_TRUTH)
    buf.seek(0)
    with open(output_path, "wb") as f:
        f.write(buf.read())

    gt_cases = [l for l in GROUND_TRUTH.splitlines() if "|" in l and not l.startswith("#")]
    p_cases  = [l for l in gt_cases if "| P |" in l]
    n_cases  = [l for l in gt_cases if "| N |" in l]
    print(f"Created: {output_path}")
    print(f"Total: {len(gt_cases)} cases  (P={len(p_cases)}, N={len(n_cases)})")


if __name__ == "__main__":
    create_zip()
