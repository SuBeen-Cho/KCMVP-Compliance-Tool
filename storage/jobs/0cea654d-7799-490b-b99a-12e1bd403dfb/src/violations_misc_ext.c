
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "lea.h"

/* ===== P23: CFB-001 rand()로 IV 생성 (CSPRNG 미사용) ===== */
void p23_cfb_rand_iv(LEA_KEY *ctx, uint8_t *pt, size_t len, uint8_t *ct) {
    uint8_t iv[16];
    for (int i = 0; i < 16; i++) iv[i] = rand() & 0xff;
    /* 위반: getrandom/DRBG 미사용 */
    lea_cfb128_encrypt(ctx, pt, ct, len, iv);
}

/* ===== P24: CMAC-002 memcmp으로 태그 비교 (타이밍 공격 취약) ===== */
int p24_cmac_memcmp_not_const_time(uint8_t *tag_computed, uint8_t *tag_received,
                                    size_t len) {
    /* 위반: memcmp는 타이밍 의존적 — crypto_memcmp 사용 필요 */
    if (memcmp(tag_computed, tag_received, len) != 0) {
        return -1;
    }
    return 0;
}

/* ===== P25: CMAC-003 K1/K2 서브키 사용 후 제로화 누락 ===== */
void p25_cmac_no_subkey_zeroize(LEA_KEY *ctx, uint8_t *msg, size_t len,
                                  uint8_t *mac) {
    uint8_t K1[16], K2[16];
    /* K1, K2 생성 */
    lea_cmac_generate_subkeys(ctx, K1, K2);
    lea_cmac_compute(ctx, msg, len, K1, K2, mac);
    /* 위반: K1, K2 사용 후 제로화 없이 반환 */
}

/* ===== P26: COM-002 에러 처리 누락 (반환값 무시) ===== */
void p26_no_error_check(LEA_KEY *ctx, uint8_t *key, uint8_t *pt, uint8_t *ct,
                         size_t len, uint8_t *iv) {
    /* 위반: 모든 반환값 무시 — 에러 코드 체크 없음 */
    lea_set_key(ctx, key, 128);
    lea_cbc_encrypt(ctx, pt, ct, len, iv);
}

/* ===== P27: LEA-041 S-box 사용 (ARX 원칙 위반) ===== */
static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76
    /* ... 나머지 생략 */
};

uint8_t p27_lea_with_sbox(uint8_t input) {
    /* 위반: LEA는 S-box 비사용 ARX 구조 */
    uint8_t s_box_result = sbox[input & 0x0f];
    return s_box_result;
}

/* ===== P28: CMAC-002 strcmp로 태그 비교 (타이밍 공격 취약) ===== */
int p28_cmac_strcmp_compare(const char *expected_mac, const char *computed_mac) {
    /* 위반: strcmp는 타이밍 의존적 */
    if (strcmp(expected_mac, computed_mac) != 0) {
        return -1;
    }
    return 0;
}
