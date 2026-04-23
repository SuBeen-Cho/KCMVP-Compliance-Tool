
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "lea.h"

/* ===== P08: CBC-003 rand()로 IV 생성 (CSPRNG 미사용) ===== */
void p08_cbc_rand_iv(LEA_KEY *ctx, uint8_t *pt, size_t len, uint8_t *ct) {
    uint8_t iv[16];
    for (int i = 0; i < 16; i++) iv[i] = (uint8_t)(rand() & 0xff);
    /* 위반: rand() 사용 — getrandom/DRBG 사용 필요 */
    lea_cbc_encrypt(ctx, pt, ct, len, iv);
}

/* ===== P09: CBC-004 IV/키 사용 후 제로화 누락 ===== */
void p09_cbc_no_zeroize(LEA_KEY *ctx, uint8_t *key, uint8_t *pt, size_t len, uint8_t *ct) {
    uint8_t iv[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                      0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    lea_cbc_encrypt(ctx, pt, ct, len, iv);
    /* 위반: iv, key 메모리 제로화 없이 반환 */
}

/* ===== P10: CBC-005 패딩 오류 정보 노출 (printf padding error) ===== */
int p10_cbc_leaky_padding_error(uint8_t *ct, size_t len) {
    int pad_byte = ct[len - 1];
    if (pad_byte > 16 || pad_byte == 0) {
        /* 위반: 패딩 오류 상세 정보 외부 노출 */
        printf("Padding verification failed: invalid padding byte %d\n", pad_byte);
        return -1;
    }
    for (int i = 0; i < pad_byte; i++) {
        if (ct[len - 1 - i] != pad_byte) {
            fprintf(stderr, "Padding error: expected %d got %d at offset %d\n",
                    pad_byte, ct[len-1-i], i);
            return -1;
        }
    }
    return 0;
}

/* ===== P11: CBC-061 잘못된 IV 크기 (8바이트) ===== */
void p11_cbc_wrong_iv_size(LEA_KEY *ctx, uint8_t *pt, size_t len, uint8_t *ct) {
    uint8_t iv[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    /* 위반: IV는 반드시 16바이트 */
    lea_cbc_encrypt(ctx, pt, ct, len, iv);
}

/* ===== P12: CBC-061 잘못된 IV 크기 (32바이트) ===== */
void p12_cbc_iv_too_large(LEA_KEY *ctx, uint8_t *pt, size_t len, uint8_t *ct) {
    uint8_t iv[32] = {0};
    /* 위반: IV 32바이트 — 16바이트 필요 */
    lea_cbc_encrypt(ctx, pt, ct, 16, iv);
}

/* ===== P13: CBC-005 RETURN INVALID_PADDING 상수 노출 ===== */
int p13_cbc_return_bad_padding(uint8_t *buf, size_t len) {
    if (!verify_pkcs7(buf, len)) {
        return -INVALID_PADDING;  /* 위반: 패딩 관련 상수 노출 */
    }
    return 0;
}
