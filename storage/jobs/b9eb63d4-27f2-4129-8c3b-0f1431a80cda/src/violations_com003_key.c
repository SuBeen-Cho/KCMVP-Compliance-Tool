/* P38: COM-003 — 하드코딩 암호키 위반 */
#include <stdint.h>

/* VIOLATION: 변수명 'aes_key', 함수 인자로 직접 전달 */
static const uint8_t aes_key[16] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

extern void lea_set_key(void *ctx, const uint8_t *key, int len);
extern void *g_ctx;

void init_module(void) {
    lea_set_key(g_ctx, aes_key, 128);  /* 암호키를 소스에 박아 직접 전달 */
}
