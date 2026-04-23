/* N43: CTR-001 — CTR 관련 함수 없음, checker는 None 반환 → 정상 취급 */
#include <stdint.h>

void lea_encrypt(uint8_t *key, uint8_t *pt, uint8_t *ct) {
    /* LEA 블록 암호화 구현 */
    (void)key; (void)pt; (void)ct;
}

void lea_decrypt(uint8_t *key, uint8_t *ct, uint8_t *pt) {
    /* LEA 블록 복호화 구현 */
    (void)key; (void)ct; (void)pt;
}
