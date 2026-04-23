/* N46: LEA-003 — 매크로 상수 LEA_ROUNDS 사용 → checker는 safe(판단불가) 처리 */
#include <stdint.h>

/* 실제로는 컴파일 시점에 24/28/32로 확장됨 */
#ifndef LEA_ROUNDS
#define LEA_ROUNDS 24
#endif

void lea_key_expand(uint32_t *key, uint32_t *rk) {
    int i;
    for (i = 0; i < LEA_ROUNDS; i++) {  /* 매크로 상수 사용 → 정상 */
        rk[i] = key[i % 4] ^ (i * 0x9e3779b9u);
    }
}
