/* P34: LEA-042 — 데이터 의존 조건 분기 (타이밍 공격 취약) */
#include <stdint.h>
#include <string.h>

#define LEA_KEYLEN 16

void lea_encrypt(uint32_t *ct, const uint32_t *pt, const uint8_t *key) {
    int i;
    /* VIOLATION: key[i] 값에 따라 분기 → 타이밍 정보 누출 */
    for (i = 0; i < LEA_KEYLEN; i++) {
        if (key[i] != 0) {     /* data-dependent branch on key material */
            ct[0] ^= key[i];
        }
    }
    ct[1] = pt[0] + ct[0];
    ct[2] = pt[1] ^ ct[1];
    ct[3] = pt[2] + ct[2];
}
