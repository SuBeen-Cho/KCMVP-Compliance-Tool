/* N31: COM-003 — LEA delta 알고리즘 상수 (오탐이면 안 됨) */
#include <stdint.h>

/* LEA 공개 delta 상수: 알고리즘 규격에 명시된 값 */
static const uint32_t lea_delta[8] = {
    0xc3efe9db, 0x44626b02, 0x79e27c8a, 0x78df30ec,
    0x715ea49e, 0xc785da0a, 0xe04ef22a, 0xe5c40957
};

uint32_t get_delta(int i) {
    return lea_delta[i & 7];
}
