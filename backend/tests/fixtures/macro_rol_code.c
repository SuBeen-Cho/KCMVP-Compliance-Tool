/* 매크로 불투명성 테스트: ROL 매크로 사용
   LEA-010에서 FP 발생하는 패턴 재현 */
typedef unsigned int uint32_t;

uint32_t ROL(uint32_t x, int r);

void lea_set_key_generic(const unsigned char *mk, int mk_len,
                         uint32_t *rk) {
    uint32_t T[8];
    int i;
    T[0] = ROL(T[0] + 0xc3efe9db, 1);
    T[1] = ROL(T[1] + 0x44626b02, 3);
    for (i = 0; i < 24; i++) {
        rk[i] = T[i % 4] + T[(i + 1) % 4];
    }
}
