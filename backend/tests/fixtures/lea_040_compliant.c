/* LEA-040 정상: < 연산자 사용 */
typedef unsigned int uint32_t;

void lea_encrypt_block(uint32_t *block, const uint32_t *rk) {
    int i;
    for (i = 0; i < 24; i++) {
        block[0] = block[0] ^ rk[i];
    }
}
