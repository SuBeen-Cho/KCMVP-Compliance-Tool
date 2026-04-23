/* LEA-003 위반: for 루프 상한이 비표준 (25) */
typedef unsigned int uint32_t;

void lea_key_schedule(const unsigned char *mk, uint32_t *rk) {
    int i;
    for (i = 0; i < 25; i++) {
        rk[i] = 0;
    }
}
