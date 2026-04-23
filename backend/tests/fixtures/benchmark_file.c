/* 벤치마크 파일 패턴: benchmark.c
   암호 함수를 호출만 하고 구현하지 않음 — missing 규칙 FP */
typedef unsigned int uint32_t;
typedef unsigned char uint8_t;

void lea_encrypt(uint8_t *ct, const uint8_t *pt, const uint32_t *rk);
void lea_decrypt(uint8_t *pt, const uint8_t *ct, const uint32_t *rk);

double get_time(void);

void lea_key_benchmark(void) {
    uint8_t key[16] = {0};
    uint32_t rk[192];
    double t0, t1;
    int i;

    t0 = get_time();
    for (i = 0; i < 10000; i++) {
        lea_encrypt(key, key, rk);
    }
    t1 = get_time();
}
