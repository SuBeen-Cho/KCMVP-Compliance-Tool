/* 함수 포인터 래퍼 패턴: lea_base.c식 디스패치
   LEA-010에서 FP 발생 — 래퍼 자체에 ROL/+ 없음 */
typedef unsigned int uint32_t;

typedef void (*lea_set_key_fn)(const unsigned char *, int, uint32_t *);

lea_set_key_fn g_lea_set_key;

void lea_set_key(const unsigned char *mk, int mk_len, uint32_t *rk) {
    g_lea_set_key(mk, mk_len, rk);
}
