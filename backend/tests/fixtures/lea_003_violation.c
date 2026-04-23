/* LEA-003 위반: 비표준 라운드 수 25 */
typedef unsigned int uint32_t;
typedef struct { int rounds; uint32_t rk[192]; } lea_ctx;

void lea_set_key(const unsigned char *mk, int mk_len, lea_ctx *ctx) {
    ctx->rounds = 25;
}
