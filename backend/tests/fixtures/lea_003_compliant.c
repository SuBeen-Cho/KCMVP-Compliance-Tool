/* LEA-003 정상: 표준 라운드 수 24/28/32 */
typedef unsigned int uint32_t;
typedef struct { int rounds; uint32_t rk[192]; } lea_ctx;

void lea_set_key(const unsigned char *mk, int mk_len, lea_ctx *ctx) {
    if (mk_len == 16) ctx->rounds = 24;
    else if (mk_len == 24) ctx->rounds = 28;
    else ctx->rounds = 32;
}
