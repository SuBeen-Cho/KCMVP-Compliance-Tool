typedef struct { unsigned int nr; } aes_context;

const unsigned int aes_block_bytes = 16;
const unsigned int aes_block_bits = 128;

int aes_set_encrypt_key(aes_context *ctx, unsigned int key_bits) {
    switch (key_bits) {
        case 128: ctx->nr = 10; break;
        case 192: ctx->nr = 12; break;
        case 256: ctx->nr = 14; break;
        default: return -1;
    }
    return 0;
}
