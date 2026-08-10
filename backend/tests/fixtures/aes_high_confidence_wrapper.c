typedef struct { unsigned int opaque[64]; } aes_context;

extern int aesni_expand_key(aes_context *, const unsigned char *, unsigned int);

int aes_set_encrypt_key(aes_context *ctx, const unsigned char *key,
                        unsigned int key_bits) {
    return aesni_expand_key(ctx, key, key_bits);
}
