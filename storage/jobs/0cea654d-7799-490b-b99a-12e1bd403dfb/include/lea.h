
#ifndef LEA_H
#define LEA_H
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

typedef struct { uint32_t rk[8][32]; } LEA_KEY;
typedef struct { uint32_t state[4]; int initialized; uint8_t J0[16]; } LEA_GCM_CTX;

int  lea_set_key(LEA_KEY *ctx, const uint8_t *key, int key_bits);
void lea_encrypt(const LEA_KEY *ctx, const uint8_t *pt, uint8_t *ct);
int  lea_cbc_encrypt(const LEA_KEY *ctx, const uint8_t *pt, uint8_t *ct,
                     size_t len, const uint8_t *iv);
int  lea_cbc_decrypt(const LEA_KEY *ctx, const uint8_t *ct, uint8_t *pt,
                     size_t len, const uint8_t *iv);
int  lea_ctr_encrypt(const LEA_KEY *ctx, const uint8_t *pt, uint8_t *ct,
                     size_t len, uint8_t *counter);
int  lea_gcm_init(LEA_GCM_CTX *ctx, const uint8_t *key, int key_bits);
int  lea_gcm_set_ctr(LEA_GCM_CTX *ctx, const uint8_t *nonce);
int  lea_gcm_encrypt(LEA_GCM_CTX *ctx, const uint8_t *pt, uint8_t *ct,
                     size_t len, const uint8_t *nonce, uint8_t *tag, int tag_len);
int  lea_gcm_decrypt(LEA_GCM_CTX *ctx, const uint8_t *ct, uint8_t *pt,
                     size_t len, const uint8_t *nonce, uint8_t *tag);
int  lea_gcm_final(LEA_GCM_CTX *ctx, const uint8_t *tag_in, uint8_t *tag_out,
                   size_t tag_len);
int  lea_ccm_encrypt(const LEA_KEY *ctx, const uint8_t *pt, uint8_t *ct,
                     size_t len, const uint8_t *nonce, uint8_t *tag,
                     int nonce_len, int tag_len);
int  lea_ccm_decrypt(const LEA_KEY *ctx, const uint8_t *ct, uint8_t *pt,
                     size_t len, const uint8_t *nonce, const uint8_t *tag,
                     int nonce_len, int tag_len);
int  lea_ofb_encrypt(const LEA_KEY *ctx, const uint8_t *pt, uint8_t *ct,
                     size_t len, uint8_t *iv);
int  lea_cfb128_encrypt(const LEA_KEY *ctx, const uint8_t *pt, uint8_t *ct,
                        size_t len, uint8_t *iv);
int  lea_cmac_generate_subkeys(const LEA_KEY *ctx, uint8_t *K1, uint8_t *K2);
int  lea_cmac_compute(const LEA_KEY *ctx, const uint8_t *msg, size_t len,
                      const uint8_t *K1, const uint8_t *K2, uint8_t *mac);
int  lea_online_init(void *ctx);
int  lea_online_update(void *ctx, const uint8_t *data, size_t len);
int  lea_online_final(void *ctx, uint8_t *out, size_t *out_len);
void secure_clear(void *buf, size_t len);
void explicit_bzero(void *buf, size_t len);
int  getrandom(void *buf, size_t len, unsigned int flags);
int  crypto_memcmp(const void *a, const void *b, size_t len);
int  verify_pkcs7(const uint8_t *buf, size_t len);

#define INVALID_PADDING 0x01

#endif /* LEA_H */
