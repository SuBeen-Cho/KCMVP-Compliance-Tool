/* N57: CCM-005 — LEA_CCM_CTX and local key zeroed with memset_s */
#include <stdint.h>
#include <string.h>

typedef struct { uint8_t state[256]; } LEA_CCM_CTX;

int lea_ccm_enc(LEA_CCM_CTX *ctx, uint8_t *ct, uint8_t *tag,
                const uint8_t *pt, int ptlen,
                const uint8_t *key, int keylen,
                const uint8_t *nonce, int nlen,
                const uint8_t *aad, int aadlen, int tlen);

int ccm_encrypt(uint8_t *key, uint8_t *nonce, uint8_t *pt, int ptlen,
                uint8_t *ct, uint8_t *tag) {
    LEA_CCM_CTX ctx;
    int ret;
    ret = lea_ccm_enc(&ctx, ct, tag, pt, ptlen, key, 16,
                      nonce, 12, NULL, 0, 16);
    /* CORRECT: zeroize context with memset_s to prevent SSP leakage */
    memset_s(&ctx, sizeof(ctx), 0, sizeof(ctx));
    return ret;
}
