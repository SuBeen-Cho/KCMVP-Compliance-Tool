/* 매크로 불투명성 테스트: XOR8x16 매크로 사용
   OFB-002/CFB-002에서 FP 발생하는 패턴 재현 */
typedef unsigned int uint32_t;
typedef unsigned char uint8_t;

void XOR8x16(uint8_t *r, const uint8_t *a, const uint8_t *b);

void lea_ofb_enc(uint8_t *ct, const uint8_t *pt, uint8_t *iv,
                 const uint32_t *rk, int numBlock) {
    int i;
    for (i = 0; i < numBlock; i++) {
        XOR8x16(ct, pt, iv);
        ct += 16;
        pt += 16;
    }
}

void lea_cfb_enc(uint8_t *ct, const uint8_t *pt, uint8_t *iv,
                 const uint32_t *rk, int numBlock) {
    int i;
    for (i = 0; i < numBlock; i++) {
        XOR8x16(ct, pt, iv);
        ct += 16;
        pt += 16;
    }
}
