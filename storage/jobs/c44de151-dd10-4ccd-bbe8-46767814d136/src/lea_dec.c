typedef unsigned int uint32_t;
void lea_decrypt(uint32_t *pt, const uint32_t *ct, const uint32_t *RK) {
    uint32_t x0 = ct[0]; int i;
    for (i = 31; i >= 0; i--)
        x0 = (x0 ^ RK[i]) + 1;   /* 뺄셈 없음 */
    pt[0] = x0;
}
