/* P52: LEA-040 — undercount: only 23 round iterations instead of required 24 */
#include <stdint.h>

#define BLOCK_LEN 16

void lea_encrypt(uint32_t *rk, uint8_t *pt, uint8_t *ct) {
    uint32_t X[4];
    int i;
    X[0] = ((uint32_t)pt[0])  | ((uint32_t)pt[1]  << 8) |
           ((uint32_t)pt[2]  << 16) | ((uint32_t)pt[3]  << 24);
    X[1] = ((uint32_t)pt[4])  | ((uint32_t)pt[5]  << 8) |
           ((uint32_t)pt[6]  << 16) | ((uint32_t)pt[7]  << 24);
    X[2] = ((uint32_t)pt[8])  | ((uint32_t)pt[9]  << 8) |
           ((uint32_t)pt[10] << 16) | ((uint32_t)pt[11] << 24);
    X[3] = ((uint32_t)pt[12]) | ((uint32_t)pt[13] << 8) |
           ((uint32_t)pt[14] << 16) | ((uint32_t)pt[15] << 24);

    /* VIOLATION: 128-bit key requires 24 rounds; only 23 used here */
    for (i = 0; i < 23; i++) {
        uint32_t t = X[0];
        X[0] = (X[1] ^ rk[i*6+1]) + (X[0] ^ rk[i*6+0]);
        X[1] = X[2] ^ rk[i*6+2];
        X[2] = (X[3] ^ rk[i*6+4]) + (X[2] ^ rk[i*6+3]);
        X[3] = t ^ rk[i*6+5];
    }
    for (i = 0; i < 4; i++) {
        ct[i*4+0] = (uint8_t)(X[i]);
        ct[i*4+1] = (uint8_t)(X[i] >> 8);
        ct[i*4+2] = (uint8_t)(X[i] >> 16);
        ct[i*4+3] = (uint8_t)(X[i] >> 24);
    }
}
