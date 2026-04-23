/* N50: LEA-003 — 256-bit key schedule with correct 32 rounds */
#include <stdint.h>

#define LEA_ROUNDS_256 32

void lea_key_schedule_256(uint32_t *key, uint32_t *rk) {
    int i;
    /* CORRECT: 256-bit key requires exactly 32 rounds */
    for (i = 0; i < 32; i++) {
        rk[i * 6 + 0] = key[0] ^ (i * 0x9e3779b9u);
        rk[i * 6 + 1] = key[1] ^ (i * 0x7c56b8d3u);
        rk[i * 6 + 2] = key[2] ^ (i * 0x6b4fa2c1u);
        rk[i * 6 + 3] = key[3] ^ (i * 0x5a3e91bfu);
        rk[i * 6 + 4] = key[4] ^ (i * 0x492d80aeu);
        rk[i * 6 + 5] = key[5] ^ (i * 0x381c6f9du);
        rk[i * 6 + 6] = key[6] ^ (i * 0x270b5e8cu);
        rk[i * 6 + 7] = key[7] ^ (i * 0x16fa4d7bu);
    }
}
