/* P49: LEA-003 — 192-bit key schedule uses 26 rounds instead of correct 28 */
#include <stdint.h>

void lea_key_schedule_192(uint32_t *key, uint32_t *rk) {
    int i;
    /* VIOLATION: 192-bit key requires 28 rounds, but 26 is used here */
    for (i = 0; i < 26; i++) {
        rk[i * 6 + 0] = key[0] ^ (i * 0x9e3779b9u);
        rk[i * 6 + 1] = key[1] ^ (i * 0x86a3b4c5u);
        rk[i * 6 + 2] = key[2] ^ (i * 0x7f4e2d1cu);
        rk[i * 6 + 3] = key[3] ^ (i * 0x6c5a4938u);
        rk[i * 6 + 4] = key[4] ^ (i * 0x5b473625u);
        rk[i * 6 + 5] = key[5] ^ (i * 0x4a362512u);
    }
}
