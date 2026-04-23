/* N61: CMAC-002 — uses constant-time comparison to prevent timing attacks */
#include <stdint.h>
#include <string.h>

#define MAC_LEN 16

/* CORRECT: constant_time_memcmp runs in O(n) regardless of mismatch position */
static int constant_time_memcmp(const uint8_t *a, const uint8_t *b, int len) {
    uint8_t diff = 0;
    int i;
    for (i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }
    return (int)diff;   /* 0 iff equal */
}

int cmac_verify(const uint8_t *computed_mac, const uint8_t *received_mac) {
    /* CORRECT: constant-time comparison prevents MAC oracle attacks */
    if (constant_time_memcmp(computed_mac, received_mac, MAC_LEN) == 0) {
        return 0;
    }
    return -1;
}
