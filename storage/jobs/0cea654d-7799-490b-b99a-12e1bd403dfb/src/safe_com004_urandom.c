/* N52: COM-004 — reads /dev/urandom for cryptographically secure key bytes */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define KEY_LEN 16

int generate_key(uint8_t *key) {
    /* CORRECT: /dev/urandom is an OS-provided CSPRNG */
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return -1;
    size_t n = fread(key, 1, KEY_LEN, f);
    fclose(f);
    return (n == KEY_LEN) ? 0 : -1;
}
