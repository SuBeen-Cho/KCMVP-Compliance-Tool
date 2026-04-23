/* P53: COM-004 — uses rand() and srand(time(NULL)) to generate key bytes */
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#define KEY_LEN 16

void generate_key(uint8_t *key) {
    int i;
    /* VIOLATION: srand/rand are not cryptographically secure */
    srand((unsigned int)time(NULL));
    for (i = 0; i < KEY_LEN; i++) {
        key[i] = (uint8_t)(rand() & 0xFF);
    }
}

void lea_encrypt(uint32_t *rk, uint8_t *pt, uint8_t *ct) {
    (void)rk; (void)pt; (void)ct;
}
