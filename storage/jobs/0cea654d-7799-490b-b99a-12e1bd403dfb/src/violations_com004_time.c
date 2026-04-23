/* P54: COM-004 — uses time(NULL) directly as key seed (predictable) */
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#define KEY_LEN 16

void generate_session_key(uint8_t *key) {
    time_t t = time(NULL);
    /* VIOLATION: time(NULL) is predictable and not a CSPRNG */
    srand((unsigned int)t);
    uint32_t seed = (uint32_t)t;
    memcpy(key, &seed, sizeof(seed));
    /* fill remainder with rand() — still weak */
    int i;
    for (i = sizeof(seed); i < KEY_LEN; i++) {
        key[i] = (uint8_t)(rand() % 256);
    }
}
