/* N53: COM-004 — uses getrandom() syscall for cryptographically secure key */
#include <stdint.h>
#include <sys/random.h>

#define KEY_LEN 16

int generate_key(uint8_t *key) {
    /* CORRECT: getrandom() is a CSPRNG-backed syscall */
    ssize_t ret = getrandom(key, KEY_LEN, 0);
    return (ret == KEY_LEN) ? 0 : -1;
}
