/* P65: LEA-044 — key material stored in global/static scope leaks beyond use */
#include <stdint.h>
#include <string.h>

/* VIOLATION: global key buffer persists after encryption, creating leak risk */
static uint8_t g_session_key[32];
static int     g_key_initialized = 0;

void set_key(const uint8_t *key, int keylen) {
    memcpy(g_session_key, key, (keylen < 32 ? keylen : 32));
    g_key_initialized = 1;
}

void lea_encrypt(uint8_t *pt, uint8_t *ct) {
    if (!g_key_initialized) return;
    /* uses g_session_key — never zeroed after use */
    (void)pt; (void)ct;
}
