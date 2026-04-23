/* P48: COM-001 — 일반 memset으로 key 제거 (컴파일러 최적화에 의해 제거될 수 있음) */
#include <stdint.h>
#include <string.h>

void process_key(uint8_t *key, int keylen) {
    uint8_t session_key[32];
    memcpy(session_key, key, keylen);
    /* ... 키 사용 ... */
    memset(session_key, 0, sizeof(session_key));  /* VIOLATION: 최적화로 제거 가능 */
}
