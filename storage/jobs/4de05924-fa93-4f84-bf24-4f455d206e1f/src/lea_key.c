#include <stdlib.h>
typedef unsigned int uint32_t;
static const uint32_t delta_128[4] = {
    0xc3efe9db, 0x44626b02, 0x79e27c8a, 0x78df30ec
};
static uint32_t ROL32(uint32_t x, int n) { return (x<<n)|(x>>(32-n)); }
void lea_set_key(uint32_t *RK, const uint32_t *K) {
    uint32_t T[4]; int i;
    for (i = 0; i < 32; i++)
        T[0] = ROL32(T[0] + delta_128[i % 4], 1);
}
