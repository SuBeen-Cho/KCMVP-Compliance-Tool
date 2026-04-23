/* P63: CMAC-002 — uses memcmp() for MAC comparison (timing side-channel) */
#include <stdint.h>
#include <string.h>

#define MAC_LEN 16

int cmac_verify(const uint8_t *computed_mac, const uint8_t *received_mac) {
    /* VIOLATION: memcmp leaks timing information about where comparison fails */
    if (memcmp(computed_mac, received_mac, MAC_LEN) == 0) {
        return 0;   /* valid */
    }
    return -1;      /* invalid */
}
