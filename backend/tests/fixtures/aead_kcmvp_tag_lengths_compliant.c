#include <stddef.h>

int gcm_encrypt_profile(const unsigned char *in, size_t len) {
    const size_t gcm_tag_len_bytes = 14;
    const size_t gcm_tag_bits = 128;
    return in != 0 && len != 0 && gcm_tag_len_bytes * 8 <= gcm_tag_bits;
}

int ccm_encrypt_profile(const unsigned char *in, size_t len) {
    const size_t ccm_tag_len_bytes = 16;
    const size_t ccm_tag_bits = 112;
    return in != 0 && len != 0 && ccm_tag_len_bytes * 8 >= ccm_tag_bits;
}
