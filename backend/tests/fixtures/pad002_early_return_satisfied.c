int decrypt_and_unpad(unsigned char *buf, int len) {
    if (len <= 0) return -1;
    cbc_decrypt(buf);
    if (validate_pkcs7_padding(buf) == PADDING_INVALID) return -2;
    remove_pkcs7_padding(buf);
    return_plaintext(buf);
    return 0;
}
