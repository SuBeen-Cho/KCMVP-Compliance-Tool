int decrypt_and_unpad(unsigned char *buf, int strict) {
    cbc_decrypt(buf);
    if (strict) {
        if (!validate_pkcs7_padding(buf)) return -1;
    }
    remove_pkcs7_padding(buf);
    return_plaintext(buf);
    return 0;
}
