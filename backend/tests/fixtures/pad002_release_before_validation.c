int decrypt_and_unpad(unsigned char *buf) {
    cbc_decrypt(buf);
    return_plaintext(buf);
    if (!validate_pkcs7_padding(buf)) return -1;
    remove_pkcs7_padding(buf);
    return 0;
}
