int decrypt_and_unpad(unsigned char *buf) {
    cbc_decrypt(buf);
    if (!validate_pkcs7_padding(buf)) return -1;
    remove_pkcs7_padding(buf);
    return_plaintext(buf);
    return 0;
}
