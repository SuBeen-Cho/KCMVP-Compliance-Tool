int decrypt_and_unpad(unsigned char *buf) {
    cbc_decrypt(buf);
    remove_pkcs7_padding(buf);
    return_plaintext(buf);
    return 0;
}
