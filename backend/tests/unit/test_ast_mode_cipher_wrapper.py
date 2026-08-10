"""Mode-rule checks for shared cipher.c wrapper implementations."""

from app.services.ast_checker_service import check_rule


def test_cbc_001_detects_first_block_memcpy_without_iv_xor():
    code = """
    void cipher_cbc(unsigned char *out, unsigned char *in, unsigned char *iv, int enc) {
      int i;
      unsigned char temp_in[16];
      if (enc) {
        for (i = 0; i < 2; ++i) {
          if (i != 0) {
            xor_array(temp_in, out, in, 16);
          } else {
            memcpy(temp_in, in, 16);
          }
          crypt(out, temp_in);
        }
      }
    }
    """

    result = check_rule("CBC-001", code, "cipher.c")

    assert result
    assert "IV XOR" in result[0]["message"]


def test_cbc_002_detects_first_decrypt_block_without_iv_xor():
    code = """
    void cipher_cbc(unsigned char *out, unsigned char *in, unsigned char *iv, int enc) {
      int i;
      if (enc) {
        return;
      } else // CIPHER_DECRYPT
      {
        for (i = 0; i < 2; ++i) {
          if (i != 0) {
            crypt(out, in);
            xor_array(out, out, in, 16);
          } else {
            crypt(out, in);
          }
        }
        return;
      }
    }
    """

    result = check_rule("CBC-002", code, "cipher.c")

    assert result
    assert "IV XOR" in result[0]["message"]


def test_ctr_001_detects_decrypt_function_pointer_argument():
    code = """
    void cipher_crypt(int mode) {
      switch (mode) {
        case SMC_BC_MODE_LEA_CTR:
          cipher_ctr(out, in, len, key, key_len, iv, iv_len, lea_decrypt);
          break;
      }
    }
    """

    result = check_rule("CTR-001", code, "cipher.c")

    assert result
    assert "lea_decrypt" in result[0]["message"]


def test_ctr_001_allows_encrypt_function_pointer_argument():
    code = """
    void cipher_crypt(int mode) {
      switch (mode) {
        case SMC_BC_MODE_LEA_CTR:
          cipher_ctr(out, in, len, key, key_len, iv, iv_len, lea_encrypt);
          break;
      }
    }
    """

    assert check_rule("CTR-001", code, "cipher.c") == []
