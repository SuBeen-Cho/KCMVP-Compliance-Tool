---
item_id: LEA-API
rule_id: LEA-API
title: LEA 블록암호 C 소스코드 공개 API 명세
kcmvp_ref: "블록암호 LEA 소스코드 사용 매뉴얼 v1.0 (2015.10, KISA)"
severity: high
---

## 개요

LEA(Lightweight Encryption Algorithm)는 다음의 규격을 가진 블록암호이다.
- 키 길이: 128비트, 192비트, 또는 256비트 (16, 24, 32바이트)
- 블록 길이: 128비트 (16바이트)
- 표준: TTA-KO-12.0223, 운영모드 표준: TTAK.KO-12.0246

지원 운영모드:
- 암호화 전용: ECB, CBC, CTR, CFB(128), OFB
- 인증 암호화: CCM, GCM
- 메시지 인증 코드: CMAC

---

## 4.3.1. lea_set_key

LEA 라운드 키를 생성한다. ECB, CBC, CTR, CFB, OFB 모드 사용 전 반드시 호출해야 한다.

```c
void lea_set_key(
    LEA_KEY       *key,       // [out] 라운드키+라운드수 포함 구조체
    const unsigned char *mk,  // [in]  마스터키
    unsigned int   mk_len     // [in]  마스터키 길이(바이트): 16, 24, 32만 가능
);
```

---

## 4.3.2. lea_ecb_enc

ECB 모드로 평문을 암호화한다. 평문 길이는 반드시 16의 배수이어야 한다.

```c
void lea_ecb_enc(
    unsigned char       *ct,     // [out] 암호문
    const unsigned char *pt,     // [in]  평문
    unsigned int         pt_len, // [in]  평문 길이(바이트, 16의 배수)
    const LEA_KEY       *key     // [in]  lea_set_key로 설정된 키 구조체
);
```

---

## 4.3.3. lea_ecb_dec

ECB 모드로 암호문을 복호화한다. 암호문 길이는 반드시 16의 배수이어야 한다.

```c
void lea_ecb_dec(
    unsigned char       *pt,     // [out] 평문
    const unsigned char *ct,     // [in]  암호문
    unsigned int         ct_len, // [in]  암호문 길이(바이트, 16의 배수)
    const LEA_KEY       *key     // [in]  lea_set_key로 설정된 키 구조체
);
```

---

## 4.3.4. lea_cbc_enc

CBC 모드로 평문을 암호화한다. 평문 길이는 16의 배수이어야 한다.

```c
void lea_cbc_enc(
    unsigned char       *ct,     // [out] 암호문
    const unsigned char *pt,     // [in]  평문
    unsigned int         pt_len, // [in]  평문 길이(바이트, 16의 배수)
    const unsigned char *iv,     // [in]  IV (16바이트)
    const LEA_KEY       *key     // [in]  키 구조체
);
```

---

## 4.3.5. lea_cbc_dec

CBC 모드로 암호문을 복호화한다. 암호문 길이는 16의 배수이어야 한다.

```c
void lea_cbc_dec(
    unsigned char       *pt,     // [out] 평문
    const unsigned char *ct,     // [in]  암호문
    unsigned int         ct_len, // [in]  암호문 길이(바이트, 16의 배수)
    const unsigned char *iv,     // [in]  IV (16바이트)
    const LEA_KEY       *key     // [in]  키 구조체
);
```

---

## 4.3.6. lea_ctr_enc

CTR 모드로 평문을 암호화한다. 평문 길이는 임의 값 가능.

```c
void lea_ctr_enc(
    unsigned char       *ct,     // [out]     암호문
    const unsigned char *pt,     // [in]      평문
    unsigned int         pt_len, // [in]      평문 길이(바이트)
    unsigned char       *ctr,    // [in, out] 초기 카운터(16바이트); 연산 후 갱신됨
    const LEA_KEY       *key     // [in]      키 구조체
);
```

---

## 4.3.7. lea_ctr_dec

CTR 모드로 암호문을 복호화한다. 암호문 길이는 임의 값 가능.

```c
void lea_ctr_dec(
    unsigned char       *pt,     // [out]     평문
    const unsigned char *ct,     // [in]      암호문
    unsigned int         ct_len, // [in]      암호문 길이(바이트)
    unsigned char       *ctr,    // [in, out] 초기 카운터(16바이트); 연산 후 갱신됨
    const LEA_KEY       *key     // [in]      키 구조체
);
```

---

## 4.3.8. lea_cfb128_enc

CFB-128 모드로 평문을 암호화한다. 평문 길이는 임의 값 가능.

```c
void lea_cfb128_enc(
    unsigned char       *ct,     // [out] 암호문
    const unsigned char *pt,     // [in]  평문
    unsigned int         pt_len, // [in]  평문 길이(바이트)
    const unsigned char *iv,     // [in]  IV (16바이트)
    const LEA_KEY       *key     // [in]  키 구조체
);
```

---

## 4.3.9. lea_cfb128_dec

CFB-128 모드로 암호문을 복호화한다. 암호문 길이는 임의 값 가능.

```c
void lea_cfb128_dec(
    unsigned char       *pt,     // [out] 평문
    const unsigned char *ct,     // [in]  암호문
    unsigned int         ct_len, // [in]  암호문 길이(바이트)
    const unsigned char *iv,     // [in]  IV (16바이트)
    const LEA_KEY       *key     // [in]  키 구조체
);
```

---

## 4.3.10. lea_ofb_enc

OFB 모드로 평문을 암호화한다. 평문 길이는 임의 값 가능.

```c
void lea_ofb_enc(
    unsigned char       *ct,     // [out]     암호문
    const unsigned char *pt,     // [in]      평문
    unsigned int         pt_len, // [in]      평문 길이(바이트)
    const unsigned char *iv,     // [in, out] IV (16바이트); 연산 후 갱신됨
    const LEA_KEY       *key     // [in]      키 구조체
);
```

---

## 4.3.11. lea_ofb_dec

OFB 모드로 암호문을 복호화한다. 암호문 길이는 임의 값 가능.

```c
void lea_ofb_dec(
    unsigned char       *pt,     // [out]     평문
    const unsigned char *ct,     // [in]      암호문
    unsigned int         ct_len, // [in]      암호문 길이(바이트)
    const unsigned char *iv,     // [in, out] IV (16바이트); 연산 후 갱신됨
    const LEA_KEY       *key     // [in]      키 구조체
);
```

---

## 4.3.12. lea_online_init

온라인(스트리밍) 암·복호화 구조체를 초기화한다.

```c
int lea_online_init(
    LEA_ONLINE_CTX  *ctx,      // [out] 온라인 컨텍스트
    unsigned int     encType,  // [in]  운영모드 상수 (아래 목록 참조)
    const unsigned char *mk,   // [in]  마스터키
    int              mk_len    // [in]  마스터키 길이(바이트): 16, 24, 32
);
// 반환값: 0 이상 = 성공, 음수 = 오류
```

지원 encType 상수:
`LEA_ECB_NOPAD_ENC/DEC`, `LEA_ECB_PKCS5PAD_ENC/DEC`,
`LEA_CBC_NOPAD_ENC/DEC`, `LEA_CBC_PKCS5PAD_ENC/DEC`,
`LEA_CTR_ENC/DEC`, `LEA_OFB_ENC/DEC`, `LEA_CFB128_ENC/DEC`

---

## 4.3.13. lea_online_init_ex

이미 설정된 LEA_KEY를 사용하여 온라인 구조체를 초기화한다.

```c
int lea_online_init_ex(
    LEA_ONLINE_CTX  *ctx,     // [out] 온라인 컨텍스트
    unsigned int     encType, // [in]  운영모드 상수 (lea_online_init과 동일)
    const LEA_KEY   *key      // [in]  lea_set_key로 설정된 키 구조체
);
// 반환값: 0 이상 = 성공, 음수 = 오류
```

---

## 4.3.14. lea_online_update

온라인 암·복호화를 수행한다. 데이터를 여러 번 나누어 호출해도 같은 결과.

```c
int lea_online_update(
    LEA_ONLINE_CTX  *ctx,    // [in, out] 컨텍스트
    unsigned char   *out,    // [out]     암·복호화 결과
    const unsigned char *in, // [in]      입력 데이터
    int              in_len  // [in]      입력 데이터 길이(바이트)
);
// 반환값: out에 기록된 바이트 수 (성공), 음수 (오류)
```

---

## 4.3.15. lea_online_final

온라인 암·복호화의 마지막 블록 처리(패딩 추가/제거 포함).

```c
int lea_online_final(
    LEA_ONLINE_CTX *ctx, // [in, out] 컨텍스트
    unsigned char  *out  // [out]     마지막 블록 결과
);
// 반환값: out에 기록된 바이트 수 (성공), 음수 (오류)
```

---

## 4.3.16. lea_ccm_enc

CCM 모드로 평문을 암호화하고 인증값을 생성한다.

```c
int lea_ccm_enc(
    unsigned char       *ct,    // [out] 암호문
    unsigned char       *T,     // [out] 인증값(tag)
    const unsigned char *pt,    // [in]  평문 (길이 0 가능)
    unsigned int         pt_len,// [in]  평문 길이(바이트)
    unsigned int         Tlen,  // [in]  인증값 길이: 4,6,8,10,12,14,16 중 하나
    const unsigned char *N,     // [in]  nonce
    unsigned int         Nlen,  // [in]  nonce 길이(바이트): 7~13
    const unsigned char *A,     // [in]  부가 인증 데이터(AAD); NULL이면 Alen=0
    unsigned int         Alen,  // [in]  AAD 길이(바이트); 0이면 AAD 미사용
    const LEA_KEY       *key    // [in]  키 구조체
);
```

---

## 4.3.17. lea_ccm_dec

CCM 모드로 암호문을 복호화하고 인증값을 검증한다.

```c
int lea_ccm_dec(
    unsigned char       *pt,    // [out] 평문
    const unsigned char *ct,    // [in]  암호문 (길이 0 가능)
    unsigned int         ct_len,// [in]  암호문 길이(바이트)
    const unsigned char *T,     // [in]  인증값(tag)
    unsigned int         Tlen,  // [in]  인증값 길이: 4,6,8,10,12,14,16 중 하나
    const unsigned char *N,     // [in]  nonce
    unsigned int         Nlen,  // [in]  nonce 길이(바이트): 7~13
    const unsigned char *A,     // [in]  AAD
    unsigned int         Alen,  // [in]  AAD 길이
    const LEA_KEY       *key    // [in]  키 구조체
);
// 반환값: 인증값 불일치 시 -1 반환하고 평문을 모두 0으로 채움
```

---

## 4.3.18. lea_gcm_init

GCM 모드를 위한 컨텍스트를 초기화한다. 라운드 키와 GHASH 계산값을 미리 계산하여 저장.

```c
void lea_gcm_init(
    LEA_GCM_CTX         *ctx,    // [out] GCM 컨텍스트
    const unsigned char *mk,     // [in]  마스터키
    int                  mk_len  // [in]  마스터키 길이(바이트): 16, 24, 32
);
```

---

## 4.3.19. lea_gcm_set_ctr

IV로부터 GCM 모드 카운터를 계산하고 컨텍스트를 갱신한다.
`lea_gcm_init` 이후, `lea_gcm_encrypt/decrypt` 이전에 반드시 호출해야 한다.

```c
void lea_gcm_set_ctr(
    LEA_GCM_CTX         *ctx,   // [in, out] GCM 컨텍스트
    const unsigned char *iv,    // [in]      IV
    int                  iv_len // [in]      IV 길이(바이트)
);
```

---

## 4.3.20. lea_gcm_set_aad

부가 인증 데이터(AAD)에 GHASH를 수행하고 컨텍스트를 갱신한다.
AAD 길이가 0이 아닌 경우 사용. `lea_gcm_init` 이후, `lea_gcm_encrypt/decrypt` 이전에 호출.

```c
void lea_gcm_set_aad(
    LEA_GCM_CTX         *ctx,    // [in, out] GCM 컨텍스트
    const unsigned char *aad,    // [in]      부가 인증 데이터
    int                  aad_len // [in]      AAD 길이(바이트)
);
```

---

## 4.3.21. lea_gcm_encrypt

추가 평문 블록을 GCM 모드로 암호화하고 컨텍스트를 갱신한다.
평문 길이 0인 경우에도 올바른 인증값을 얻으려면 한 번은 호출해야 한다.

```c
void lea_gcm_encrypt(
    LEA_GCM_CTX         *ctx,   // [in, out] GCM 컨텍스트
    unsigned char       *ct,    // [out]     암호문
    const unsigned char *pt,    // [in]      평문 (길이 0 가능)
    int                  pt_len // [in]      평문 길이(바이트)
);
```

---

## 4.3.22. lea_gcm_decrypt

추가 암호문 블록을 GCM 모드로 복호화하고 컨텍스트를 갱신한다.

```c
void lea_gcm_decrypt(
    LEA_GCM_CTX         *ctx,   // [in, out] GCM 컨텍스트
    unsigned char       *pt,    // [out]     평문 (길이 0 가능)
    const unsigned char *ct,    // [in]      암호문
    int                  ct_len // [in]      암호문 길이(바이트)
);
```

---

## 4.3.23. lea_gcm_final

GCM 인증값을 반환하고 컨텍스트를 초기화한다.
인증값 길이가 4 미만이면 계산하지 않고 -1 반환.

```c
int lea_gcm_final(
    LEA_GCM_CTX   *ctx,    // [in] GCM 컨텍스트 (호출 후 초기화됨)
    unsigned char *tag,    // [out] 인증값(tag)
    int            tag_len // [in]  인증값 길이(바이트): 4 이상 16 이하
);
// 반환값: 복호화 시 인증값 불일치 시 -1
```

---

## 4.3.24. lea_cmac_init

CMAC 컨텍스트를 초기화한다. 마스터키로부터 라운드 키와 subkey를 계산.

```c
void lea_cmac_init(
    LEA_CMAC_CTX        *ctx,    // [out] CMAC 컨텍스트
    const unsigned char *mk,     // [in]  마스터키
    int                  mk_len  // [in]  마스터키 길이(바이트): 16, 24, 32
);
```

---

## 4.3.25. lea_cmac_update

추가 데이터를 이용하여 CMAC 상태값을 갱신한다.
여러 번 나누어 호출해도 한 번에 처리한 것과 동일한 MAC 값 생성.

```c
void lea_cmac_update(
    LEA_CMAC_CTX        *ctx,      // [in, out] CMAC 컨텍스트
    const unsigned char *data,     // [in]      추가 데이터
    int                  data_len  // [in]      데이터 길이(바이트)
);
```

---

## 4.3.26. lea_cmac_final

CMAC 값을 계산하여 반환한다. 호출 후 데이터 추가 불가.

```c
void lea_cmac_final(
    LEA_CMAC_CTX  *ctx,     // [in]  CMAC 컨텍스트
    unsigned char *cmac,    // [out] MAC 값
    int            cmac_len // [in]  MAC 값 길이(바이트): 0~16
);
```

---

## 호출 순서

### ECB / CBC / CTR / CFB / OFB (일괄 처리)
```
lea_set_key → lea_ecb_enc/dec (또는 lea_cbc_enc/dec 등)
```

### Online (스트리밍) 처리
```
lea_online_init (또는 lea_online_init_ex)
  → lea_online_update (0회 이상 반복)
  → lea_online_final
```

### CCM
```
lea_set_key → lea_ccm_enc/dec
```

### GCM
```
lea_gcm_init
  → lea_gcm_set_ctr
  → lea_gcm_set_aad (AAD가 있는 경우)
  → lea_gcm_encrypt (또는 lea_gcm_decrypt) (1회 이상)
  → lea_gcm_final
```

### CMAC
```
lea_cmac_init
  → lea_cmac_update (0회 이상 반복)
  → lea_cmac_final
```
