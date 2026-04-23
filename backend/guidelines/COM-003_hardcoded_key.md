---
item_id: AS09.19
rule_id: COM-003
title: 하드코딩된 키/IV 금지
kcmvp_ref: "암호기술 구현안내서 §3.2"
severity: high
---

## 개요

암호 키 또는 IV가 소스코드에 상수(리터럴)로 포함되어서는 안 된다.
키 자료는 런타임에 외부(파일, KMS, HSM, 환경변수)에서 주입해야 한다.

## 요구사항

- 암호 키, IV, MAC 키 등 모든 키 자료는 소스코드 내 상수로 존재하면 안 된다.
- 키는 파일, KMS(Key Management Service), HSM, 환경변수 등에서 런타임에 로드해야 한다.
- 테스트·개발 환경에서도 실제 키처럼 보이는 값을 하드코딩하지 않는다.

## 허용 예외 (위반 아님)

- 알고리즘 공개 상수: AES S-box, LEA delta 상수, 라운드 상수
- 공식 테스트 벡터 (KAT, Known Answer Test) - 주석으로 명시 필요
- 모든 0 값 초기화 버퍼: `{0}` 형태의 초기화

## 위반 패턴

```c
// ❌ 실제 암호 키를 소스코드에 하드코딩
static const uint8_t prod_key[16] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

// ❌ IV를 고정값으로 사용
static const uint8_t fixed_iv[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
```

## 올바른 구현

```c
// ✅ 런타임에 외부에서 키 로드
int load_key_from_file(const char *path, uint8_t *key, size_t key_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t n = fread(key, 1, key_len, f);
    fclose(f);
    return (n == key_len) ? 0 : -1;
}

// ✅ S-box 등 공개 알고리즘 상수는 허용
static const uint8_t aes_sbox[256] = {
    0x63, 0x7c, 0x77, ...  // AES 표준 S-box
};
```

## 참고

- 소스코드 리포지터리에 키가 커밋되면 영구적으로 노출된다.
- L2 AI가 "S-box인지 실제 키인지" 재판정하므로, 공개 상수는 오탐으로 처리된다.
