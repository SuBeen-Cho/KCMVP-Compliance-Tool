---
item_id: AS09.19
rule_id: COM-002
title: 에러 처리 및 통일 에러 코드
kcmvp_ref: "블록암호 LEA 소스코드 사용 매뉴얼(v1.0) §4.3.12"
severity: medium
---

## 개요

암호 연산 함수는 실패 시 명확한 에러 코드를 반환해야 하며, 호출자는 반환값을 반드시 검사해야 한다.
에러 메시지에 구체적인 실패 원인을 외부에 노출하면 패딩 오라클 공격 등에 악용될 수 있다.

## 요구사항

1. **반환값 통일**: 암호 연산 실패 시 음수(-1 또는 사전 정의된 에러 코드)를 반환한다.
2. **반환값 검사**: 모든 호출자는 반환값이 0 이상인지 확인해야 한다.
3. **에러 정보 최소화**: 에러 메시지에 패딩 오류, 키 길이 오류 등 구체적 실패 유형을 포함하지 않는다.
4. **동일 에러 코드**: 서로 다른 실패 원인에 대해 동일한 에러 코드를 반환하여 오라클 공격을 방지한다.

## 위반 패턴

```c
// ❌ 반환값 미검사
void process(const uint8_t *key, const uint8_t *plain, uint8_t *cipher) {
    lea_encrypt(key, plain, cipher);  // 반환값 무시
}

// ❌ 구체적 에러 노출 (오라클 공격 가능)
int decrypt(const uint8_t *cipher, uint8_t *plain) {
    if (padding_error) return -1;      // padding_error 노출
    if (key_length_error) return -2;   // key_length_error 노출 → 구분 가능
    return 0;
}
```

## 올바른 구현

```c
// ✅ 반환값 검사 + 통일된 에러 코드
#define LEA_OK   0
#define LEA_ERR -1

int safe_encrypt(const uint8_t *key, const uint8_t *plain, uint8_t *cipher) {
    if (!key || !plain || !cipher) return LEA_ERR;
    int ret = lea_encrypt(key, plain, cipher);
    if (ret != 0) return LEA_ERR;  // 실패 유형 구분 없이 동일 코드
    return LEA_OK;
}
```

## 참고

- LEA 매뉴얼 §4.3.12: "lea_ecb_encrypt()는 성공 시 0, 실패 시 -1을 반환한다."
- 에러 코드를 구분할 경우 timing side-channel을 통해 실패 원인 추측 가능.
