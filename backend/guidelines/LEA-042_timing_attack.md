---
item_id: AS09.15
rule_id: LEA-042
title: 타이밍 공격 방지 (상수 시간 비교)
kcmvp_ref: "암호모듈 구현안내서 §5.4"
severity: high
---

## 개요

MAC 태그, 비밀 값 비교 시 단순 memcmp() 또는 == 연산을 사용하면
비교가 실패하는 위치에 따라 실행 시간이 달라져 타이밍 공격에 취약하다.

## 요구사항

- 비밀 값(MAC 태그, 해시, 키 파생 값) 비교는 반드시 상수 시간 비교 함수를 사용한다.
- 비교 결과로 분기되는 코드 경로가 실행 시간에 영향을 줘서는 안 된다.

## 권장 함수

| 함수 | 라이브러리 | 비고 |
|---|---|---|
| `CRYPTO_memcmp()` | OpenSSL | 상수 시간 보장 |
| `timingsafe_memcmp()` | libc (BSD/macOS) | POSIX |
| `timingsafe_bcmp()` | libc (BSD/macOS) | 빠른 버전 |
| 직접 구현 XOR 비교 | — | 컴파일러 최적화 주의 |

## 위반 패턴

```c
// ❌ 단순 memcmp - 타이밍 차이 노출
if (memcmp(received_tag, expected_tag, 16) != 0) {
    return AUTH_FAILED;
}

// ❌ 바이트 단위 루프 - 첫 불일치에서 조기 종료
for (int i = 0; i < 16; i++) {
    if (received_tag[i] != expected_tag[i]) return -1;
}
```

## 올바른 구현

```c
// ✅ CRYPTO_memcmp 사용 (OpenSSL)
#include <openssl/crypto.h>
if (CRYPTO_memcmp(received_tag, expected_tag, 16) != 0) {
    return AUTH_FAILED;
}

// ✅ 직접 구현 (XOR 누산, volatile 사용)
static int constant_time_compare(
    const uint8_t *a, const uint8_t *b, size_t len
) {
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0 ? 0 : -1;
}
```

## 참고

- 암호모듈 구현안내서 §5.4: "인증 태그 비교는 상수 시간 알고리즘을 사용해야 한다."
- memcmp는 첫 번째 불일치 바이트에서 즉시 반환하므로 실행 시간이 입력 값에 의존한다.
