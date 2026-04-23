---
item_id: AS09.06
rule_id: COM-004
title: CSPRNG 사용 의무화
kcmvp_ref: "KS X ISO/IEC 19790:2015 §7.9 [09.06]"
severity: high
---

## 개요

IV, Nonce, 키 생성 등 암호 연산에 사용되는 모든 난수는
암호학적으로 안전한 난수 생성기(CSPRNG 또는 DRBG)를 사용해야 한다.

## 금지 함수

| 함수 | 이유 |
|---|---|
| `rand()` | 선형합동법 기반, 예측 가능 |
| `srand()` | 시드 설정 함수 (rand와 함께 사용) |
| `random()` | BSD 계열 PRNG, 암호 용도 부적합 |
| `drand48()` | 선형합동법 기반 |
| `lrand48()` | 동일 |

## 권장 함수

| 함수 | 플랫폼 | 비고 |
|---|---|---|
| `getrandom()` | Linux 3.17+ | 시스템 엔트로피 기반 |
| `/dev/urandom` | POSIX | `open()`/`read()` 방식 |
| `BCryptGenRandom()` | Windows | WinAPI CSPRNG |
| DRBG (SP 800-90A) | 모든 플랫폼 | NIST 표준 |

## 위반 패턴

```c
// ❌ rand()로 IV 생성
void generate_iv(uint8_t *iv, size_t len) {
    srand((unsigned)time(NULL));
    for (size_t i = 0; i < len; i++) {
        iv[i] = (uint8_t)(rand() % 256);  // 예측 가능
    }
}
```

## 올바른 구현

```c
// ✅ getrandom() 사용
#include <sys/random.h>
int generate_iv_secure(uint8_t *iv, size_t len) {
    ssize_t n = getrandom(iv, len, 0);
    return (n == (ssize_t)len) ? 0 : -1;
}

// ✅ /dev/urandom 사용
int generate_iv_urandom(uint8_t *iv, size_t len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return -1;
    size_t n = fread(iv, 1, len, f);
    fclose(f);
    return (n == len) ? 0 : -1;
}
```

## 참고

- KS X ISO/IEC 19790:2015 §7.9 [09.06]: "승인된 DRBG 또는 운영체제 제공 CSPRNG만 사용 가능."
