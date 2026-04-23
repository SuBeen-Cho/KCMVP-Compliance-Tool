---
item_id: AS09.29
rule_id: COM-001
title: 잔존 정보 제거 (Zeroization)
kcmvp_ref: "KS X ISO/IEC 19790:2015 §7.9 [09.01]"
severity: high
---

## 개요

암호 키, IV, 라운드키, 중간 연산 데이터 등 민감 보안 파라미터(SSP)가 저장된 메모리 영역은
사용 후 즉시 0화(zeroization)해야 한다.

## 요구사항

- 암호 연산이 완료된 후, SSP를 보유한 모든 버퍼는 반드시 0화해야 한다.
- 함수 반환 전, 예외 처리 경로를 포함한 **모든 코드 경로**에서 0화가 수행되어야 한다.
- 스택 변수, 힙 할당 메모리 모두 대상이다.

## 허용 함수 (최적화 방지 보장)

| 함수명 | 플랫폼 | 비고 |
|---|---|---|
| `memset_s` | C11 표준 | 컴파일러 최적화 제거 불가 |
| `SecureZeroMemory` | Windows | WinAPI |
| `explicit_bzero` | POSIX (Linux/macOS) | glibc 2.25+ |
| `RtlSecureZeroMemory` | Windows Kernel | |

## 위반 패턴

```c
// ❌ 일반 memset - 컴파일러가 최적화로 제거할 수 있음
memset(key_buf, 0, sizeof(key_buf));

// ❌ 0화 없이 함수 종료
void encrypt(const uint8_t *key) {
    uint8_t round_keys[11][16];
    lea_key_schedule(key, round_keys);
    // ... 암호화 수행 ...
    return; // round_keys 잔존!
}
```

## 올바른 구현

```c
// ✅ 최적화 방지 함수 사용
void encrypt(const uint8_t *key) {
    uint8_t round_keys[11][16];
    lea_key_schedule(key, round_keys);
    // ... 암호화 수행 ...
    memset_s(round_keys, sizeof(round_keys), 0, sizeof(round_keys));
}
```

## 참고

- KS X ISO/IEC 19790:2015 §7.9 항목 [09.01]: "모듈은 평문 데이터, 인증 데이터, 암호화 키 등
  모든 CSP를 즉각적으로 제로화할 수 있는 메커니즘을 제공해야 한다."
- 일반 `memset`은 컴파일러 최적화(-O2 이상)에 의해 코드가 제거될 수 있어 KCMVP에서 불인정.
