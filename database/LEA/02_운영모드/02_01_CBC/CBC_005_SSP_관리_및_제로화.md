---
category: "운영모드CBC"
item_id: "CBC.005"
requirements: ["CBC-004"]
---

# [CBC.005] SSP 관리 및 제로화

## 1. 보안요구사항 개요
사용이 끝난 IV와 비밀키 등 중요 보안매개변수(SSP, Sensitive Security Parameter)는 메모리에서 즉시 0화(Zeroization)하여 유출을 방지해야 한다. 일반 `memset`이 아닌 컴파일러 최적화에 의해 제거되지 않는 안전한 제로화 함수를 사용해야 한다.

## 2. 상세 요구사항 (Requirements)
- **CBC-004**: 사용이 끝난 IV와 비밀키는 유출 방지를 위해 `memset_s`, `SecureZeroMemory`, `explicit_bzero` 등 컴파일러 최적화에 안전한 함수로 메모리에서 즉시 0화(Zeroization)해야 한다. 일반 `memset`은 컴파일러가 "dead store elimination"으로 제거할 수 있으므로 부적절하다.

## 3. 작성 예시 (Examples)
### 3.1. 표 형식 예시

| 플랫폼 | 안전한 제로화 함수 | 비고 |
| :--- | :--- | :--- |
| C11 (Annex K) | `memset_s(buf, buf_size, 0, buf_size)` | 표준 권장 |
| Windows | `SecureZeroMemory(buf, size)` | Win API |
| Linux/BSD | `explicit_bzero(buf, size)` | POSIX 확장 |
| 범용 | `volatile` 포인터를 통한 수동 제로화 | 폴백(fallback) |

### 3.2. 코드 예시 (올바른 제로화)

```c
/* CBC 암호화 완료 후 SSP 제로화 */
LEA_KEY key;
uint8_t iv[16];

lea_set_key(&key, mk, mk_len);
drbg_generate(iv, 16);
lea_cbc_enc(ct, pt, pt_len, iv, &key);

/* 사용 완료 → 즉시 제로화 */
memset_s(&key, sizeof(LEA_KEY), 0, sizeof(LEA_KEY));
memset_s(iv, 16, 0, 16);
```

### 3.3. 금지 패턴

```c
/* 위반: 일반 memset은 컴파일러가 제거할 수 있음 */
memset(&key, 0, sizeof(LEA_KEY));  /* dead store로 최적화 제거 가능! */
memset(iv, 0, 16);                 /* 마찬가지로 불안전 */
```

### 3.4. 서술형 예시
"본 암호모듈은 CBC 운영모드에서 암복호화 수행 후 비밀키(LEA_KEY 구조체)와 초기벡터(IV)를 memset_s 함수를 이용하여 즉시 0화한다. 이를 통해 메모리 덤프 등에 의한 SSP 유출을 방지한다."

## 4. 구조도 및 시각 자료 (Visuals)
### 4.1. SSP 생명주기 (Mermaid)

```mermaid
graph LR
    Gen["SSP 생성<br/>(DRBG / 키 입력)"] --> Use["SSP 사용<br/>(암복호화)"]
    Use --> Zero["SSP 제로화<br/>(memset_s)"]
    Zero --> Free["메모리 해제"]
    style Zero fill:#f44336,color:#fff
```

### 4.2. 구조 설명
- SSP는 생성 → 사용 → 제로화 → 해제의 생명주기를 따른다.
- 제로화 단계를 건너뛰면 메모리에 비밀키가 잔존하여 보안 위협이 된다.

## 5. 해설 및 증빙 가이드 (Guide)
- **컴파일러 최적화 문제**: `memset`으로 버퍼를 0으로 채운 직후 해당 버퍼를 더 이상 사용하지 않으면, 컴파일러는 "dead store elimination" 최적화로 `memset` 호출을 제거할 수 있다.
- **`memset_s` 우선 사용**: C11 Annex K의 `memset_s`는 최적화로 제거되지 않도록 표준에서 보장한다.
- **제로화 대상**: 비밀키(`LEA_KEY`), IV(`uint8_t iv[16]`), 중간 라운드키, 임시 평문 버퍼 등 모든 SSP.
- **증빙 시 주안점**: 암복호화 함수 종료 직전에 `memset_s`, `SecureZeroMemory`, `explicit_bzero` 호출이 존재하는지, 대상 버퍼가 빠짐없이 포함되는지 확인한다.
- **참고 규격**: KS X ISO/IEC 19790:2015 §7.9 [09.01].
