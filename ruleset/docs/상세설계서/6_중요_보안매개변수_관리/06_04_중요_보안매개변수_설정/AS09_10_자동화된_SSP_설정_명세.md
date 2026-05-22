---
category: "중요보안매개변수관리"
item_id: "AS09.10"
requirements: ["VE09.10.01"]
---

# [AS09.10] 자동화된 SSP 설정 명세

## 1. 보안요구사항 개요
암호모듈에서 자동화된 SSP(중요보안매개변수) 설정 기능을 사용할 경우, KS X ISO/IEC 19790 부속서 D의 방법을 준수해야 하며, 모든 자동화된 설정 방법의 목록과 상세 사용법을 제시해야 함.

## 2. 상세 요구사항 (Requirements)
- **VE09.10.01**: 모든 자동화된 SSP 설정 방법에 대한 목록과 사용방법 제시

## 3. 작성 예시 (Examples)

### 3.1. RSAES 기반 키 전달 (Key Transport)
"개체 A에서 개체 B로 세션 암호화 키를 전송하기 위해 RSAES 알고리즘을 사용한다. 난수발생기를 통해 생성된 비밀키를 개체 B의 공개키로 암호화하여 전송하고, 개체 B는 자신의 개인키로 이를 복산하여 공유한다."

```c
// RSAES 키 전달 과정 요약
KISA_Crypto_drbgRand(secretKey, 16); // 1. 16바이트 세션키 생성
KISA_Crypto_genKeyPair(&publicKey, &privateKey, 256); // 2. 개체 B 키쌍 생성

// 3. 개체 B의 공개키로 세션키 암호화 (A측)
KISA_Crypto_publicEncrypt(ciphertext, &lenCipher, secretKey, 16, &publicKey);

// 4. 개체 B의 개인키로 복호화 (B측)
KISA_Crypto_privateDecrypt(recovered, &lenPlain, ciphertext, 256, &privateKey);

// 5. 사용 완료 후 제로화
KISA_clear(&priKeyA);
KISA_Crypto_DH_freeParam(params);
```

### 3.2. DH 기반 키 합의 (Key Agreement)
"DH(Diffie-Hellman) 알고리즘을 이용하여 두 개체 간에 공통 비밀값을 합의한다. 각 개체는 자신의 개인키와 상대방의 공개키를 이용하여 동일한 공유키(Shared Secret)를 도출한다."

```c
// DH 키 합의 과정 요약 (|p|=2048-bit, |q|=256-bit)
params = KISA_Crypto_DH_newParam();
KISA_Crypto_DH_genParam(params, primePLen//8, primeQLen//8); // 1. 파라미터 생성

// 2. 개체 A, B 각각의 키쌍 생성
KISA_Crypto_DH_genKeyPair(&priKeyA, &pubKeyA, params);
KISA_Crypto_DH_genKeyPair(&priKeyB, &pubKeyB, params);

// 3. 공유키 계산 (A측: 자신의 개인키 A + 상대의 공개키 B)
KISA_Crypto_DH_computeSharedSecret(&secretAB, &priKeyA, &pubKeyB, params);

// 4. 공유키 계산 (B측: 자신의 개인키 B + 상대의 공개키 A)
KISA_Crypto_DH_computeSharedSecret(&secretBA, &priKeyB, &pubKeyA, params);

// 5. 사용 완료 후 메모리 해제 및 제로화
KISA_clear(&secretAB);
KISA_clear(&secretBA);
KISA_Crypto_DH_freeParam(params);
```

## 4. 구조도 및 시각 자료 (Visuals)
> **알림**: 본 항목은 개체 간의 데이터 교환 및 연산 흐름에 집중함.
> **논리 흐름**: [자동화 설정 요청] → [알고리즘(RSAES/DH) 파라미터 세팅] → [키 생성 및 교환/합의] → [공유된 SSP 확정] → **[임시 SSP 데이터 제로화]**

## 5. 해설 및 증빙 가이드 (Guide)
- **표준 부합성**: 자동화된 키 설정 방식은 반드시 부속서 D에서 허용하는 국제 표준(ISO/IEC 11770 등)의 메커니즘을 따라야 함.
- **제로화 필수**: 수도코드 예시에 포함된 것과 같이, 키 전송이나 합의 과정에서 발생한 모든 임시 비밀값(개인키, 중간 계산값 등)은 연산 종료 즉시 `KISA_clear()` 등의 함수를 통해 제로화되어야 함을 명세해야 함.
- **데이터 타입의 일치**: 암호모듈이 제공하는 실제 API의 형식과 데이터 타입(예: `unsigned char`, `BN` 등)에 맞춰 수도코드를 작성하여 실제 소스코드와의 정합성을 증빙할 것.