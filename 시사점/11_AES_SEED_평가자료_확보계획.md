# AES·SEED 평가 자료 확보 및 일반화 실험 계획

## 1. 결론

AES·SEED 일반화 평가에는 하나의 구현체만 사용하지 않고, 서로 다른 소스 구조와 API를 갖는 C/C++ 구현체를 사용한다. 이를 위해 OpenSSL 3.5.7, Botan 3.12.0, Crypto++ 8.9.0, Mbed TLS 3.6.7을 고정 후보로 선정한다. 해당 소스는 Git 저장소에 직접 복제하지 않고, `backend/evaluation/candidates/sources.lock.json`에 기록한 태그·커밋·해시로 재현한다.

## 2. 후보 구현체

| 후보 | 언어 | 알고리즘 | 라이선스 | 실험상 역할 |
|---|---|---|---|---|
| OpenSSL 3.5.7 LTS | C | AES, SEED | Apache-2.0 | 주 C 평가 후보 |
| Botan 3.12.0 | C++ | AES, SEED | BSD-2-Clause | 독립 C++ 평가 후보 |
| Crypto++ 8.9.0 | C++ | AES, SEED | Boost-1.0 및 파일별 고지 | 보조 C++ 평가 후보 |
| Mbed TLS 3.6.7 | C | AES | Apache-2.0 OR GPL-2.0-or-later | 독립 AES C 평가 후보 |

OpenSSL 3.5는 2030년 4월까지 지원되는 LTS 계열이므로 장기 재현성 측면에서 주 후보로 선정한다. Botan과 Crypto++는 OpenSSL과 다른 C++ 구조를 제공하므로 특정 코딩 스타일에 대한 과적합을 완화하는 데 사용한다. Mbed TLS는 AES에 대한 두 번째 C 구현체로 사용한다.

## 3. 권위 있는 시험 벡터

- AES 정확성은 NIST FIPS 197의 예제와 NIST CAVP의 KAT, MCT, MMT 벡터로 확인한다.
- SEED 정확성은 RFC 4269 Appendix B의 키, 평문, 암호문 및 중간값으로 확인한다.
- 구현체가 백터를 통과했다는 사실은 알고리즘 구현의 기능적 정확성만을 의미하며, KCMVP 적합성이나 모듈 인증을 의미하지 않는다.

## 4. 평가 설계

### 4.1 자연 코드 평가

각 구현체의 AES·SEED 암호 커널, 키 스케줄, 모드 연결 코드를 변경 없이 분석한다. 다만 이들은 KCMVP 평가용으로 작성된 코드가 아니므로, 탐지 결과를 즉시 오탐으로 간주하지 않는다. 해당 결과는 전문가 라벨링 대상이며, 라벨링 전에는 정밀도·재현율을 계산하지 않는다.

### 4.2 통제된 변이 평가

알고리즘별 공통 규칙에 대해 정상 패턴과 단일 위반만 주입한 변이 패턴을 쌍으로 구성한다. 각 변이는 하나의 rule ID만 변경하며, 정답은 소스 주석이 아닌 sidecar JSON에 저장한다. 정답 주석은 파이프라인 입력에 포함하지 않는다.

### 4.3 구현체 홀드아웃

하나의 구현체를 규칙 작성과 threshold 선정에서 완전히 제외한 후 최종 평가에만 사용한다. 예를 들어 OpenSSL·Botan·Crypto++로 개발하고 Mbed TLS AES를 홀드아웃으로 사용한다. SEED는 세 구현체를 순환하는 leave-one-implementation-out 평가를 수행한다.

### 4.4 보고 지표

전체 수치만 제시하지 않고 알고리즘, 구현체, 언어, 규칙 가족별로 recall, precision, F1, false positives/KLOC를 분리해 보고한다. 각 셀의 분모와 95% bootstrap confidence interval을 함께 제시한다. 표본이 작은 셀은 확정적 결론에서 제외한다.

## 5. 라이선스 및 재현성 통제

1. 태그가 아닌 정확한 commit SHA를 저장한다.
2. 소스를 가져온 후 상위 LICENSE와 선택 파일의 SPDX/파일별 고지를 저장한다.
3. 원본과 실험용 파일의 SHA-256를 manifest에 기록한다.
4. 변이 파일은 upstream 원본, patch, sidecar GT로 분리한다.
5. KISA의 SEED ZIP은 공식 자료이지만 재배포 조건이 다운로드 페이지에서 명확히 확인되지 않으므로 현재 Git 저장소에 복제하지 않는다.

## 6. 주의할 해석

상기 외부 구현체는 AES·SEED 알고리즘을 구현한 신뢰할 수 있는 오픈소스 후보이지만, KCMVP 인증 요구사항을 준수하는 모듈이라고 가정할 수는 없다. 따라서 이를 사용한 실험은 “암호 구현체를 바꾸어도 탐지 규칙이 작동하는가”를 평가하며, 해당 라이브러리의 KCMVP 적합성을 선언하지 않는다.

## 7. 일차 출처

- NIST AES 예제 및 중간값: https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
- NIST CAVP 블록암호 벡터: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers
- RFC 4269 SEED 명세 및 벡터: https://www.rfc-editor.org/rfc/rfc4269.html
- OpenSSL 공식 배포: https://www.openssl-library.org/source/
- Botan 공식 배포: https://botan.randombit.net/
- Crypto++ 8.9 공식 배포: https://cryptopp.com/release890.html
- Mbed TLS 공식 저장소: https://github.com/Mbed-TLS/mbedtls
- KISA SEED 소스 안내: https://seed.kisa.or.kr/kisa/Board/190/detailView.do
