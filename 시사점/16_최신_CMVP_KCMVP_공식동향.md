# 최신 CMVP·KCMVP 공식 동향

## 조사 원칙

2026년 8월 11일을 기준으로 NIST 및 KISA의 공식 1차 출처만 확인한다. 공개 참고 구현, 시험 벡터 통과 및 본 도구의 판정은 암호모듈 인증을 의미하지 않으며 시험기관과 검증기관의 판단을 대체하지 않는다.

## CMVP 및 FIPS 140-3

- NIST CMVP는 2020년 9월 22일부터 FIPS 140-3 제출을 수용하였다. FIPS 140-2 신규 인증서 제출은 2021년 9월 22일부터 기존 시험기관 계약에 따른 제한적 예외만 허용하였으며, 2022년 4월 1일부터 신규 인증서를 위한 제출을 더 이상 수용하지 않고 검증 만료일을 변경하지 않는 제한된 보고만 수용하였다.
- FIPS 140-2 활성 모듈은 2026년 9월 21일까지 신규 시스템에서 사용할 수 있으며, 2026년 9월 22일부터 Historical List로 이동한다. Historical 상태를 revoked와 동일시하지 않는다.
- 최신 FIPS 140-3 Implementation Guidance는 2026년 4월 9일 판이다. RAG 코퍼스가 이를 사용한다고 주장하려면 문서 버전·해시·취득일을 고정해야 한다.
- CMVP 승인 보안기능의 기준인 SP 800-140C Rev.2에는 AES가 승인 블록암호로 포함되지만 SEED와 ARIA는 포함되지 않는다. CMVP와 KCMVP 알고리즘 범위를 동일시하지 않는다.
- CAVP 알고리즘 검증은 모듈 검증의 선행요건이지만, 알고리즘 검증만으로 FIPS 140 모듈 검증을 충족하지 않는다.

공식 출처:

- <https://csrc.nist.gov/Projects/cryptographic-module-validation-program>
- <https://csrc.nist.gov/Projects/FIPS-140-3-Transition-Effort>
- <https://csrc.nist.gov/projects/cryptographic-module-validation-program/fips-140-3-ig-announcements>
- <https://csrc.nist.gov/projects/cryptographic-module-validation-program/sp-800-140-series-supplemental-information/sp800-140c>
- <https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program>

## KCMVP 알고리즘 및 제출물

- KISA의 현재 검증대상 블록암호에는 ARIA, SEED, LEA, HIGHT 및 AES가 포함된다.
- AES의 검증시스템 및 테스트 벡터는 현재 `TBD`이다. AES를 범위 밖이라고 쓰지 않되, KCMVP 공식 AES 구현적합성 검증이 완비되었다고 주장하지 않는다.
- AES 평가에는 NIST FIPS 197 및 CAVP 벡터를 사용하고 이를 KCMVP 공식 벡터 평가와 구분한다.
- 현재 저장소의 SEED 및 ARIA 기준 벡터는 RFC 4269와 RFC 5794에서 취득한 교차검증 자료이다. 후속 평가에서는 KISA 공식 벡터를 확보·해시 고정하여 우선 검증하고, RFC 벡터 결과와 교차검증해야 한다.
- KISA는 2025년 9월 17일 암호모듈 제출물 작성 안내서 개정본을 게시하였다. 문서 검사와 RAG 코퍼스는 구판만 사용하지 않고 해당 판의 포함 여부와 해시를 기록해야 한다.
- KISA 절차는 소스코드, 기본·상세설계서, 형상관리문서, 시험서 및 알고리즘 구현적합성 결과를 제출물로 열거한다. 이는 코드·문서·추적성 검사 문제를 뒷받침하지만 공식 소요기간 통계를 제공하지 않으므로 약 1년 반이라는 기간을 일반 사실로 단정하지 않는다.

공식 출처:

- <https://seed.kisa.or.kr/kisa/kcmvp/EgovVerification.do>
- <https://seed.kisa.or.kr/kisa/Board/203/detailView.do>
- <https://seed.kisa.or.kr/kisa/kcmvp/EgovProcedure.do>

## 표준 및 벡터 경계

- AES는 2023년 5월 9일 갱신된 NIST FIPS 197을 기준으로 하며 기술적 알고리즘 변경은 없다.
- NIST CAVP 벡터의 로컬 통과는 벡터 일치를 의미하며 CAVP validation을 대체하지 않는다.
- RFC 4269와 RFC 5794는 각각 SEED와 ARIA의 재현 가능한 교차검증 벡터를 제공하지만 Informational RFC이다. KCMVP 규범의 주된 근거는 KISA가 열거한 KS·TTA·ISO 문서와 KISA 공식 자료로 둔다.
- KISA 공개 소스는 참고용 예제이며 안전성·정확성·적합성·완전성을 보증하는 검증필 구현체로 표현하지 않는다.

공식 출처:

- <https://csrc.nist.gov/pubs/fips/197/final>
- <https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/Block-Ciphers>
- <https://www.rfc-editor.org/info/rfc4269/>
- <https://www.rfc-editor.org/info/rfc5794/>

## 프로젝트 반영 우선순위

1. 규칙 메타데이터에 관할 체계, 규범 출처, 문서 버전·날짜·해시, 알고리즘, 운용 모드 및 validation status를 분리한다.
2. AES에는 `KCMVP 대상, 공식 KCMVP 벡터 TBD` 상태를 기록한다.
3. LEA·AES·SEED·ARIA를 알고리즘별로 평가하고 macro 지표와 pooled micro 지표를 함께 보고한다.
4. KISA AES 상태와 NIST IG 판 변경을 감지하는 최신성 점검을 추가한다.
5. 논문에서는 도구를 사전 점검 및 의사결정 지원으로 한정하고 인증 자동화 또는 적합성 보증으로 표현하지 않는다.
