# AES-001 블록 크기 명시값

이 문서는 프로젝트 저자가 작성한 검사 해설이며 NIST 표준 원문이나 KCMVP 판정을 대체하지 않는다. FIPS PUB 197-upd1 §2.1은 AES 블록을 128비트로 정의하며 §5 Table 3도 이를 명시한다. 본 규칙은 단위가 명시된 코드 값이 이 규정과 직접 모순될 때만 보고하며 간접·최적화 구현은 판정하지 않는다.

KISA는 AES를 검증대상 목록에 포함하지만 2026년 8월 11일 확인 당시 AES 검증시스템과 시험 벡터를 `TBD`로 표시한다. 따라서 본 규칙 통과는 KCMVP AES 구현적합성 검증을 의미하지 않는다.

- NIST: <https://doi.org/10.6028/NIST.FIPS.197-upd1>
- KISA: <https://seed.kisa.or.kr/kisa/kcmvp/EgovVerification.do>
