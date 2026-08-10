# AES-002 허용 키 길이 명시값

이 문서는 프로젝트 저자가 작성한 검사 해설이며 NIST 표준 원문이나 KCMVP 판정을 대체하지 않는다. FIPS PUB 197-upd1 §5 Table 3은 AES-128, AES-192, AES-256을 규정한다. 본 규칙은 단위가 비트 또는 바이트로 명시되고 코드가 명시적으로 성공 처리하는 키 길이가 128, 192, 256비트와 모순될 때만 보고한다.

KISA AES 검증시스템과 시험 벡터는 2026년 8월 11일 확인 당시 `TBD`이다. 이 정적 검사는 NIST 표준의 명시값 교차점검이며 KCMVP 공식 AES 시험을 대체하지 않는다.

- NIST: <https://doi.org/10.6028/NIST.FIPS.197-upd1>
- KISA: <https://seed.kisa.or.kr/kisa/kcmvp/EgovVerification.do>
