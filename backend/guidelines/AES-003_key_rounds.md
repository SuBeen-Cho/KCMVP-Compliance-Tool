# AES-003 키 길이별 라운드 수 명시값

이 문서는 프로젝트 저자가 작성한 검사 해설이며 NIST 표준 원문이나 KCMVP 판정을 대체하지 않는다. FIPS PUB 197-upd1 §5 Table 3은 128, 192, 256비트 키에 각각 10, 12, 14라운드를 대응시킨다. 본 규칙은 이 대응이 코드에 직접 드러나면서 표준값과 모순되는 경우만 보고한다.

래퍼·간접 계산·최적화 구현에는 판정을 내리지 않는다. 또한 KISA AES 검증시스템과 시험 벡터가 2026년 8월 11일 현재 `TBD`이므로 규칙 통과를 KCMVP 구현적합성으로 해석하지 않는다.

- NIST: <https://doi.org/10.6028/NIST.FIPS.197-upd1>
- KISA: <https://seed.kisa.or.kr/kisa/kcmvp/EgovVerification.do>
