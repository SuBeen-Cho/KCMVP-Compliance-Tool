# SEED-001 비밀키 배열 길이

이 문서는 프로젝트 저자가 작성한 검사 해설이며 표준 원문이나 KCMVP 판정을 대체하지 않는다. KISA는 SEED를 KCMVP 검증대상으로 열거한다. Informational RFC 4269 §1.2는 SEED가 128비트 비밀키를 사용한다고 설명하며, 본 규칙은 이를 16바이트의 명시적 바이트 배열과 교차점검한다.

포인터·래퍼·매크로·런타임 길이·모호한 배열은 판정을 보류한다. 이 규칙은 라운드 구조를 검사하지 않으며 규칙 통과만으로 SEED 구현의 적합성이나 암호모듈 인증을 주장할 수 없다.

- KISA: <https://seed.kisa.or.kr/kisa/kcmvp/EgovVerification.do>
- RFC 4269: <https://www.rfc-editor.org/rfc/rfc4269.html>
- 확인일: 2026-08-11
