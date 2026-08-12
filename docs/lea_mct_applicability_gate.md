# LEA MCT applicability 게이트

CBC-LEA-005와 LEA-057은 LEA 검증시스템의 MCT 산출물에 적용되는 키 갱신 규칙이다. 일반 production CBC 암호화가 MCT 수식을 구현해야 하는 것은 아니다. 함수명의 `mct`, fallback regex, key·ciphertext XOR 문자열만으로 검증 harness 적용성을 확정하지 않는다.

현 snapshot에서 CBC-LEA-005는 6건, LEA-057은 2건이며 그 2건은 동일 occurrence와 중복된다. 독립 표본 8건으로 계수하지 않아야 한다. authenticated validation-artifact manifest, LEA/CBC 모드, 키 길이 variant, MCT 상태, 암호문 dataflow가 모두 없으므로 applicability 0, production authorization 0으로 유지한다.
