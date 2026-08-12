# COM-003 하드코딩 규칙 과장 차단

공식 원문은 무결성 검증키가 소스에 하드코딩되는 경우 인코딩·암호화·분산 저장 등의 보호를 요구하며, KAT 테스트 벡터의 하드코딩을 명시적으로 허용한다. 따라서 8개 이상의 16진 리터럴 initializer를 모두 비밀키로 분류하거나, 모든 키의 KMS/HSM 외부 주입을 일반 의무로 단정하면 근거 범위를 넘는다.

현 scanner는 후보 생성용으로만 유지한다. production 판정에는 authenticated preprocessing/build context, canonical object identity, 실제 비밀키·IV·CSP 사용 경로, KAT·S-box·delta·공개 상수 제외, 마스킹·암호화·분산 보호 상태, alias·interprocedural 흐름이 모두 필요하다. 그 전까지 14건은 `unknown/abstain`으로 유지한다.
