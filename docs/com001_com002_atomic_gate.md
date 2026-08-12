# COM-001/002 atomic claim 분리

COM-001의 직접 규범은 사용이 끝난 SSP 제로화와 API 반환 전 내부 데이터 제로화이다. 특정 함수명만 허용한다거나 프로젝트에서 그 문자열이 없으면 제로화 실패라는 주장은 별도 program-fact이다.

COM-002에서 `lea_set_key` 원문 시그니처는 `void`이며, 음수 에러 반환은 별도 LEA 모드 API에 해당한다. 현 규칙처럼 `void wrapper + lea_set_key` 패턴으로 반환값 검사·외부 오류 노출·오라클 방지를 동시에 판정할 수 없다. 두 규칙은 CFG/dataflow·소유권·API 계약 증거 전까지 fail closed로 유지한다.
