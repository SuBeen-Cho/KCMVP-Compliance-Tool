# CBC-005 padding-oracle 근거 게이트

GVI Part 2는 CBC padding-oracle 공격 가능성을 없애고 MAC을 추가해 공격자의 유효 암호문 생성을 방지할 것을 직접 요구한다. 반면 모든 실패가 하나의 일반 음수를 반환해야 한다는 특정 API 표현은 해당 span에 없다. 제출 안내서에는 `BLOCK_PADDING_ERROR` 예시도 있어 상수명 존재만을 위반으로 분류하는 규칙과 충돌한다.

판정에는 CBC 복호·패딩 검사 적용성, 외부에서 관찰할 수 있는 값·메시지·시간·상태 채널, 잘못된 패딩과 기타 실패 경로의 구별 가능성, MAC/AE 보호와 verify-before-release 순서, 함수 간 모든 return path가 필요하다. 이 증거 전까지 현 5건은 `unknown/abstain`으로 유지한다.
