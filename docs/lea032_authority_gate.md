# LEA-032 research-vs-normative 게이트

현 규칙의 “AES와 달리 마지막 라운드도 동일 구조” 비교는 LEA 설계 논문에 기대고 있으며, 논문은 `research_reference`이지 KCMVP normative source가 아니다. LEA 규격서의 고정 라운드 반복은 관련 알고리즘 사실을 지지하지만 AES 비교 문구와 현 detector의 범위를 직접 함의하지 않는다.

현 10 occurrence에는 헤더 선언, wrapper 호출, CBC/CTR 호출부, 라운드 loop가 섞여 있다. 이들은 마지막 라운드에 별도 변형이 있는지를 증명하지 않는다. authenticated operation-graph에서 모든 라운드 호출의 동일성을 증명하기 전까지 production authorization 0을 유지한다.
