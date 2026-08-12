# L1.5 forced-in routing 보정

기존 selector는 민감 이름 후보를 `forced_in`에 모았지만 결과 구성에 사용하지 않아 rule당 cap 이상의 후보가 조용히 탈락했다. 보정 후에는 정상 eligibility와 deterministic bypass 검사를 통과한 forced-in 후보를 결과 앞에 배치하고, 버킷에서 제외해 중복을 막는다. 이는 L3 라우팅 우선순위일 뿐 semantic TP 판정은 아니다.

회귀 테스트는 동일 rule의 민감 이름 12건이 cap에 의해 손실되지 않음, FP 이름 제외, eligibility 불충족 후보 차단, deterministic verified bypass를 검증한다.
