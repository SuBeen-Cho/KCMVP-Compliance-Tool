# COM-004 authenticated direct-store shadow

최소 구조 실험은 authenticated preprocessing binding과 사전 감사된 sensitive-sink 이름이 모두 있을 때, 동일 함수의 단일 직접 배열 대입 형태만 관찰한다. 이것은 Clang SSA/dataflow 증명이 아니므로 결과 state는 항상 `unknown`, semantic/production authorization은 항상 false이다.

분기, 매크로, alias, 간접 대입, `memcpy`, 다중 호출, 비암호·미사용 호출은 fail closed로 처리한다. 후속 승격에는 Clang AST symbol identity, CFG reachability, SSA def-use, alias 해소, KAT/test 문맥 분류, 공식 근거와 결합된 sink registry가 필요하다.
