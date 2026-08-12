# COM-004 공식 근거·program-fact 게이트

KCMVP GVI Part 2의 공식 원문은 암호 키·논스·솔트 등에 난수가 쓰이며, 난수를 생성할 때 검증대상 난수발생기를 사용해야 함을 지지한다. 반면 현재 COM-004가 나열한 모든 C 함수의 전역 금지, 특정 OS API의 KCMVP 승인, 함수명의 단순 출현이 암호 목적 사용을 증명한다는 주장은 해당 span이 직접 함의하지 않는다.

따라서 현재 16건은 근거 매핑만으로 승격하지 않는다. 신뢰할 수 있는 전처리·빌드 provenance, 취약 난수 반환값에서 키·IV·nonce 등의 검증된 sink로 이어지는 reachable def-use, alias·interprocedural 해소, KAT·test vector·benchmark·logging·비암호 사용 제외가 모두 필요하다. 그 전까지 판정은 `unknown/abstain`, production authorization은 0으로 유지한다.
