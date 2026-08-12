# COM-004 현재 16건 program-fact 가용성

clean snapshot `9314f4df...` 내 COM-004 후보는 16건이며 소스 전체는 16/16 확보됐다. 단순 lexical 관찰에서 seed/time/clock 계열은 15건, `rand()` 직접 출력은 14건이다. 이 수치는 dataflow 증거가 아니므로 정확도 분자로 사용하지 않았다.

신뢰할 수 있는 전처리, 빌드 manifest, 취약 난수 반환값에서 보안 민감 sink로의 def-use는 모두 0/16이다. candidate payload에 위조한 `verified_build_manifest` 또는 `sensitive_sink`를 추가해도 이 지표는 증가하지 않도록 공격 테스를 추가했다. 결과는 16/16 `unknown/abstain`, production authorization 0, API 호출 0이다.

다음 게이트는 합성 fixture에서 authenticated preprocessing binding과 Clang symbol identity를 결합해 직선형 동일 함수 내 direct def-use만 구조적으로 확인하는 것이다. alias, 분기, 매크로, 함수 간 호출, KAT/test/benchmark 문맥은 각각 증명되기 전까지 unknown으로 남긴다.
