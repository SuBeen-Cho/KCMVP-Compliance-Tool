# LEA closed operation graph 동등성 합성평가

## 목적

LEA round word의 폐쇄형 규범식을 canonical operation graph로 표현했을 때 정확한 식과
허용된 교환법칙 변형은 보존하고, 연산 순서·회전량 변조와 무관한 복사를 분리하는지 API
호출 없이 평가했다. 규범 fixture는
`ROL32_9((x0 XOR rk0) ADD32 (x1 XOR rk1))` 한 식으로 제한했다.

## 계약과 결과

canonicalizer는 32-bit `xor`, modular `add`, `rol` 및 명시적 input만 허용한다. `xor`와
`add`의 두 피연산자 순서만 canonical sorting하며, 결합법칙 재작성·상수 접기·연산 재배치는
허용하지 않는다. 스키마 밖 연산, 폭, arity, rotate 값 및 추가 필드는 fail-closed된다.

| fixture | 기대 | 결과 |
|---|---:|---:|
| exact | 동등 | 동등 |
| XOR·ADD 피연산자 교환 | 동등 | 동등 |
| rotate와 add 순서 변경 | 비동등 | 비동등 |
| rotate 9를 8로 변경 | 비동등 | 비동등 |
| 입력값 단순 복사 | 비동등 | 비동등 |

- TP 2, TN 3, FP 0, FN 0
- 합성 accuracy 100%, positive recall 100%, negative recall 100%
- 비교 10,000회씩 5표본: 평균 42.373 μs, 중앙값 40.950 μs, 최대 48.926 μs
- API 호출: 0
- 의미론적 자동 승인: 0

## 해석 경계

100%는 다섯 개의 설계된 합성 fixture에 대한 기능·mutation 결과이며 실제 구현체 정확도나
일반화 성능이 아니다. 특히 C 정수 승격, overflow 의미, alias, load/store, round loop,
상수·키 인덱스, 호출 도달성 및 출력 영향은 이 평가가 증명하지 않는다. operation graph가
전처리·AST provenance와 결합되고 독립 공격감사를 통과하기 전까지 production
`semantic_authorization`은 0으로 유지한다.

Clang 연결 구현은 `out/in/rk` 모두에 `restrict`가 있을 때만 비alias 조건을 구조적으로
수용하고, 동일 toolchain에서 `sizeof(uint32_t)==4`와 `CHAR_BIT==8`을 확인한다. AST/ABI
검사 compiler binary hash도 preprocessing capture의 compiler와 일치해야 한다. 이는
호출자가 C `restrict` 계약을 지킨다는 조건부 증명이며 모든 call site를 검증한 결과는
아니다. 현재 공식 evidence-unit 결합이 비어 있으므로 그래프가 일치해도 state는
`unknown`, `evidence_binding_complete=false`, semantic authorization은 0이다.

공개 집계는 `backend/evaluation/public_lea_operation_graph_equivalence_synthetic.json`,
재현 코드는 `backend/experiments/lea_operation_graph_equivalence_benchmark.py`에 기록했다.
