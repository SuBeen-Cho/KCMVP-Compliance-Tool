# Hold 내부 proxy 위반 81건의 근거 매핑 우선순위

## 1. 평가 범위

commit `82c6e55`의 단계형 정책을 동결 L1 265건에 재생하여 `hold`로 분류되고 동일 모델 temperature-0 test–retest proxy가 `violation`으로 표시한 81건을 분석한다. proxy는 독립 인간 정답이 아니므로 본 결과를 recall, false negative 또는 실제 정확도 개선량으로 해석하지 않는다. 분석 목적은 공식 근거 매핑과 검출기 개선의 작업 순서를 정하는 데 한정한다.

private snapshot, sidecar 및 proxy GT는 메모리에서 occurrence 단위로 결합한다. 공개 artifact에는 occurrence ID, source ID/path, line, snippet 및 clone group ID를 기록하지 않고 SHA-256과 규칙·규칙군·격차별 집계만 기록한다. 재현 집계기는 `backend/experiments/hold_violation_priority.py`, 폐쇄형 결과는 `backend/mapping/hold_proxy_violation_priority_baseline81.json`에 둔다.

## 2. 기초 분포

81건은 20개 규칙, 4개 규칙군, 73개 고유 clone group에 걸쳐 있다. 동일 clone 반복만으로 특정 규칙의 우선순위가 과대평가되는 것을 피하기 위해 occurrence 수와 고유 clone group 수를 함께 보고한다.

| 규칙군 | occurrence | 고유 규칙 | 고유 clone group | 주요 격차 |
|---|---:|---:|---:|---|
| COM | 36 | 5 | 28 | detector scope 30, authority 6 |
| CBC | 18 | 4 | 18 | exact locator 10, authority 6, applicability 2 |
| CTR | 17 | 4 | 17 | exact locator 13, authority 3, applicability 1 |
| LEA | 10 | 7 | 10 | detector scope 5, authority 2, applicability 2, routing 1 |

격차별로는 detector scope 35건, exact locator 23건, authority 17건, applicability 5건, 이미 검증된 규칙의 routing/selector 보류 1건이다. 따라서 공식 근거 또는 적용성 계약 작업의 검토 대상 상한은 45/81건(55.56%)이고 검출기 변경이 필요한 부분은 35/81건(43.21%)이다. 나머지 1건은 근거 추가가 아니라 routing/selector 원인을 감사해야 한다. 이 상한은 자동 승격 또는 실현된 AI-ready 증가량이 아니다.

## 3. 공식 근거 작업 우선순위

공식 근거 작업만 놓고 보면 다음 순서가 가장 많은 occurrence를 먼저 다룬다.

| 순위 | 규칙 | 격차 | occurrence | 고유 clone group | 전체 81건 누적 잠재 비율 |
|---:|---|---|---:|---:|---:|
| 1 | CTR-001 | exact locator | 11 | 11 | 13.58% |
| 2 | CBC-001 | exact locator | 10 | 10 | 25.93% |
| 3 | CBC-005 | authority | 5 | 5 | 32.10% |
| 4 | CTR-LEA-001 | authority | 3 | 3 | 35.80% |
| 5 | COM-001 | authority | 3 | 1 | 39.51% |
| 6 | CBC-LEA-005 | applicability | 2 | 2 | 41.98% |
| 7 | COM-002 | authority | 2 | 2 | 44.44% |
| 8 | CTR-002 | exact locator | 2 | 2 | 46.91% |

CTR-001과 CBC-001 두 규칙만으로 21/81건(25.93%)이 우선 검토 범위에 들어간다. 두 규칙은 새로운 문서를 찾는 문제보다 이미 관련 공식 자료가 있는 상태에서 완전한 claim-to-unit entailment와 locator를 봉인하는 문제가 우선이다. 그 다음은 CBC-005, CTR-LEA-001, COM-001의 권위 출처 확보이며, applicability 규칙은 occurrence별 적용 대상임을 입증하는 계약 없이는 승격하지 않는다.

## 4. 근거 매핑으로 해결되지 않는 부분

전체 빈도 1·2위인 COM-004 16건과 COM-003 14건은 detector scope 격차이다. 이 30건을 근거 문서만 추가하여 AI-ready로 전환하면 검출기 의미와 근거 의미가 어긋난다. 별도의 AST/semantic detector 정제와 적용성 테스트가 선행되어야 한다. LEA detector-scope 5건도 동일하다.

또한 LEA-011 1건은 baseline audit에서 이미 verified인데도 hold로 남는다. 이는 evidence coverage 문제가 아니므로 selector cap, route 계약, applicability 또는 후보 상태 전달을 별도로 추적한다.

## 5. 승격 및 재평가 게이트

각 우선 규칙은 다음 조건을 모두 만족할 때만 `verified`로 승격한다.

1. 공식 원문의 정확 span, page/section locator, source hash 및 version을 봉인한다.
2. 규칙 주장 전체가 evidence unit에 의해 entail되는지 반례와 함께 독립 재검토한다.
3. occurrence 적용성 조건을 규칙 계약과 detector 출력에서 확인한다.
4. 변조·잘못된 locator·부분 entailment·상충 근거가 모두 fail-closed인지 회귀 테스트한다.
5. 승격 전후 동일 265건을 재생하여 `hold → ai_ready`, `hold → deterministic`, 잔여 hold를 구분한다.
6. 새 AI-ready에 실제 grounded 판정을 수행할 때 citation, locator, span 및 entailment verifier 통과율을 별도로 측정한다.

baseline 81건과 승격 후 결과는 같은 artifact로 덮어쓰지 않는다. mapping tree와 evidence audit 입력 hash가 다른 별도 결과로 보존하여 정책 변화에 따른 순증감을 계산한다.

## 6. 1차 승격 결과

독립 원문 감사를 통과한 `CBC-001`, `CTR-001`, `CTR-002` 세 규칙만 승격했다. 적용 범위는 LEA로 봉인했고 COM-003·004 등은 승격하지 않았다. 265건 historical-policy replay에서 AI-ready는 8→41건(3.02%→15.47%), hold는 227→194건(85.66%→73.21%)으로 변했다. binary-eligible AI-ready는 3→26건이었고, hold 내부 proxy 위반은 81→63건으로 18건 감소했다. 결정적 routing은 30건으로 같았다.

이 감소는 정확도 향상이 아니라 공식 근거를 갖춘 AI 검토 대상으로의 전환을 의미한다. 실제 LLM 판정과 citation-entailment verifier를 실행하지 않았으므로 최종 판정 성능은 별도로 측정해야 한다.
