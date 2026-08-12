# 265건 historical stage boundary 성능평가

## 1. 평가 범위

본 평가는 commit `84fa2bc` 시점에 생성된 동결 L1 후보 265건을 현재 `run_l2_rag_context`와 L3 selector 경계에 재생한 `historical_policy_replay_not_current_end_to_end`이다. 현재 HEAD에서 L1부터 새로 생성한 end-to-end 정확도 평가가 아니다.

실행 과정에서 외부 API는 호출하지 않았다. 공개 artifact는 후보 ID, rule ID별 결과, 소스 원문, 키를 포함하지 않고 집계만 포함한다.

## 2. 결과

265건의 경계 분포는 다음과 같다.

- deterministic: 30건(11.32%)
- AI-ready: 8건(3.02%)
- hold: 227건(85.66%)

실제 API 호출을 수행하지 않은 router projection에서는 265건 중 8건만 AI-ready이다. 그러나 eligible-all-call comparator를 실행하지 않았으므로 **실측 LLM 호출 절감률은 산출하지 않는다**. 모든 L1 후보를 한 번씩 호출한다는 단순 상한과 비교하면 AI-ready 비율은 3.02%, 호출 감소 상한은 96.98%이다.

공식 evidence bundle이 있는 AI-ready 후보는 8건이다. 다만 LLM 판정의 citation·span·applicability·entailment 검증을 수행하지 않았으므로 verifier full-pass coverage는 미측정이다. 단순히 bundle이 존재한다는 이유로 verified coverage로 계산하지 않는다.

## 3. 지연시간

20회 warm 반복을 수행했다.

- cold batch: 약 158 ms
- cold candidate 당: 약 0.60 ms
- warm batch 평균/중앙값: 약 31.54 ms / 24.45 ms
- warm batch p95: 약 70.23 ms
- warm candidate 당 평균: 약 0.12 ms

이 수치는 로컬 프로세스의 routing·검색·selector 경계 시간이며 네트워크 LLM latency를 포함하지 않는다.

## 4. 해석

현재 정책은 AI 호출 후보를 크게 줄이는 반면, 227건을 fail-closed hold로 보낸다. 따라서 지금 결과는 “효율적으로 정확하다”는 결론이 아니라, “근거가 검증된 소수만 AI 진입을 허용한다”는 안전성 결과이다. 실용 성능 향상의 핵심은 hold 227건에 대해 정확한 공식 evidence mapping을 늘리는 것이다.

다음 평가에서는 현재 HEAD L1 코퍼스를 별도로 동결하고, GT가 있는 동일 eligible 집합에서 no-RAG, eligible-all-call, need-gated RAG를 교차 비교해야 한다. 이때에만 precision·recall·F1, verifier full-pass coverage, 실측 API 호출 절감률을 보고할 수 있다.
