# 공식 Evidence 검색평가 하네스 초안

## 1. 목적

본 평가는 LLM 판정 정확도와 검색 자체의 품질을 분리한다. 동일한 closed-schema GT에서 `relevant`, `irrelevant`, `conflicting`, `oracle` 조건을 생성하며, 유료 API나 외부 네트워크를 사용하지 않는다. 따라서 결과는 환경에서 결정적으로 재현할 수 있다.

semantic GT는 2026-08-12 현재 사람이 질의와 원문을 검토한 CCM-003, GCM-002, LEA-048 세 규칙만 포함한다. 이는 `human_reviewed_semantic_seed`이며 전체 규칙에 대한 의미론적 검색 성능 추정치는 아니다. 별도 mapping-integrity layer는 실행 시점의 감사 registry에서 verified 규칙 전체를 자동 선택하므로 원문 매핑이 확대되어도 누락되지 않는다.

## 2. 평가 설계

- `Recall@k`는 상위 k개 단위에서 GT 근거 회수율을 측정한다.
- `MRR`은 첫 관련 근거의 순위를 측정한다.
- `bundle recall`은 순위 절단과 무관하게 감사된 근거 묶음을 모두 보존했는지 측정한다.
- `wrong-authority rate`는 허용된 source ID 밖의 단위 비율을 측정한다.
- citation verifier 정확도는 relevant/oracle을 수용하고 irrelevant/conflicting에서 abstain하는지 측정한다.
- latency는 질의당 20회 반복하여 median과 p95 샘플을 기록한다.

## 3. 최초 측정 결과

`python3 -m experiments.evidence_retrieval_eval --repeats 20`을 실행한 결과는 다음과 같다.

| 조건 | Recall@3 | MRR | Bundle recall | Wrong-authority | Citation 수용 | Abstain |
|---|---:|---:|---:|---:|---:|---:|
| relevant | 0.7778 | 1.0000 | 1.0000 | 0.0000 | 1.0000 | 0.0000 |
| irrelevant | 0.0000 | 0.0000 | 0.0000 | 1.0000 | 0.0000 | 1.0000 |
| conflicting | 0.7778 | 1.0000 | 1.0000 | 0.3111 | 0.0000 | 1.0000 |
| oracle | 0.7778 | 1.0000 | 1.0000 | 0.0000 | 1.0000 | 0.0000 |

질의별 median의 중앙값은 0.472 ms이다. LEA-048은 9개의 원문 단위가 하나의 분할 불가능한 bundle을 이루므로 Recall@3은 1/3이지만 bundle recall은 1이다. 이 차이는 `top_k`로 검증된 bundle을 잘라서는 안 된다는 현재 설계를 지지한다.

## 4. 발견 및 교정된 결함

1. 무관한 공식 근거 수용: 최초 하네스는 다른 공식 source 단위를 3/3 수용하는 결함을 발견했다. verifier가 cited unit을 감사된 `rule_id → source/unit IDs` 매핑과 재결합하도록 교정했으며, 재평가에서 irrelevant acceptance=0을 확인했다.
2. LEA 버전 메타데이터 차단: LEA-048의 `effective_date=null`이 정상 근거를 차단했다. 날짜 미상 local artifact는 감사된 source SHA-256가 일치하는 경우에만 수용하도록 정책을 교정했으며, relevant/oracle acceptance=1을 확인했다.

## 5. 전체 verified mapping integrity

초기 자동 승격은 verified 65개였으나, 독립 entailment 공격감사에서 원문보다 구체적이거나 의무 범위를 넓힌 24개를 `review_required`로 롤백했다. 이후 CMAC-004와 LEA 규칙 8개를 exact normative units로 재검증하여 최종 결과는 166개 중 verified 50개, unverified 116개, verified coverage 30.12%이다. verified 규칙의 returned mapped-unit exact-set rate, source-binding rate, mean bundle recall은 모두 1.0이다. unverified 규칙의 fail-closed rate도 1.0이고 누출은 0건이다.

이 층의 exact-set rate는 registry와 runtime retrieval의 동등성을 의미할 뿐, 질의에 대한 문서 검색 적합성이나 근거의 규범적 타당성을 의미하지 않는다. semantic 주장은 상기 3-query seed로 제한한다.

## 6. 판정과 후속 검증

현재 검색은 임의 유사도 순위화가 아니라 규칙별로 감사된 bundle을 반환한다. 따라서 MRR=1을 검색 모델의 일반적 우수성으로 해석해서는 안 된다. 매핑이 검증된 3개 규칙에서만 bundle recall=1을 확인한 결과이다.

상기 보정 후 irrelevant acceptance=0, conflicting acceptance=0, relevant/oracle acceptance=1 게이트를 모두 통과했다. 다음으로 원문 매핑 규칙을 확대하고, query GT를 개발/보정/고정 평가로 분리해야 한다.
