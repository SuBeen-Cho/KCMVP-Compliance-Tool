# current 45 단계 분포·근거 결합·API 예산 평가

## 목적과 범위

동결된 265건 snapshot에 현재 mapping과 router를 재적용해, LEA 라운드 근거 매핑 후의
실제 단계 분포를 API 호출 없이 재다. 이 평가는 routing coverage와 입력 계약
완전성을 측정하며, 탐지 정확도나 AI 의미 판정 성능을 주장하지 않는다.

## 결과

| 구분 | 건수 | 265건 대비 |
|---|---:|---:|
| deterministic | 30 | 11.32% |
| AI-ready | 45 | 16.98% |
| hold | 190 | 71.70% |

기존 AI-ready 41건보다 4건이 늘었다. 신규 occurrence는 `LEA-027`·`LEA-028`·
`LEA-029`·`LEA-030` 각 1건이며 `LEA-031`은 0건이다. 이 변화는 각 라운드
출력식의 공식 evidence-unit 결합이 통과한 routing coverage 변화이지 정확도 향상이
아니다.

45건 전체가 verified rule binding, 필수 evidence-unit 집합, source SHA-256, 각 span
SHA-256를 다시 확인했다. atomic claim registry도 45/45건에 있다. 그러나 인증된
sealed program fact는 0/45건이고 production semantic authorization도 0건이다. 따라서
신규 4건을 포함한 모든 건은 계속 AI review-only이며 자동 판정으로 승격하지
않는다.

## 호출·비용 계획치

각 occurrence를 grounded 1회씩 판정하면 최대 호출 수는 41→45회, paired
RAG/no-RAG를 모두 수행하면 90회다. 기존 atomic-v3 41건의 실측치를 45/41로
선형 확장한 계획치는 입력 52,401 token, 출력 9,577 token, USD 0.009070573이다.
이는 단일 과거 실험의 관측 평균을 이용한 budget projection이며, 토큰·요금의 보증된
상한이나 청구서 금액이 아니다.

## 결론과 다음 게이트

공식 근거 결합 coverage는 45건까지 늘었지만 추가 유료 AI 호출로 정확도가
자동으로 늘어난다고 볼 근거는 없다. 먼저 신규 LEA 라운드 4건에 대해
전처리·callsite·operation graph·출력 영향을 하나의 authenticated program-fact chain으로
결합해야 한다. 이 게이트를 통과하기 전에는 45건 API 재실행보다 API-free
semantic shadow replay를 우선한다.

공개 집계는 `backend/evaluation/public_current45_stage_and_evidence.json`, 재현 하네스는
`backend/experiments/current45_stage_eval.py`에 두었다. 공개 산출물에 candidate ID, 경로,
snippet, prompt, 소스 원문은 남기지 않았다.
