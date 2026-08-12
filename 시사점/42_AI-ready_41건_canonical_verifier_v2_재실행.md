# AI-ready 41건 canonical verifier v2 재실행

## 목적과 범위

동결 historical 후보 265건 중 현재 정책이 `AI-ready`로 선택하는 동일 41건을 `gemini-2.5-flash-lite`로 다시 판정한다. no-RAG와 grounded 조건은 evidence block만 다르고 나머지 프롬프트와 생성 설정은 동일하다. 독립 인간 GT가 없으므로 정확도·precision·recall·F1을 주장하지 않는다. 측정 대상은 raw 판정 coverage, citation-bound verifier 통과율, 비용 및 replay 일치성이다.

## 실행 무결성

새 mode-0600 private ledger와 배타적 run lock을 사용했다. 실행 전 41개 후보의 원 payload·envelope 결합 hash, 82개 `(index, condition)` 슬롯, 공통 prompt core를 봉인했다. 완료된 ledger에는 82개 고유 슬롯이 정확히 한 번씩 존재하며 물리 API 요청 82건, retry 0건, duplicate 0건이다. raw decision과 canonical decision, citation ID, 공식 span, verifier pass·reason·final을 private ledger에 보존했다. 공개 artifact에는 집계와 hash만 포함한다.

이 통제는 **완료된 실행의 중복 부재**를 입증한다. 공급자 API가 idempotency key를 제공하지 않으므로 프로세스가 응답 수신과 ledger 기록 사이에 중단된 경우까지 전역 exact-once를 보장하지 않는다. 불완전 ledger는 resume하지 않고 폐기 대상으로 분리한다.

## 결과

| 조건 | raw 판정 | verifier 최종 판정 | 입력/출력 token | 평균 지연 |
|---|---|---|---:|---:|
| no-RAG | abstain 39, not-applicable 2 | abstain 41 | 9,863 / 3,289 | 1,185.39 ms |
| grounded | violation 2, non-violation 32, not-applicable 2, abstain 5 | violation 2, non-violation 12, abstain 27 | 31,462 / 5,785 | 1,303.17 ms |

grounded verifier는 14/41건(34.15%)을 최종 통과시켰다. raw non-abstain 36건을 분모로 하면 14/36건(38.89%)이다. 실패 원인은 `entailment_unconfirmed` 16건, `citation_missing` 10건, `citation_unknown` 1건이다. 수정 전 문자열 기반 applicability 결함이 포함된 4/41 수치는 폐기하며, 같은 raw 응답 분포에서 canonical verifier를 적용한 현재 결과는 14/41이다.

전체 82건의 token은 입력 41,325, 출력 9,074이며 실험 스냅샷 단가 기준 추정 비용은 USD 0.0077621이다. 청구서 금액이 아니다. raw label 전이는 abstain→non-violation 30건, abstain→violation 2건, abstain→not-applicable 2건, abstain→abstain 5건, not-applicable→non-violation 2건이다.

## API 없는 replay

private ledger의 41개 grounded canonical decision을 현재 verifier로 재생했으며 API 호출은 0건이다. 각 index의 pass 여부, reason, final label을 저장값과 exact 비교했고 모두 일치했다. replay 결과도 14건 통과, 실패 사유 16·10·1건으로 실제 실행 집계와 동일하다. replay는 snapshot·mapping·공식 index·runner·verifier·private ledger·run instance·experiment spec을 SHA-256으로 결합한다.

## 해석

공식 근거는 raw abstention을 39건에서 5건으로 낮추지만, 엄격한 verifier까지 통과한 자동 판정은 14건이다. 따라서 RAG의 효용은 응답 생성률만으로 평가하면 안 되며 citation과 entailment를 통과한 selective coverage로 평가해야 한다. 다음 개선은 16건의 entailment 실패와 10건의 citation 누락을 규칙군별로 분석하되, verifier 문턱을 낮추지 않고 evidence bundle과 출력 계약을 보완하는 것이다.
