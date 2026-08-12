# AI-ready 41건 grounded v1–v2 안정성 및 verifier 검증

## 평가 계약

동일한 AI-ready 41건의 정렬된 candidate identity를 결합하여 grounded v1과 v2를 비교한다. v2는 v1의 응답을 재사용하지 않고 동일 모델·temperature 0·프롬프트로 다시 실행한 결과다. 독립 GT가 없으므로 정확도·recall·F1 또는 RAG 주효과를 산출하지 않는다.

v1 ledger는 실험 시 중복 물리 요청 11건을 포함하므로 condition·index별 첫 완결 record를 선택하여 41건을 복원한다. v2는 41건이 한 번씩 기록되었다. v1 verifier의 final 의미는 v2의 보강된 entailment 의미론과 다르므로 v2 final과의 비교는 `invalid`로 둔다.

## 결과

- raw label 완전 일치: 41/41(100%)
- raw 분포: abstain 5, non-violation 32, not-applicable 2, violation 2
- v2 verifier 통과: 14/41(34.15%)
- v2 verifier 사유: citation-bound verified 14, entailment-unconfirmed 16, citation-missing 10, citation-unknown 1
- v2 final: non-violation 12, violation 2, abstain 27
- v2 final abstention: 27/41(65.85%)

raw label은 완전히 재현되었지만 v2 verifier를 통과한 판정은 14건이다. 따라서 모델 응답 재현성과 공식 근거에 구속된 final coverage는 구분해야 한다. 특히 entailment-unconfirmed 16건이 가장 큰 실패 원인이므로, 다음 개선은 라벨을 조정하기보다 claim–span entailment 프롬프트와 evidence bundle 품질을 개선해야 한다.

## 자원 비교

v1과 v2는 각각 41회 호출, 입력 31,462 token, 출력 5,785 token, 추정비용 USD 0.0054602로 동일하다. 총 순차 지연시간은 v1 51,392.846ms, v2 53,430.091ms이며 v2가 2,037.245ms 길다. 평균은 1,253.484ms와 1,303.173ms로 49.689ms 차이다. 단일 순차 실행이므로 이 지연 차이를 유의미한 성능 변화로 해석하지 않는다.

no-RAG 41건과 grounded 41건을 합친 분석 분모는 각 버전 82건이며, 두 버전 모두 입력 41,325 token, 출력 9,074 token, 추정비용 USD 0.0077621이다. v1의 물리 요청에는 중복 11건이 있었으나 분석 token·비용 분모에서 제외했다. v2의 중복 요청은 0건이다.

폐쇄형 집계 artifact는 `backend/evaluation/public_grounded_ai_ready41_v1_v2_compare.json`, 재현 하네스는 `backend/experiments/grounded_v1_v2_compare.py`에 둔다. 공개 산출물에 candidate ID·원문·응답·경로·API key를 포함하지 않는다.
