# AI-ready 41건 no-evidence Gemini comparator

## 1. 실험 계약

53개 verified mapping 승격 후 동결 265건을 현재 정책으로 재생하여 AI-ready로 선택된 41건의 순서와 candidate hash를 고정한다. `backend/experiments/no_evidence_41_eval.py`는 운영 단계 계약을 우회하지 않고 실험 모듈에서만 Gemini를 직접 호출한다. grounded condition의 출력은 읽지 않는다.

프롬프트 core와 JSON 응답 스키마를 고정하고 condition 차이는 마지막 `official_evidence=` block로만 제한한다. no-evidence에서는 이 block을 빈 문자열로 두며 `rag_evidence_bundle`, `rag_guideline_text`, `rag_route`를 직렬화하지 않는다. 프롬프트 parity와 evidence-field 제거는 단위 테스트로 고정한다.

## 2. 실행 결과

- model: `gemini-2.5-flash-lite`
- temperature: 0
- 요청: 41/41
- 입력 token: 7,571
- 출력 token: 3,364
- 총 순차 지연시간: 45,818.304ms
- 평균 요청 지연시간: 1,117.520ms
- 추정 비용: USD 0.002102700
- 라벨 분포: non-violation 31, insufficient-context 9, not-applicable 1, violation 0

사용된 단가는 입력 USD 0.10/1M token, 출력 USD 0.40/1M token의 실험 스냅샷이며 청구서가 아닌 추정치다. 원문 프롬프트·응답·rationale을 포함한 private ledger는 `/private/tmp`에 owner-only mode 0600으로 저장했다. 공개 결과에는 정렬된 41개 candidate hash list의 결합 hash만 남긴다.

## 3. 해석 한계

이 실험은 독립 GT가 없으므로 non-violation 31건을 정답, 오탐 제거 또는 정확도로 계산하지 않는다. 특히 violation 0건은 무근거 조건에서 모델이 소극적으로 판정했다는 탐색적 분포일 뿐이다. grounded 41건의 동일 순서 결과가 완료된 후에도 비교는 paired label transition, abstention 변화, citation·locator·entailment verifier coverage, token·지연·비용 차이로 제한하며 proxy accuracy 주효과를 주장하지 않는다.
