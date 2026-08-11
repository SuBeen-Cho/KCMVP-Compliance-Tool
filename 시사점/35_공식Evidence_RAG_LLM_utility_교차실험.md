# 공식 evidence RAG의 LLM utility 교차 실험

## 1. 목적과 설계

본 실험은 공식 근거가 LLM 판정을 실제로 개선하는지와, 무관한 공식 문서가 오히려 판정을 오염시키는지를 분리하는 소규모 파일럿이다. 원문 매핑이 검증된 `GCM-002`, `CCM-003`, `LEA-048`을 선택하고, 각 규칙에 위반·비위반·비적용 counterfactual을 하나씩 배치하여 9개 occurrence를 구성한다. 각 occurrence는 다음 세 조건에 동일하게 입력한다.

1. `no_rag`: 규칙 요구사항과 관찰만 제공한다.
2. `verified_oracle`: 해당 규칙에 사전 검증된 공식 evidence unit만 제공한다.
3. `irrelevant_official`: 다른 규칙에 속한 공식 evidence unit을 제공한다.

모델은 `gemini-2.5-flash-lite`, temperature 0을 사용한다. 프롬프트와 응답 원문은 Git 산출물에 저장하지 않고 SHA-256, label, token, latency만 로컬 원장에 기록한다. 원장은 `.gitignore`로 차단한다. 공개 JSON에는 API key, 원문 span, prompt, response, 절대경로를 포함하지 않는다.

## 2. 실험 계약 개발

`v1`은 규칙 ID만 no-RAG에 제공하여 no-RAG 1/9, oracle raw 5/9를 얻었다. 이는 규칙 ID가 자연어 요구사항이 아니므로 비교군을 의도적으로 열세하게 만든 설계 결함으로 판단한다. 따라서 효과크기 추정에서 제외하되 재현성을 위해 결과를 보존한다.

`v2`는 모든 조건에 동일한 규칙 요구사항을 제공한다. no-RAG raw 7/9, oracle raw 8/9로 변하여 공식 원문 추가의 순수 이득이 1건임을 확인한다. 다만 LLM이 원문을 요약하여 `supporting_span_mismatch`가 4건 발생한다.

`v3`부터는 LLM이 선택한 citation ID를 불변 evidence index의 정확한 span으로 결정적 해석한 후 verifier에 전달한다. 이는 원문을 LLM에게 재타이핑하게 하는 불필요한 실패 모드를 제거하면서도 citation ID, source hash, locator, applicability, entailment 검사를 유지한다. `v4`는 LEA fixture가 MOVS 교환 산출물임을 문장에 명시하여 적용범위 모호성을 줄인 최종 탐색 버전이다.

## 3. `v4` 결과

| 조건 | raw accuracy | verifier coverage | abstention | final accuracy(all) | 입력/출력 token | 평균 latency | 추정 비용 |
|---|---:|---:|---:|---:|---:|---:|---:|
| no-RAG | 7/9 (77.8%) | 9/9 | 0.0% | 7/9 | 2,307 / 861 | 988 ms | $0.0005751 |
| verified oracle | 8/9 (88.9%) | 4/9 | 55.6% | 4/9 | 6,915 / 1,197 | 1,123 ms | $0.0011703 |
| irrelevant official | 7/9 (77.8%) | 0/9 | 100.0% | 0/9 | 5,232 / 1,261 | 1,146 ms | $0.0010276 |

oracle의 raw 정답은 no-RAG 대비 1건 증가하고 손실은 0건이다. McNemar exact two-sided `p=1.0`으로, 표본 9건에서 유의한 향상을 주장할 수 없다. oracle은 no-RAG보다 입력 token을 약 3.0배, 추정 비용을 약 2.0배 사용한다. 따라서 현재 결과는 “공식 RAG가 정확도를 유의하게 향상시킨다”가 아니라 “무관 공식 근거를 모두 차단하면서 관련 근거의 소규모 raw 이득을 관찰했다”로 제한한다.

`final_accuracy_all`은 abstention을 오답으로 계산하므로 정확도와 coverage를 반드시 함께 보고한다. oracle의 5건 차단은 citation missing이며, 이 중 3건은 비적용 fixture로 보수적 abstention이 예정된 결과이다. 나머지 2건은 `LEA-048`에서 발생한다. GCM/CCM의 적용 fixture 4건은 모두 citation-bound 검증을 통과한 반면 LEA는 명시적 MOVS 파일에서도 citation을 생성하지 않았다. 이는 현재 9개 LEA evidence unit이 실제 파일명 정규식 전체를 직접 entail하는지 재감사해야 함을 의미한다. 재감사 전에는 `LEA-048`을 강한 verified 근거로 확대 해석하지 않는다.

무관 공식 근거는 4건의 `citation_not_bound_to_rule`과 5건의 `citation_missing`으로 9/9 모두 차단된다. raw label이 정답이더라도 잘못된 근거로 후보를 제거하지 않는 fail-closed 계약이 작동한다.

## 4. 보안·재현성 검증

- 하네스 테스트 5건에서 fixture 균형성, GT 비노출, fail-closed disposition, citation ID→exact span 결정적 변환, 공개 산출물 비밀정보 배제를 검증한다.
- 공개 결과 v1–v4는 각각 다른 SHA-256와 prompt version을 보존한다.
- 실제 호출은 v1–v5 5회 버전×27건=135회이며, 단가 가정에 따른 총 추정비용은 `$0.0143364`이다. 비용은 input `$0.10/M`, output `$0.40/M` 가정을 결과에 명시한다.
- 본 실험은 단일 모델·단일 시드·합성 fixture의 파일럿으로 외부 성능 추정이 아니다.

## 5. 다음 개발 방향

1. `LEA-048`의 9개 unit이 REQUEST/RESPONSE/FACTS의 확장자·키 길이·모드·테스트 유형 토큰을 직접 함의하는지 원문 단위로 재감사한다.
2. verifier는 candidate 제거 판정과 비적용 유지 판정을 분리한다. 비적용에서 citation이 없다는 이유만으로 품질 지표가 왜곡되지 않도록 applicability gate를 별도 평가한다.
3. 현행 50개 verified 규칙에 대해 규칙별 최소 30건 이상의 균형 fixture와 실제 코드 occurrence를 구성하고, rule-stratified bootstrap CI와 McNemar 검정을 적용한다.
4. no-RAG, retrieved RAG, verified oracle, irrelevant evidence, contradictory evidence를 분리하여 retrieval recall과 judgment utility를 따로 보고한다.
5. 정확도와 함께 coverage-risk curve, abstention rate, citation validity, entailment acceptance, input token, latency, cost를 동시에 보고한다.

## 6. v5 적용성 인용 계약 후속 실험

v4의 oracle `citation_missing` 5건을 분석한 후, v5에서는 RAG 조건의 모든 라벨이 규칙 영역 또는 적용성 경계 판단에 사용한 공식 unit ID를 반환하도록 계약을 강화한다. 근거가 실제로 해당 판단을 지지하지 않으면 인용을 조작하지 않고 `abstain`하도록 명시한다. unit ID가 정상적으로 반환되면 런너가 불변 인덱스의 exact span을 결정적으로 결합한다.

| 지표 | v4 oracle | v5 oracle | 차이 |
|---|---:|---:|---:|
| raw accuracy | 8/9 | 8/9 | 0 |
| citation coverage | 4/9 | 9/9 | +5건 |
| verifier acceptance | 4/9 | 3/9 | -1건 |
| abstention | 5/9 | 6/9 | +1건 |
| input/output token | 6,915 / 1,197 | 7,653 / 2,315 | +738 / +1,118 |
| 평균 latency | 1,123 ms | 1,518 ms | +35.2% |
| 추정 비용 | $0.0011703 | $0.0016913 | +44.5% |

citation coverage는 44.4%에서 100%로 증가하여 프롬프트 계약의 직접적 목표를 달성한다. 그러나 verifier acceptance는 오히려 4건에서 3건으로 감소한다. 6건의 `entailment_unconfirmed`은 citation의 존재와 최종 verdict의 entailment가 다른 문제임을 보여준다. 즉, 인용률만 높이는 것은 판정을 더 많이 통과시키지 않으며, entailment gate를 유지해야 한다.

LEA 재감사 대기 상태를 분리하면 GCM·CCM 6건은 no-RAG와 oracle raw accuracy가 모두 6/6이고, oracle citation coverage는 6/6, verifier acceptance는 3/6이다. 따라서 검증된 수치 프로파일에서는 RAG의 정확도 이득을 관찰하지 못했고, 인용 추적성만 확보한다. LEA 3건은 oracle raw 2/3, citation 3/3이지만 entailment acceptance 0/3이다. 이 결과는 `LEA-048` 원문 매핑 재감사 전에 성능 지표에 합산하지 않는다.

v5의 무관 공식 근거는 8건 `citation_not_bound_to_rule`, 1건 `citation_missing`으로 전부 fail-closed된다. 강한 인용 유도가 무관 근거 인용을 4건에서 8건으로 증가시켰지만 rule binding verifier가 모두 차단한다. 이는 prompt 준수율과 근거 타당성을 분리 평가해야 함을 다시 확인한다.

## 7. 결정적 verified-literal router

v5에서 GCM·CCM의 no-RAG와 oracle이 모두 6/6이고 RAG는 token·비용·지연만 증가시켰다. 따라서 AI 의존도를 일괄적으로 높이는 대신, 다음 네 조건을 모두 만족하는 후보만 `deterministic_verified_rule`로 분류한다.

1. 규칙 ID가 `GCM-002`, `CCM-003`, `CMAC-004` 화이트리스트에 속한다.
2. 규칙과 공식 evidence unit 매핑이 verified이며 source hash가 유효하다.
3. L1이 `kcmvp_explicit_tag_literal_v1` scanner로 명시적 단위와 정수 literal을 확정했다.
4. router가 매치 span hash를 재검증하고 동일 scanner를 다시 실행했을 때 동일한 위반이 재현된다.

해당 후보는 L1 결과에서 제거하지 않고 `decision_source=deterministic_l1_official_evidence`를 부착한다. 또한 unit ID, source ID, page/block locator, evidence span SHA-256, source SHA-256를 `official_evidence_provenance`에 기록한다. L3 candidate selector는 이 후보를 제외하므로 API key가 없어도 결정적 후보만 있는 배치를 정상 처리한다. 인덱스·매핑·hash 불일치가 발생하면 즉시 일반 retrieval 경로로 fail-closed한다. 일반 semantic, 단위 미지정, runtime 변수, 혼합 알고리즘 문맥에는 확대하지 않는다.

독립 공격감사에서 초기 marker의 span hash는 자기 일관성만 검사하고 후보 occurrence와 결합되지 않으며, selector와 L3가 `rag_route` 문자열만 보고 우회하는 문제를 확인했다. 이를 rule/file/line/end-line/scope/snippet/span hash에 결합된 process-local HMAC seal로 교체했다. selector와 L3 직전에는 scanner seal, 현재 audit binding, 현재 공식 인덱스의 source/text hash, exact unit set, locator와 provenance를 전부 재검증한다. forged marker, clone, rehashed span, malformed type, 다른 규칙으로의 복제, provenance 변조, 인덱스 누락·사후 변조는 모두 retrieval로 강등되며 후보를 조용히 제거하지 않는다. 이 공격 회귀를 포함한 후속 전체 테스트 결과는 `540 passed, 1 skipped`이다.

3개 합성 위반을 실제 pipeline으로 실행한 결과 GCM 2개, CCM 1개, CMAC 4개의 공식 unit provenance가 부착되고 LLM 호출 3건을 회피한다. router와 provenance 로드는 fresh process 단일 관찰치 128.270 ms이며 지연 분포 추정이 아니다. v5 no-RAG 관찰 평균을 적용한 투영치로는 입력 1,015 token, 출력 296 token, 순차 지연 3,094.531 ms, `$0.0002199`를 절약한다. 이 수치는 새 API 호출의 실측치가 아니라 v5 관찰 평균에서 계산한 투영치임을 명시한다.

## 8. 마감 독립 재계산 감사

v1–v5의 135개 공개 row에서 raw accuracy, final accuracy, coverage, abstention, token, 평균 latency, 비용과 paired McNemar exact 검정을 하네스 함수와 분리하여 재계산한다. 모든 저장 수치가 재계산과 일치한다. v5의 GCM·CCM 18 rows와 LEA 9 rows 분할도 중복·누락 없이 일치한다. `final_accuracy_all`은 abstention을 오답으로 계산한다는 정의가 coverage와 분리되어 있으며, raw accuracy와 혼동하지 않는다.

prompt parity는 각 버전 내에서 fixture, 규칙 요구사항, 출력 계약을 고정하고 evidence 조건만 변경한다. v1은 no-RAG에 규칙 설명이 없는 설계 결함으로 효과 추정에서 제외한다. v2–v3과 v4–v5는 서로 다른 fixture hash를 사용하므로 버전 경계를 넘어선 paired 효과로 합성하지 않는다.

마감 감사에서 v1–v4 JSON은 model, prompt version, fixture hash, 시각과 단가를 보존하지만 run ID, temperature/seed, evidence index·mapping·runner hash가 없음을 확인한다. 이 산출물은 원본 보존을 위해 변경하지 않고 `legacy_provenance_incomplete`로 다룬다. v5 schema 1.1에는 run ID, model, temperature 0, seed 미지정, request 27건, closed response contract를 추가한다. 다만 index·mapping·runner hash는 실험 후 소스가 변경된 뒤 소급 보강했으므로 `retroactive_partial`로 표시하고 실행 시점 hash로 가장하지 않는다. deterministic router 결과도 schema 1.1로 올려 run ID, baseline result hash, API 호출 0건, 측정 반복 1회를 명시하되 기존 실행은 동일한 소급 provenance 한계를 갖는다. 후속 실행부터는 `provenance_capture=at_execution`으로 실행 시점에 자동 동결한다.

결론적으로 AI 활용 고도화는 모든 후보에 LLM을 추가하는 것이 아니다. parser·scanner가 확정할 수 있는 사실과 공식 provenance는 결정적으로 처리하고, applicability·exception·교차 함수·분산 호출처처럼 문맥이 판정을 바꾸는 후보에만 RAG와 LLM을 사용해야 한다.
