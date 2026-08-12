# AI-ready 41건 grounded Gemini 실측

## 평가 목적과 제한

동결 historical L1 265건에 mapping 53 상태의 단계형 router를 재생하여 정확히 `AI-ready`인 41건만 실제 Gemini로 판정한다. 본 평가에는 독립 인간 GT가 없으므로 precision·recall·F1이나 정확도를 산출하지 않는다. 주효과는 공식 근거 제공 전후의 raw label 전이, abstention 변화, citation-bound verifier 통과율로 정의한다.

공개 manifest는 ordered occurrence hash 목록 자체대신 해당 목록의 SHA-256만 포함한다. 프롬프트, 응답, occurrence ID, source text와 경로는 mode `0600` 비공개 JSONL에만 보존한다. API key는 `.env`에서만 읽으며 어떤 artifact에도 기록하지 않는다.

별도 no-evidence comparator와 동일하게 retrieval 생성 필드를 제거한 candidate hash 정의를 적용했을 때 ordered digest는 두 runner 모두 `a4a26d74159abf49b64b0dc68f24006b636563d460390852ec8f942580b6a1b1`이다. 초기 grounded manifest의 `ae995...`는 candidate ID와 evidence bundle까지 포함한 다른 hash 정의였으며, 유니버스 차이가 아니다. 현재 manifest는 공통 digest와 추가 envelope-binding digest를 분리해 기록한다.

## 설계

`no_rag`와 `grounded`는 동일 observation·schema·model·temperature를 사용하고 `official_evidence` 블록만 다르게 구성한다. Grounded 응답은 모델이 선택한 unit ID를 불변 원문 span으로 재결합한 후 다음을 모두 검증한다.

- rule–unit·source·hash binding
- 공식 권위와 normative role
- locator·version·적용 범위
- exact supporting span
- entailment·예외·반례 확인
- 현재 sealed official index와의 동일성

## 결과

분석에 사용한 유일 paired 응답은 82건이다. 실행 도구 세션 회수 과정의 중복 실행으로 11건이 추가 요청되어 물리 API 요청은 93건이다. 중복은 인덱스·조건별 첫 응답만 채택하여 분석에서 제외하고, 실제 비용에는 모두 포함한다.

| 지표 | no-RAG | grounded |
|---|---:|---:|
| 분석 요청 | 41 | 41 |
| raw violation | 0 | 2 |
| raw non-violation | 0 | 32 |
| raw not-applicable | 2 | 2 |
| raw abstain | 39 | 5 |
| verifier 통과 | 0 | 4 |
| verified final non-violation | 0 | 4 |
| verified final abstain | 41 | 37 |
| 입력 토큰 | 9,863 | 31,462 |
| 출력 토큰 | 3,289 | 5,785 |
| 평균 지연시간 | 1,074.29 ms | 1,253.48 ms |
| 중앙 지연시간 | 1,064.20 ms | 1,186.91 ms |
| 추정 비용 | $0.0023019 | $0.0054602 |

Raw 전이는 `abstain→non_violation` 30건, `abstain→violation` 2건, `abstain→not_applicable` 2건, `not_applicable→non_violation` 2건, `abstain→abstain` 5건이다. 즉 공식 근거는 모델의 raw abstention을 크게 줄였다. 다만 초기 verifier 통과 4/41은 아래 적용성 검사 구현 결함을 포함하므로 최종 성능 수치로 사용하지 않는다.

Verifier 실패는 적용 범위 불일치 26건, citation 누락 10건, 미지 unit ID 1건이었다. 사후 공격 감사에서 26건은 `CBC-001`·`CTR-001`과 같이 rule ID에 `LEA`가 포함되지 않으면 거부하는 문자열 추론 결함으로 확인했다. 현재는 candidate 임의 metadata가 아닌 audited mapping과 active YAML을 content-addressed seal로 결합하여 algorithm·mode 적용성을 검증하도록 수정했다. 기존 v1 private ledger는 citation ID·span·decision 원문을 보존하지 않아 수정 verifier로 과거 41건을 과학적으로 replay할 수 없다. 따라서 초기 4/41은 무효화하고, 향후 실행부터 canonical decision ledger를 저장한다.

물리 93요청의 총 사용량은 입력 48,030, 출력 10,022 토큰이며 총 추정 비용은 $0.0088118이다. 가격은 입력 $0.10/M, 출력 $0.40/M 가정을 사용한다.

## 결론과 다음 단계

공식 근거 주입은 raw decision coverage를 높였지만 수정 전 verifier 결과는 최종 성능으로 사용할 수 없다. 적용성 검증은 audited rule contract와 active YAML을 통한 canonical provenance로 교체했으며, 다음 실행은 exact-once ledger와 replay 가능한 canonical decision을 보존하여 수정 verifier 통과율을 새로 측정해야 한다.
