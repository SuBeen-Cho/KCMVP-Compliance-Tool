# Atomic claim–evidence 계약 그림자 replay

## 목적

AI-ready 41건의 인용·entailment 실패를 rule과 claim 단위로 분리하고, AI가 자유로운 근거 ID를 생성하지 못하도록 audited atomic registry를 구축한다. 본 실험은 v2 private ledger를 외부 API 호출 없이 replay한 shadow 평가이며, 독립 GT 정확도 평가가 아니다.

## 계약

현재 41건에 나타난 8개 rule에 대해 polarity, 적용성, 필수 공식 evidence ID 전체, 프로그램에서 관찰해야 할 사실, context 필수 여부, 예외를 등록했다. 공식 규범의 entailment와 코드 사실 관찰은 서로 다른 필드로 다룬다. selector는 citation과 entailment를 자동 주입하지 않고 허용된 ID 선택지만 제공한다.

계약은 mapping과 현재 공식 index의 ID 전체·출처·hash·locator·span·적용성이 일치할 때만 생성한다. 필수 ID 부분 선택, 미등록 ID, 중복 ID, polarity–verdict 모순, 예외 변조, counterevidence, registry hash 변조는 모두 fail-closed한다. 원문과 코드 내의 prompt injection은 명령이 아닌 untrusted data로 처리한다.

## Shadow replay 결과

| 층위 | 결과 |
|---|---:|
| audited ID 세트 내 citation 선택 | 28/41 |
| v3 atomic assessment 구조 통과 | 0/41 |
| 독립 semantic authorization | 0/41 |
| legacy v2 verifier 통과 | 14/41 |

v2 응답에는 claim assessment·polarity·program fact 필드가 없으므로 추정 복구하지 않았다. 따라서 v3 구조 통과 0건은 성능 하락이 아니라 신규 계약에 대한 historical compatibility 경계이다. AI의 자기 보고만으로 semantic truth를 증명할 수 없으므로 완전한 구조 응답도 `independent_semantic_review_required`로 보류한다.

## 다음 실험

v3 prompt로 41건을 새로 실행하여 1) audited citation 세트 완전성, 2) 구조적 claim 완전성, 3) 독립 semantic authorization을 분리 측정해야 한다. 3번 전에 자동 최종 판정을 허용하지 않는다.
