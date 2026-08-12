# Atomic claim v3 구조 계약 탐색 실험

## 목적과 주장 범위

현재 HEAD에 결합된 265개 L1 후보 중 router가 공식 근거 기반 AI 검토 대상으로 선택한 41건에 대해, 규칙을 사전 감사된 atomic claim과 정확한 evidence-unit 집합으로 분해하여 Gemini가 폐쇄형 응답 계약을 따르는지 측정했다. 이 실험은 판정 정확도나 독립적인 의미 entailment를 측정하지 않는다. 모델에 필수 evidence-unit ID가 제공되므로 `structurally_valid`는 근거 선택 정확도가 아니라 구조·복사·내부 일관성 준수율이다.

## 실행 결과

- 실행 대상: grounded AI-ready 41건
- API 호출: 41건, 재시도 0건
- 입력/출력 토큰: 47,743 / 8,725
- 평균 지연시간: 1,317.861ms
- 추정 비용: USD 0.0082643 (`estimate_not_invoice`)
- 구조 계약 충족: 16/41(39.02%)
- 규범 entailment 미확인: 14건
- 프로그램 사실 불충분: 8건
- claim verdict 내부 불일치: 3건
- 독립적 의미 승인 및 자동 최종 판정: 0건

따라서 유효한 결론은 모델이 16건에서 필수 ID 집합, 예외 필드, polarity와 자기 보고를 구조적으로 일관되게 반환했다는 것뿐이다. 16건이 실제 준수·위반 판정에 맞았다는 뜻은 아니다. 나머지 25건은 fail-closed되어 hold 상태를 유지한다.

## provenance 제한

해당 유료 실행은 이후 추가된 future-run hardening 이전에 수행되었다. private ledger는 41개 연속 index, 41개 고유 candidate binding, 단일 모델·prompt version, retry 0, mode 0600을 만족한다. 그러나 실행 당시 row에 contract 본문, registry/index/mapping/runner hash와 완전한 experiment spec stamp를 보존하지 않았다. 따라서 공개 partial replay는 저장된 구조 결과와 ledger hash만 재집계하며, 현재 registry 값을 과거 실행 값으로 소급 대입하지 않는다.

이 결과의 provenance 상태는 `legacy_provenance_partial`이고, hardened verifier의 완전 재현 결과로 표현하지 않는다. 공개 artifact에는 원문 span, candidate ID, prompt, 응답, 로컬 경로 및 API key를 포함하지 않는다.

## 다음 게이트

1. future runner는 registry schema/hash, official index, mapping, runner, snapshot, universe, model/config와 prompt version을 experiment spec에 결합한다.
2. 모델 응답은 duplicate-key를 거부하는 closed JSON parser로 검증하고, 41개 slot의 중복·누락이 있으면 공개 결과를 발행하지 않는다.
3. atomic contract의 구조 통과는 계속 `verified=false`로 유지한다.
4. 최종 판정 승격에는 별도의 sealed program-fact extractor와 독립적인 semantic reviewer가 모두 필요하다.
5. 이후 성능평가는 독립 GT가 있는 동일 occurrence에서 selective coverage, abstention, accuracy를 분리하여 측정한다.

## 검증

전체 backend 회귀는 `623 passed, 1 skipped`이며, atomic contract 공격 테스트는 forged same-ID evidence, registry drift, 부분·중복 citation, 예외·counterevidence, polarity 불일치, Unicode prompt injection 및 provenance 누락을 fail-closed로 확인한다.
