# Fail-closed 116개 격차 분류 및 mode/common 2차 감사

## 결과

현재 166개 활성 규칙 중 50개는 원문 evidence에 바인딩되어 있고 116개는 fail-closed이다. 116개를 중복 없는 primary gap으로 기계 분류한 결과는 다음과 같다.

| Primary gap | 규칙 수 | 의미 |
|---|---:|---|
| detector scope | 49 | 부재·문자열·표면 AST로 동치 구현과 project boundary를 증명하지 못함 |
| authority gap | 30 | 7-source index에 주장 전체를 직접 입증하는 규범 source가 없거나 manual/research/일반 요구와 혼합됨 |
| exact locator gap | 27 | 관련 공식 문구는 있으나 claim 전체를 바인딩한 exact unit 감사가 완료되지 않음 |
| applicability gap | 10 | MCT/MMT/KAT/제출 산출물 조건을 일반 구현 파일에 적용할 수 없음 |

`backend/experiments/failclosed_gap_audit.py`는 활성 YAML과 evidence audit를 읽어 closed-schema artifact를 재생성한다. 각 항목은 네 격차 플래그 중 정확히 하나만 true이고 결정은 `remain_fail_closed`로 고정된다. artifact는 `backend/mapping/failclosed_gap_audit.json`이다.

## Mode/common 전수 재검토

Fail-closed mode 31개와 common 5개, 총 36개를 7-source index와 다시 대조했다. 신규 verified 승격은 0개이다.

- CBC/CTR/OFB/CFB 수식, GCM/CCM nonce, CMAC 보조키는 관련 알고리즘 문구가 있으나 현재 detector가 상태 유일성·동치 표현·wrapper를 충분히 증명하지 못한다.
- 제로화, CSPRNG, constant-time, 통일 error는 일반 암호모듈 보안 의무와 mode 특화 claim이 혼합되어 있다.
- 소스 매뉴얼의 API 행동을 모든 적합 구현의 유일한 구조로 승격하지 않는다.
- CBC/CTR MCT 주장은 검증 산출물 occurrence에만 적용되므로 일반 소스에 적용하지 않는다.

상세 그룹은 `backend/mapping/mode_common_entailment_review.json`에 기록했다. “공식 문구 발견”을 즉시 승격으로 간주하지 않고 detector claim의 완전한 entailment를 요구했기 때문에 0개 승격은 예상된 보수적 결과이다.

## 재평가

Mapping integrity는 verified exact-set, source binding, bundle recall, unverified fail-closed를 분리하여 측정한다. 본 사이클은 신규 승격이 없으므로 verified 50개/fail-closed 116개 집합이 유지된다. 이 결과는 semantic retrieval 정확도가 아니라 registry와 runtime의 동등성 검증이다.
