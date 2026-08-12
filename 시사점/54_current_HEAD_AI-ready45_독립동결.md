# 현재 HEAD AI-ready 45건 독립 동결 및 이전 41건 비교

## 목적

검증된 LEA round 근거 매핑 반영 후 router 모집단이 41건에서 45건으로 바뀌었다. 기존 41건 유료 실행의 결과와 새 모집단을 합치거나 소급 재해석하지 않고, 현재 모집단을 별도 동결하여 occurrence membership과 근거 준비도만 API 없이 비교했다. 이 결과는 정확도·의미 entailment·자동 승인 성능을 주장하지 않는다.

## 깨끗한 L1 snapshot

- 기준 commit: `bd440a17aceee3cd88eb31e36993348ca61459ba`
- source: 193개
- L1 candidate: 265건
- snapshot ID: `15fc808f1abf6fe63c7de857e1fd972b6aae85dc65a8de2b8f412f10d71952b8`
- snapshot file SHA-256: `57d5cf0b6381ccf094ac54be6408aedab3ef86d3df62133a57657c90d50dde8d`
- mode: `0600`
- 동일 입력 2회 생성 file SHA-256: 완전 일치

private snapshot은 공개 저장소에 포함하지 않았다. 공개 artifact에는 집계, 결합 hash, 규칙군별 빈도만 남겼다.

## 현재 router 분포

| 단계 | 건수 | 비율 |
|---|---:|---:|
| deterministic | 30 | 11.32% |
| AI-ready | 45 | 16.98% |
| hold | 190 | 71.70% |

현재 AI-ready ordered payload hash는 `430495f3fc249f97d2e6d028e3a103afc1342099e69bbe361c8c30829f5a2d17`, ordered envelope-binding hash는 `ecccd8e650412d5f6d02a67bdf3b52ca84a96e1e47276e805dabb94f17a9458a`이다. 후보 순서나 router가 결합한 payload가 달라지면 값도 달라진다.

## 이전 41건과 독립 비교

이전 atomic-v3 private ledger의 공개 SHA-256 seal을 먼저 검증한 다음, ledger에 저장된 41개 candidate ID digest를 현재 265건 snapshot에 exact join했다. 개별 digest는 공개하지 않았다.

| cohort | 건수 | 규칙군 |
|---|---:|---|
| retained | 41 | 기존 8개 rule family 전부 |
| added | 4 | LEA-027, LEA-028, LEA-029, LEA-030 각 1건 |
| removed | 0 | 없음 |

따라서 45건은 이전 41건을 완전히 보존하면서 공식 LEA round 근거가 검증된 4건이 추가된 새 모집단이다. 기존 41건의 Gemini 결과는 새 4건에 적용하지 않는다.

## 근거 준비도

| cohort | verified official bundle | audited atomic contract | semantic authorization |
|---|---:|---:|---|
| retained 41 | 41 | 41 | 이번 실험에서 미측정 |
| added 4 | 4 | 4 | 이번 실험에서 미측정 |
| current 45 | 45 | 45 | 이번 실험에서 미측정 |

`verified official bundle`은 unit/source/locator/span이 존재하고 span SHA-256이 일치한다는 뜻이다. `audited atomic contract`는 해당 rule에 폐쇄형 claim 계약이 존재한다는 뜻이다. 둘 다 프로그램 사실의 진위나 최종 판정 정확성을 의미하지 않는다.

## 재현과 한계

재현 코드는 `backend/experiments/current_router_universe_freeze.py`, 공개 결과는 `backend/evaluation/public_current_head_ai_ready45_freeze.json`이다. 외부 API 호출은 0건이다. 공개 평가 시점에는 병렬 개발 파일이 존재하여 artifact scope와 manifest에 dirty worktree가 기록된다. 반면 private snapshot 자체는 위 clean commit에서 두 번 동일하게 생성됐으며 router 의미 입력인 rules·mapping·official index hash는 공개 artifact에 별도 봉인했다.

다음 유료 평가나 프로그램 사실 검증은 이 45건 universe hash를 새 실험 사양에 명시해야 한다. 이전 41건과 점수를 병합하려면 새 4건을 동일 프로토콜로 독립 실행한 뒤 41/4 cohort를 분리 보고해야 한다.
