# 현재 HEAD AI-ready 45건 독립 동결 및 이전 41건 비교

## 목적

검증된 LEA round 근거 매핑 반영 후 router 모집단이 41건에서 45건으로 바뀌었다. 기존 41건 유료 실행의 결과와 새 모집단을 합치거나 소급 재해석하지 않고, 현재 모집단을 별도 동결하여 occurrence membership과 근거 준비도만 API 없이 비교했다. 이 결과는 정확도·의미 entailment·자동 승인 성능을 주장하지 않는다.

## 깨끗한 L1 snapshot

- 기준 commit: `1f7e50c9f8f1b80d3b206d4147eba78653ae4fef`
- source: 193개
- L1 candidate: 265건
- snapshot ID: `9314f4dfd756efef6c74d62350cfde6d08dfb334b007637861439cc6f24bbb06`
- snapshot file SHA-256: `4f0418dd711d4c164e3c0eef126d162c8e9d249f8caa7b6d333a19d536bfecc2`
- mode: `0600`
- clean HEAD에서 생성한 private snapshot과 공개 manifest의 file SHA-256: 일치

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

재현 코드는 `backend/experiments/current_router_universe_freeze.py`, 공개 결과는 `backend/evaluation/public_current_head_ai_ready45_freeze.json`이다. 외부 API 호출은 0건이다. private snapshot과 공개 평가는 모두 위 clean commit에서 실행했고, artifact scope는 `clean_current_head_router_universe_freeze_api_free`, router manifest의 `git_dirty`는 `false`다. router 의미 입력인 rules·mapping·official index hash와 source tree hash는 공개 artifact에 별도 봉인했다. 지연시간은 해당 clean 재실행에서 cold batch 735.338ms, warm 5회 평균 724.826ms였으며 일반 처리량 성능으로 일반화하지 않는다.

다음 유료 평가나 프로그램 사실 검증은 이 45건 universe hash를 새 실험 사양에 명시해야 한다. 이전 41건과 점수를 병합하려면 새 4건을 동일 프로토콜로 독립 실행한 뒤 41/4 cohort를 분리 보고해야 한다.
