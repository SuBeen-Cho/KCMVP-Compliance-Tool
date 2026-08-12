# HEAD 252e756 sets 1–7 L1 신규 snapshot

## 실행 계약

commit `252e75637fa7d3997e3e1c61dc32f3e122c50eef`를 detached clean worktree에 checkout한 뒤 `scripts/export_real_sets_l1_snapshot.py`로 실제 sets 1–7 ZIP을 새로 전처리하고 L1을 실행했다. RAG, L3 및 외부 API는 호출하지 않았다. 실행 전후 clean worktree 변경은 0건이다.

새 snapshot은 `/private/tmp/kcmvp-real-sets1-7-head252e756-clean.snapshot.json`에 owner-only mode 0600으로 저장했다. 공개 artifact는 후보 ID·source·snippet을 제외한 집계만 포함한다.

## 결과

- sources: 193
- L1 candidates: 265
- unique detected rules: 61
- strict snapshot validation: pass
- API calls: 0
- clean detached execution latency: 61,209.965ms
- snapshot ID: `3e28c077799f8f01231b73fd2f65747f9c8668982f53f77daebb39011e1479a7`
- private snapshot SHA-256: `9d491f2b83e7ed077a16aa45fe73715e4e4d0842aad6cc4eb372618a10a36d7b`
- source/input tree SHA-256: `66023b843f81060bf00505cf8aff203c2ea08233bf672e2639100addcee2d31f`
- rules SHA-256: `e03c4aae05088b6425f8395e0bd1f530eefe9dd3001d0d1c4bcab46d2bc9e36e`
- prompts SHA-256: `d51cb578041fd4b20ec4c43cebf5a4801f50dcb652b3141492abe77e39d6ef6c`
- clean workspace SHA-256: `5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456`

## historical 265건과의 경계

과거 snapshot은 현재 snapshot 생성에 입력하지 않았다. 양쪽을 각각 strict validate한 뒤 aggregate count만 비교했다. candidate 수는 둘 다 265건이고 rule-frequency delta는 0건이다. 그러나 snapshot ID는 현재 `3e28c0…`, historical `3727dd…`로 다르며 두 자료를 하나의 성능 분모로 혼합하지 않는다.

재현 집계 코드는 `backend/experiments/current_l1_snapshot_report.py`, 공개 결과는 `backend/evaluation/public_current_head_sets1_7_l1.json`에 기록한다. 지연시간은 단일 cold execution이므로 일반적 처리량으로 주장하지 않는다.

## 현재 router 재평가

신규 snapshot 265건을 현재 router에 입력한 API-free 결과는 deterministic 30건(11.32%), AI-ready 41건(15.47%), hold 194건(73.21%)이다. 과거 정책 재생 artifact의 30/8/227과 비교하면 deterministic은 동일하고 AI-ready는 33건 증가하며 hold는 33건 감소한다. 이는 mapping·router 정책 변화의 coverage 차이지 정확도 향상이 아니다.

AI-ready universe는 `select_exact_ai_ready` 공통 함수와 동일한 순서로 봉인한다. 현재 atomic-v3 계약을 포함한 candidate hash-list 결합값은 `184c1390c2b3c5556b5579dbbf6885f9ab463e9e28511b358618695443dda17b`, candidate ID와 routed payload를 결합한 envelope hash-list 결합값은 `a699bfb24aee051129f2a5ea909c53a82f7f8848c49389bcafafcca4588195b4`이다. 이 값은 이전 v2 프롬프트 실험의 hash가 아니며, atomic-v3 후보 universe alignment에 사용한다.

router cold batch는 815.589ms, warm 5회 평균는 462.287ms, 중앙값은 455.065ms, nearest-rank p95는 586.585ms이다. 신규 snapshot의 router 공개 artifact는 `backend/evaluation/public_current_head_sets1_7_router.json`에 따로 기록한다.
