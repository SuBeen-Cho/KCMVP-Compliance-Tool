# 0_KCMVP smart-crypto 원본 최신 AI 성능평가

## 입력 확정

활성 저장소 job storage에 보존된 `smart-crypto-master.zip` 3개를 검사했고 모두 바이트 단위 SHA-256 `3f4b865efe9350753119857918ac7addd1b012171f899defa6a36a415817de93`로 동일했다. 원본은 C 34개, H 25개, 총 59개 C/H 파일과 14,511 물리 LOC를 포함한다. 세트 5–7은 원본과 `src/lea.c`, `src/cipher.c`가 서로 다른 변형이므로 이 실험에서 대리 입력으로 쓰지 않았다.

## 논문·과거 실험 기록 감사

- 2026-05-02 보고: L1 29건, L3 2건 제거, 최종 27건, 1.86건/KLOC.
- 2026-05-19 GPT-4.1-mini 보고: C 파일 34개, L1 11건, L3 처리 10건, 최종 11건, 172초.
- 더 이전 저장 JSON은 규칙 버전에 따라 107–166건을 기록한다.

이 편차는 과거 실행이 불변 code/input/prompt manifest와 결합되지 않았음을 보여준다. 따라서 수정 논문의 기존 0.58건/KLOC 및 과거 실행 수치는 현재 스냅샷의 성능 주장에 합치지 않는 다.

## 수정 전 원본 대비 달라진 기능과 개선점

| 영역 | 수정 전 논문/실행 | 현재 구현 |
|---|---|---|
| 실험 무결성 | 코드·입력·프롬프트 버전 결합 없음 | Git commit, snapshot, rules, mapping, index, prompt SHA-256 분리 봉인 |
| 원본 식별 | 세트 변형과 0_KCMVP 원본의 구분이 불명확 | 동일 ZIP 3개 SHA-256 일치 확인, 세트 5–7의 `lea.c`/`cipher.c` 차이 분리 |
| L1 후보 | ruleset 버전에 따라 107–166→29건→11건으로 흔들림 | 현재 ruleset에서 11건을 불변 snapshot으로 봉인 |
| L2/RAG | 저자 작성 Markdown을 rule ID별로 무조건 주입 | 공식 PDF evidence unit, exact rule binding, authority/version/hash/applicability 검증, 미매핑 fail-closed |
| AI 선택 | 대부분 후보를 L3에 전달 | deterministic/AI-ready/hold router, 선택 분모·강제포함·cap 검증 |
| AI 판정 | 원문 근거 인용 계약 없음 | span, locator, source/text hash, applicability, exception, entailment verifier 강제 |
| 안전 처리 | AI가 제거한 후보를 FP 제거로 계수 | 근거/semantic fact 미충족은 hold/abstain, GT 없이 정확한 제거로 표현 금지 |
| 반복 통계 | 반복 호출을 독립 표본으로 오독할 수 있음 | 결정적 반복은 stability-only, 고유 candidate/clone group 단위 통계 |
| 비용·지연 | 총 시간 중심 | 후보별 mean/median/p95, token, 물리 호출, duplicate/retry, 추정 비용 분리 |
| 공개 안전 | 원시 실행 파일에 경로/코드가 섞일 수 있음 | 공개 artifact는 집계+hash만, private ledger/snapshot은 mode 0600 |

가장 큰 행동 차이는 이전에는 AI 후보 제거를 성능 개선으로 바로 계수했지만, 현재는 공식 근거와 코드 사실이 둘 다 봉인되지 않으면 제거하지 않고 hold한다는 점이다. 이 때문에 이번 0_KCMVP 원본은 production AI-ready 0건이며, 별도 No-RAG comparator만 탐색적으로 실행했다.

## 논문 기존 표 형식의 최신 교체값

### 표 2 형식: 코드 위반 탐지 성능

기존 128 GT 전체 표와 분모가 다른, 고유 후보·clone-group 분리를 적용한 historical proxy post-selector held-out 46행의 교체값이다.
이 표의 TP/FP/FN·Precision·Recall·F1은 **AI score/post-selector 결과를 포함**한다. 다만 RAG와 No-RAG 조건을 pooled한 탐색 실험이어서, 기존 표의 `L3 FP removal`을 동일 정의로 분리하지 못한다.

| Metric | Updated result |
|---|---:|
| True Positive (TP) | 36 cases |
| False Negative (FN) | 4 cases |
| Recall | 90.0% |
| L1-stage False Positive candidates | Not isolated in this post-selector cohort |
| L3 filtering: FP removal | Not isolated |
| Proxy-labeled TPs removed by L3 | Not isolated |
| Final False Positive (FP) | 6 cases |
| Precision | 85.7% |
| F1-score | 87.8% |

TN이 0인 양성 편중 소표본이고 동일 모델 proxy GT이므로, 이 표를 전체 시스템 정확도나 128 GT의 직접 갱신으로 해석하지 않는다.

### 표 3 형식: 상용 암호모듈 사례

이 표는 `0_KCMVP.zip` 원본에 대한 **현재 L1 직접 재실행 + 실제 Gemini No-RAG AI 9회 호출**을 포함한다. 공식 evidence를 결합한 grounded-RAG는 해당 rule family mapping이 없어 production 계약이 11건 전체를 hold했으며, 실행하지 않았다.

| Metric | Updated result |
|---|---|
| C source scope | 34 files / 11,983 physical LOC |
| C and header scope | 59 files / 14,511 physical LOC |
| Candidate count | 11 |
| Candidate frequency | 0.758 cases/KLOC (C/H denominator) |
| Ground-truth status | Unavailable; AI label distribution only |
| Production routing | deterministic 0 / AI-ready 0 / hold 11 |
| Experimental No-RAG AI | 9 calls; violation 3 / non-violation 6 |
| AI latency | mean 1,098.614 ms; median 1,110.690 ms; p95 1,234.897 ms |
| AI token/cost | 1,645 input / 732 output; USD 0.0004573 estimated |

## 다차원 성능평가 전체 표

아래 표는 처음 사전 정의한 성능 축을 누락 없이 나눈 것이다. 표본이 다른 경우 `0_KCMVP current`, `historical proxy`, `synthetic fixture`를 명시했다.

### 1. 탐지 성능

| 지표 | 값 | 분모·한계 |
|---|---:|---|
| Precision | 85.7% | historical proxy post-selector held-out 46행 |
| Recall | 90.0% | 동일 분모 |
| F1 | 87.8% | 동일 분모 |
| TP / FP / FN / TN | 36 / 6 / 4 / 0 | 양성 편중, TN=0 |
| F1 clone-bootstrap 95% CI | [77.33%, 95.45%] | 23 held-out clone groups |
| 0_KCMVP 정확도 | N/A | 독립 GT 없음 |

### 2. 4-class 판정 및 분포

| 항목 | violation | non-violation | insufficient-context | not-applicable |
|---|---:|---:|---:|---:|
| Proxy GT 265 | 104 | 18 | 30 | 113 |
| 0_KCMVP No-RAG AI 9 | 3 | 6 | 0 | 0 |

4-class accuracy, macro-F1, weighted-F1은 현재 스냅샷과 proxy GT의 candidate identity 1건 불일치 및 0_KCMVP GT 부재로 N/A이다.

### 3. 선택적 판정·abstention

| 지표 | 값 | 범위 |
|---|---:|---|
| Deterministic coverage | 30/265 (11.32%) | historical proxy routing |
| AI-ready coverage | 45/265 (16.98%) | historical proxy routing |
| Hold/abstention | 190/265 (71.70%) | hold를 정답으로 세지 않음 |
| Binary-eligible hold | 73/122 (59.84%) | proxy binary subset |
| Hold 내 proxy violation | 63 | 미해결 위반 위험 |
| 0_KCMVP production hold | 11/11 (100%) | official evidence 미매핑 |

Deterministic route에 최종 verdict가 봉인되지 않아 selective accuracy/risk는 N/A로 유지한다.

### 4. 단계별 Router 성능

| 모집단 | L1 후보 | Deterministic | AI-ready | Hold |
|---|---:|---:|---:|---:|
| 7세트 current | 265 | 30 | 45 | 190 |
| 0_KCMVP 원본 current | 11 | 0 | 0 | 11 |

7세트 router cold batch 735.338 ms, warm 평균 724.826 ms이며 0_KCMVP는 cold 3.317 ms, warm 평균 2.867 ms이다.

### 5. RAG / No-RAG 효과

| 지표 | 값 |
|---|---:|
| Paired unique binary candidates | 78 |
| No-RAG만 정답 | 6 |
| RAG만 정답 | 1 |
| McNemar exact two-sided p | 0.125 |
| 결론 | 유의한 RAG 우위 미입증 |

Grounded v2 41건에서 raw No-RAG는 abstain 39/not-applicable 2, grounded는 non-violation 32/violation 2/not-applicable 2/abstain 5였다. verifier 후 grounded final은 non-violation 12/violation 2/abstain 27이었다.

### 6. 검색 성능

| 지표 | 값 | 한계 |
|---|---:|---|
| MRR | 1.0000 | human-reviewed semantic seed 3 queries |
| Recall@3 | 0.7778 | LEA 9-unit bundle의 atomic unit 분모 영향 |
| Relevant/oracle bundle recall | 1.0000 | 3-rule seed |
| Irrelevant citation accept | 0/3 | 모두 fail-closed |
| Conflicting citation accept | 0/3 | 모두 fail-closed |
| Mapping integrity | exact-set/source/bundle/fail-closed 1.0 | verified registry 기계 무결성 |

세 질의만으로 일반 retrieval 정확도를 주장하지 않는다.

### 7. 인용·공식 근거 검증

| 지표 | 값 |
|---|---:|
| Grounded verifier pass | 14/41 (34.15%) |
| Entailment unconfirmed | 16/41 |
| Citation missing | 10/41 |
| Citation unknown | 1/41 |
| Atomic structural-valid | 16/41 (39.02%) |
| Independent semantic authorization | 0/41 |
| Current authenticated program fact | 0/45 |
| 0_KCMVP verified evidence bundle | 0/11 |

인용 ID가 존재하는 것과 근거가 판정을 지지하는 것을 분리했으며, semantic authorization은 아직 0이다.

### 8. 안정성·표현 민감도

| 지표 | 값 |
|---|---:|
| 3-view 완전 일치 | 219/265 (82.64%) |
| Artifact/minimal/opaque violation | 108 / 104 / 98 |
| RAG repeat identical | 147/147 (100%) |
| No-RAG repeat identical | 147/147 (100%) |
| 반복 변동 candidate | 0 |

반복 3회를 독립 표본으로 세지 않고 candidate-condition당 1행으로 collapse했다.

### 9. 데이터셋·규칙 층화

| 데이터셋 | 파일 | LOC | L1 후보 | 후보/KLOC |
|---|---:|---:|---:|---:|
| 합성 세트 1 | 4 | 478 | 62 | 129.707 |
| 합성 세트 2 | 4 | 449 | 61 | 135.858 |
| 합성 세트 3 | 4 | 579 | 53 | 91.537 |
| 합성 세트 4 | 4 | 466 | 49 | 105.150 |
| 상용 변형 세트 5 | 59 | 14,512 | 14 | 0.965 |
| 상용 변형 세트 6 | 59 | 14,511 | 13 | 0.896 |
| 상용 변형 세트 7 | 59 | 14,518 | 13 | 0.895 |
| 0_KCMVP 원본 | 59 | 14,511 | 11 | 0.758 |

0_KCMVP 원본 rule family는 COM-001 5, COM-004 3, LEA-007/044/062 각 1이다. 알고리즘별 precision/recall은 각 층의 GT가 없어 N/A이다.

### 10. 비용·속도

| 실험 | API 호출 | Input / output token | 평균 지연 | 추정 비용 |
|---|---:|---:|---:|---:|
| Grounded/No-RAG paired v2 | 82 | 41,325 / 9,074 | grounded 1,303.17 ms; no-RAG 1,185.39 ms | USD 0.0077621 |
| Atomic v3 | 41 | 47,743 / 8,725 | 1,317.86 ms | USD 0.0082643 |
| 0_KCMVP No-RAG | 9 | 1,645 / 732 | 1,098.61 ms | USD 0.0004573 |
| 7-set synthetic syntax | 0 | 0 / 0 | total 3,412.888 ms | USD 0 |

### 11. 최종 무결성 게이트

| 게이트 | 상태 |
|---|---|
| Clean commit·snapshot·rules·mapping·index hash | 통과/기록 |
| 조건별 분모 동일성 | paired v2 통과 |
| Duplicate/retry/missing | paired v2 0/0/0; 0_KCMVP 0/0/0 |
| Clone-group split | 248 groups, dev 174/held-out 74 동결 |
| 공개 경로·키·소스 누출 | 0 |
| 전체 테스트 | 857 passed, 1 skipped |
| 독립 인간 GT | 미충족(본 요청에서 제외) |
| Authenticated build context | 0/7, 미충족 |

즉 판정 성능, abstention, router, RAG 비교, retrieval, citation, stability, 층화, 비용·속도, 무결성을 모두 측정했다. 다만 독립 GT 및 인증 빌드 문맥이 없는 지표는 수치를 만들지 않고 N/A로 남겼다.

## 현재 L1 직접 재실행

| 지표 | 결과 |
|---|---:|
| C/H 파일 | 59 |
| 물리 LOC | 14,511 |
| L1 후보 | 11 |
| 후보 밀도 | 0.758건/KLOC |
| snapshot ID | `803ffef337aff9ce044d532b1242ae349ea2da637a82ef3e63e42dd782de0cbb` |

규칙별 분포는 COM-001 5건, COM-004 3건, LEA-007 1건, LEA-044 1건, LEA-062 1건이다. 총건수는 2026-05-19 논문 실험 기록의 11건과 일치하지만 rule ID 분포는 현재 ruleset 기준이다.

## 현재 router 및 공식 evidence

현 production router는 deterministic 0, AI-ready 0, hold 11이다. 해당 5개 rule family에 대한 verified official evidence bundle이 없으므로 안전 계약상 grounded AI 호출을 금지한 결과이다. cold router batch 3.317 ms, warm 5회 평균 2.867 ms, 중앙값 2.826 ms였다.

## 실험용 No-RAG AI 실측

운영 정책을 완화하지 않고 별도 실험 comparator로 selector 대상 9건을 Gemini 2.5 Flash-Lite, temperature 0으로 판정했다.

| 지표 | 결과 |
|---|---:|
| API 호출 | 9 |
| duplicate/retry | 0/0 |
| violation 라벨 | 3 |
| non-violation 라벨 | 6 |
| input/output token | 1,645 / 732 |
| 평균 지연 | 1,098.614 ms |
| 중앙 지연 | 1,110.690 ms |
| p95 nearest-rank | 1,234.897 ms |
| 추정 비용 | USD 0.0004573 |

정답 GT가 없으므로 3건을 TP, 6건을 FP 제거로 표현하지 않는다. 이 수치는 AI 라벨 분포이며 precision, recall, F1, L3 정확도가 아니다. grounded-RAG는 공식 evidence mapping 미완료로 실행 대상 0건이다.

## 산출물

- `backend/evaluation/public_smartcrypto_original_router.json`
- `backend/evaluation/public_smartcrypto_original_ai.json`
- private snapshot/AI ledger는 `/private/tmp`에 mode 0600으로 보존한다.
