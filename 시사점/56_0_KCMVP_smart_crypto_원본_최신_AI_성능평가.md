# 0_KCMVP smart-crypto 원본 최신 AI 성능평가

## 입력 확정

활성 저장소 job storage에 보존된 `smart-crypto-master.zip` 3개를 검사했고 모두 바이트 단위 SHA-256 `3f4b865efe9350753119857918ac7addd1b012171f899defa6a36a415817de93`로 동일했다. 원본은 C 34개, H 25개, 총 59개 C/H 파일과 14,511 물리 LOC를 포함한다. 세트 5–7은 원본과 `src/lea.c`, `src/cipher.c`가 서로 다른 변형이므로 이 실험에서 대리 입력으로 쓰지 않았다.

## 논문·과거 실험 기록 감사

- 2026-05-02 보고: L1 29건, L3 2건 제거, 최종 27건, 1.86건/KLOC.
- 2026-05-19 GPT-4.1-mini 보고: C 파일 34개, L1 11건, L3 처리 10건, 최종 11건, 172초.
- 더 이전 저장 JSON은 규칙 버전에 따라 107–166건을 기록한다.

이 편차는 과거 실행이 불변 code/input/prompt manifest와 결합되지 않았음을 보여준다. 따라서 수정 논문의 기존 0.58건/KLOC 및 과거 실행 수치는 현재 스냅샷의 성능 주장에 합치지 않는 다.

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
