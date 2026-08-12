# 최종 proxy 성능평가 통합 결과

## 평가 범위

논문의 저자 구축 자료를 두 층으로 분리한다. 세트 1–4는 의도적 위반을 삽입한 합성 자료이고, 세트 5–7은 KCMVP 제출용 상용 암호모듈 사례 사본/변형이다. 후자의 인증 상태를 개별 후보의 정답으로 간주하지 않는다. 정확도 지표는 동일 Gemini temperature-0 test-retest proxy GT와 완전 결합된 과거 동결 실험에서만 보고한다.

## 현재 7세트 L1 및 후보 밀도

| 세트 | 유형 | 파일 | 물리 LOC | L1 후보 | 후보/KLOC |
|---:|---|---:|---:|---:|---:|
| 1 | 합성 위반 | 4 | 478 | 62 | 129.707 |
| 2 | 합성 위반 | 4 | 449 | 61 | 135.858 |
| 3 | 합성 위반 | 4 | 579 | 53 | 91.537 |
| 4 | 합성 위반 | 4 | 466 | 49 | 105.150 |
| 5 | 실제 모듈 사례 | 59 | 14,512 | 14 | 0.965 |
| 6 | 실제 모듈 사례 | 59 | 14,511 | 13 | 0.896 |
| 7 | 실제 모듈 사례 | 59 | 14,518 | 13 | 0.895 |

총 193개 소스, 265개 후보이다. 실제 모듈의 후보 밀도는 정성적 사례 지표이며 precision이 아니다.

## 현재 단계형 라우팅

265건 중 deterministic 30건(11.32%), AI-ready 45건(16.98%), hold 190건(71.70%)이다. 공식 evidence bundle과 atomic contract는 AI-ready 45건에 존재하지만 authenticated program fact는 0건이므로 현재 end-to-end 정확도는 계산하지 않는다. 합성 C11 구문 검사는 114 translation unit 중 29건(25.44%)만 통과했으며, 원 빌드 성공률이 아니다.

## 과거 proxy GT 기반 탐색 지표

- GT 분포: violation 104, non-violation 18, insufficient-context 30, not-applicable 113.
- binary eligible 122건 중 routing coverage: deterministic 23, AI-ready 26, hold 73.
- hold 190건 중 proxy violation 63건이므로 hold를 정답으로 세지 않는다.
- post-selector pooled-condition held-out 46행: precision 0.8571, recall 0.9000, F1 0.8780, TP 36, FP 6, FN 4, TN 0. clone-group bootstrap F1 95% CI [0.7733, 0.9545]. 양 조건·고유 후보를 pooled한 탐색 수치이며 전체 L1 성능이 아니다.
- RAG/no-RAG 고유 binary 후보 78건: no-RAG만 정답 6, RAG만 정답 1, McNemar exact p=0.125. 유의한 차이를 입증하지 못했다.

## Grounded verifier·비용·시간

AI-ready 41건 paired v2에서 grounded verifier pass는 14/41(34.15%), 최종 abstain은 27/41이었다. no-RAG는 evidence 미제공으로 41/41 abstain이었다. 물리 API 호출 82건, input 41,325 token, output 9,074 token, 추정 비용 USD 0.0077621이며 duplicate/retry는 0이었다. grounded 평균 지연은 1,303.17 ms, no-RAG 평균은 1,185.39 ms였다.

## 근거 검색·안정성·결론

공식 evidence seed 3개 rule 검색에서 relevant/oracle bundle recall 1.0, MRR 1.0, Recall@3 0.7778이었고 irrelevant/conflicting 근거는 0/3 수용, 3/3 abstain이었다. 이는 3-query human-reviewed seed에 한정된다. 3-view 표현 안정성은 219/265(82.64%) 완전 일치였다. 반복 score는 조건별 147건에서 변동 0으로 결정적이었으며, 반복행을 독립 표본으로 세지 않았다.

현재 결과는 동일 모델 proxy GT에 대한 동결 탐색 평가이다. 4-class accuracy, macro-F1, 현재 파이프라인 end-to-end accuracy, 실제 모듈 precision/recall/F1은 현재 스냅샷과 proxy GT의 candidate identity 1건 불일치 및 독립 인간 GT 부재로 미측정으로 남겨 둔다.

## 무결성

라벨 독립 clone split은 248 group을 development 174 group/189건, held-out 74 group/76건으로 동결했다. 공개 산출물은 집계와 SHA-256만 포함하고 소스, 절대경로, API key, 비공개 occurrence ID를 포함하지 않는다.
