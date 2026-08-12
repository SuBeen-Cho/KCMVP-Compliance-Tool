# KCMVP 논문·프로젝트 수정 시사점

이 폴더는 리뷰 대응 과정의 결정, 검증 근거, 실행 결과와 남은 위험을 단계별로 기록한다.
각 문서는 구현 내용뿐 아니라 독립 감사, 테스트 결과, 논문에 사용할 수 있는 주장 범위를 구분한다.

최신 탐색 평가는 [30_동일모델_프록시GT_3view_RAG보정_결과.md](30_동일모델_프록시GT_3view_RAG보정_결과.md)에 기록한다. 이 결과는 동일 모델 test–retest 프록시이며 외부 전문가 GT 성능으로 해석하지 않는다.
공식 PDF evidence-unit 인덱스, fail-closed 매핑, adaptive router와 인용 검증의 구현·한계는 [31_공식_Evidence_RAG_고도화_구현과_검증.md](31_공식_Evidence_RAG_고도화_구현과_검증.md)에 기록한다.
동일 counterfactual의 no-RAG·verified oracle·무관 공식 근거 LLM 교차 실험은 [35_공식Evidence_RAG_LLM_utility_교차실험.md](35_공식Evidence_RAG_LLM_utility_교차실험.md)에 기록한다.
AES·ARIA·SEED의 FIPS·RFC·ISO 외부 일차 출처, hash-bound registry, 저작권 정책과 fail-closed 매핑 후보는 [36_AES_ARIA_SEED_외부공식출처_감사.md](36_AES_ARIA_SEED_외부공식출처_감사.md)에 기록한다.
AI 필요도를 결정적 판정·공식 근거 검색·근거 검증·AI 판정·보류로 분리한 폐쇄형 단계 계약과 오프라인 성능평가는 [38_AI_필요도_게이팅_단계형_파이프라인_성능평가.md](38_AI_필요도_게이팅_단계형_파이프라인_성능평가.md)에 기록한다.
265건 과거 동결 후보에 현재 단계형 정책을 재생한 routing·지연시간 결과와 동일 모델 proxy 라벨 층화는 [39_265건_historical_stage_boundary_성능평가.md](39_265건_historical_stage_boundary_성능평가.md)와 [39_265_proxyGT_단계형_router_selective_성능평가.md](39_265_proxyGT_단계형_router_selective_성능평가.md)에 기록한다. 두 결과는 historical-policy replay이며 현재 end-to-end 정확도가 아니다.

## 단계

1. 실험 기준 코드와 재현성 기반
2. canonical 결과 체계
3. 수치·산정 방식 교정
4. L2 독립 ablation
5. 비용·시간·토큰 계측
6. confidence calibration
7. AES·SEED 일반화
8. 제3자 blind labeling
9. MDPI 원고 수정
10. reviewer response 및 최종 검증
11. AES·SEED 평가 자료 후보와 고정 출처
12. 논문 수정추적본 완전성 검증

## 2026-08-11 현재 완료 상태

- 구현 및 정적 검증: 현재 스냅샷의 규칙 inventory는 166개(코드 지향 97개, 문서 65개, 추적성 4개)이며, 산술 감사, GT 주석 제거, no-RAG 경로, 실행 manifest, 토큰 카운터, confidence 입력 검증, L3 fail-fast를 반영했다. AES 3개, ARIA 1개, SEED 1개의 보수적 명시 모순 규칙과 KCMVP CMAC 인증값 길이 규칙 1개가 포함되지만 알고리즘별 일반화 성능은 아직 입증되지 않았다.
- 테스트: backend 현재 회귀 `589 passed, 1 skipped`; frontend Vite production build 310 modules 통과; MDPI PDF 24쪽 재컴파일 성공.
- 과거 결과: 코드·입력·프롬프트를 묶는 manifest가 없어 `legacy_unverified`로만 유지한다.
- 실제 재실행: 동일한 동결 L1 후보 161개에 대해 RAG/no-RAG를 3 pair·6회 AB/BA로 실행하였다. 총 1,014회 호출과 Standard 단가 기준 추정 API 토큰 비용 `$0.3494106`을 기록하였다. 다만 파일명·식별자 label leakage가 남아 탐색적 조건 비교로만 유지한다.
- 알고리즘 구현체: 고정된 OpenSSL·Botan·Crypto++·Mbed TLS를 직접 빌드·링크하여 AES·SEED·ARIA 공개 벡터 28/28 일치를 재현하였다. 이는 KCMVP 인증 또는 정적 규칙 준수 증명이 아니다.
- 외부 검증: 제3자 blind annotator와 occurrence 단위 정답이 없어 일반화, 독립 정확도 검증 및 threshold 보정은 미완료다.
- 제출 원칙: 위 세 종류의 미완료 결과를 완료된 실험으로 표현하지 않는다. 현재 수정본은 범위를 LEA 중심의 feasibility study로 제한한다.

## 다음 실행 게이트

1. `violations_*`, `wrong_*`, `no_zeroize` 등의 정답 단서를 중립적 식별자로 변환한 blind corpus를 만든다.
2. 두 명 이상의 blind annotator가 occurrence 단위 candidate를 독립 라벨링하고 합의 전 원라벨을 보존한다.
3. 점수 계약과 counterfactual 재판정 coverage를 완성한 뒤 개발/보류 분리 threshold calibration을 수행한다.
4. AES·SEED·ARIA의 정상/변조 corpus와 occurrence 정답을 구축하여 알고리즘별 confusion matrix를 산출한다.
5. 실행 bundle의 manifest, 입력·출력 hash, 비용 단가 snapshot, 실행 로그를 함께 동결한 뒤에만 논문 성능 수치를 교체한다.
# 추가 실험 기록

- [42_AI-ready_41건_canonical_verifier_v2_재실행.md](42_AI-ready_41건_canonical_verifier_v2_재실행.md): canonical decision 보존, 수정 verifier 실측 및 API 없는 replay 결과
- [43_HEAD252e756_sets1-7_L1_신규snapshot.md](43_HEAD252e756_sets1-7_L1_신규snapshot.md): 현재 코드에 결합된 265건 L1 snapshot과 30/41/194 단계 분포
- [44_atomic_claim_v3_구조계약_탐색실험.md](44_atomic_claim_v3_구조계약_탐색실험.md): 41건 atomic evidence 구조 준수 실험과 의미 승인 0건, partial provenance 한계
- [45_program_fact_sealed_shadow_baseline.md](45_program_fact_sealed_shadow_baseline.md): 인증된 프로그램 사실 0/41 기준선과 LEA-011 보수적 extractor 경계
