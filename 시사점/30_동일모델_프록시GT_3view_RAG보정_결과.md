# 동일 모델 프록시 GT·3-view·RAG 보정 탐색 결과

## 1. 결론과 주장 범위

본 실험은 동결된 265건의 occurrence에 대해 동일 `gemini-2.5-flash-lite`를 temperature 0으로 두 번 실행한 테스트–재테스트 합의를 프록시 GT로 삼아 3-view 민감도, RAG/no-RAG 차이 및 threshold 보정 절차를 탐색한 결과이다. 두 판정은 모델, temperature, prompt 및 입력이 동일한 test–retest이며, 독립된 AI 라벨러 2명이나 외부 전문가 정답이 아니다. 따라서 본 결과는 파이프라인의 실행 가능성과 내부 안정성을 점검하는 탐색적 프록시 평가이며, 외부 타당도를 갖는 precision·recall·F1 성능 추정으로 사용하지 않는다.

또한 보정 결과는 L1 265건 전체가 아니라 RAG와 no-RAG에서 모두 점수가 확정된 **post-selector 공통 부분집합**에만 해당한다. 이 결과를 whole-L1 탐지 성능으로 확장해석하지 않는다.

## 2. 프록시 GT 구성

최소 단서 통제 뷰 `minimal_cue_controlled` 265건을 동일 모델로 두 번 판정하였다. A와 B는 265건 모두에서 라벨이 일치하여 표면적 일치율과 Cohen's κ가 모두 1.0이었다. 그러나 이 일치는 동일 결정적 실행의 재현성을 나타낼 뿐, 판정자 간 독립적 합의를 나타내지 않는다. 라벨 분포는 위반 104건, 비위반 18건, 문맥 불충분 30건, 요구사항 비적용 113건이다.

- proxy GT ID: `f8256fafac9c62d2800a01c63e5761b1d9bf94de73294be7d1e4888ad3ac3587`
- 판정 기반: same-model, temperature-0 test–retest proxy
- 이진 보정 적용 가능 라벨: 위반·비위반 122건
- 보정에서 제외한 라벨: 문맥 불충분 30건, 비적용 113건

## 3. 3-view 민감도

동일한 265 occurrence를 다음 세 뷰로 판정하였다. 전체 라벨이 세 뷰에서 모두 일치한 경우는 219건, 즉 82.64%이다.

| 뷰 | 위반 | 비위반 | 문맥 불충분 | 비적용 |
|---|---:|---:|---:|---:|
| `analysis_artifact_aware` | 108 | 13 | 22 | 122 |
| `minimal_cue_controlled` | 104 | 18 | 30 | 113 |
| `fully_opaque` | 98 | 14 | 31 | 122 |

쌍별 정확 일치율은 artifact-aware–minimal 88.68%(235/265), artifact-aware–opaque 86.04%(228/265), minimal–opaque 89.81%(238/265)이다. 함수명·식별자를 보존한 artifact-aware 뷰에서 위반 판정이 가장 많고, opaque 뷰에서 위반 판정이 10건 감소하고 문맥 불충분이 9건 증가하였다. 이는 명명 정보가 판정에 영향을 준다는 민감도 신호이다. 다만 이 차이는 어느 뷰가 사실적으로 더 정확한지를 입증하지 않으며, opaque 뷰를 주 성능 평가로 사용해야 한다는 근거도 아니다.

## 4. RAG/no-RAG 3-pair 교차 실험

동결 snapshot을 공유하고 seed 42–44를 적용하여 RAG→no-RAG, no-RAG→RAG, RAG→no-RAG 순서로 3쌍·6회를 실행하였다. 각 조건의 세 번 반복은 결과가 동일하여 확률적 독립 반복으로 계수하지 않았다.

| 조건 | 선택 | 유지 | 제거 | 미해결 | 요청 포함 후보-반복(`request_covered`) |
|---|---:|---:|---:|---:|---:|
| RAG 3회 | 161×3 | 137×3 | 10×3 | 14×3 | 477 |
| no-RAG 3회 | 161×3 | 135×3 | 12×3 | 14×3 | 471 |

원장에 기록된 provider call은 재시도를 포함하여 1,006회이며, 입력 2,142,273토큰과 출력 304,599토큰이 사용되었다. 2026-08-11 Standard 단가 snapshot인 입력 100만 토큰당 0.10달러, 출력 100만 토큰당 0.40달러를 적용한 추정 API 토큰 비용은 0.3360669달러이다. 이 금액은 실제 청구액이 아니며, 무료 티어·로컬 연산·전력 비용을 포함하지 않는다.

반복을 제거하고 고유 후보로 축약한 이진 비교 부분집합은 78건이다. threshold 50에서 no-RAG만 정답인 경우는 6건, RAG만 정답인 경우는 1건이며, 양측 McNemar exact two-sided `p=0.125`이다. 따라서 현재 자료로는 RAG 조건의 유의한 정확도 개선을 확정하지 않는다. 또한 clone group 내 상관이 남아 있으므로 이 p값은 독립적 확증 검정으로 사용하지 않는다. 3회 반복을 occurrence-repeat로 계수한 234쌍의 18:3, `p=0.0014896`은 의사반복을 포함하므로 설명적 참고값에 한정한다.

## 5. Threshold 보정과 분리 평가

반복 결과를 독립 표본으로 계수하지 않기 위해 고유 후보로 축약하고, RAG와 no-RAG 조건을 풀링한 탐색적 post-selector 보정을 수행하였다. 고유 후보 78건은 조건 풀링 후 156건의 점수–라벨 관측치를 구성한다. clone group 기반으로 개발 53개 그룹·110건과 보류 23개 그룹·46건을 분리하였다. 보류 세트는 고유 후보 단위로 23건이며, 각 후보에 대한 RAG/no-RAG 두 조건으로 인해 46건으로 계수된다.

개발 세트에서 최소 recall 0.90 제약을 적용하여 0–100을 5간격으로 탐색한 결과 threshold 75를 선택하였다.

| 분할 | n | TP | FP | TN | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 개발 | 110 | 88 | 10 | 4 | 8 | 0.8980 | 0.9167 | 0.9072 |
| 보류 | 46 | 36 | 6 | 0 | 4 | 0.8571 | 0.9000 | 0.8780 |

보류 그룹 bootstrap 500회의 95% 구간은 precision [0.6889, 1.0000], recall [0.7763, 1.0000], F1 [0.7733, 0.9545]이다. Brier score는 0.1837, expected calibration error는 0.1500이다. 개발 bootstrap에서 threshold 75의 선택 빈도는 500회 중 287회(57.4%)에 그쳤으며, threshold 0이 171회, 80이 35회, 10이 7회 선택되었다. 따라서 75는 단일 최적값으로 확정하기에 안정성이 부족하다.

보류 세트에서 TN이 0이며, 프록시 음성 6건이 모두 FP로 분류되었다. 이 구성에서 specificity와 음성 일반화를 평가할 수 없으며, 위반 중심의 라벨 불균형으로 precision·F1이 낙관적으로 보일 수 있다. no-RAG와 RAG의 점수 반복 안정성은 각각 완전 반복 후보 147건 중 147건 동일하여 100%이었으나, 이 결과 또한 temperature 0 동일 모델의 결정적 안정성으로만 해석한다.

## 6. 재현성과 provenance 판정

주요 산출물은 SHA-256으로 무결성을 확인하였다.

| 산출물 | SHA-256 |
|---|---|
| 동결 3-view private packet | `2c0659ce7bcea1db3a968880461adf4e1c422a45877fe2d0ea4145ffe8a7d98f` |
| grouped sidecar | `c34381dc8aaac39ceea2b00d76b06c63a16d22694376feba6cc6c7c56ed81cdf` |
| proxy GT | `a42b9e40f42f007b22881413feec3c51d55df7752f253552fcccb1f8941ce9ab` |
| 3-view cross-view report | `9a4ca91dc4bd27ae1d994fd5b7493641ac4c4435f1274b29d72d7c6ee32f3e3c` |
| 3-pair 보정 결과 | `6b84590151d89bc8afac3193327cc992c47aad27f0529d6015d83335680d34c8` |
| 고유 후보 보정 결과 | `6bf93abfde5aa69d22309d1e45a0c24f711932525bf369ea2e4c12502b2a2cee` |
| paired run manifest | `b39774ffa3d2e70dbb4f9b88e4f299f93ce9486b7f67b7d51ab71700f9f07b61` |

다만 paired run manifest는 snapshot·result·ledger 해시와 실행 설계를 보존하지만, 현재 스키마에는 실험 시점의 코드 commit 바인딩이 없다. 따라서 고유 후보 보정 산출물의 상태는 `provisional_missing_paired_manifest_code_commit_binding`으로 유지한다. 최종 논문 성능표에 반영하려면 코드 commit, 동결 packet, prompt 버전, 실행 원장 및 단가 snapshot을 단일 manifest에 바인딩한 후 외부 전문가 GT로 재실행해야 한다.

## 7. 해석 및 후속 게이트

1. 3-view 일치 219/265는 대부분의 판정이 뷰 변환에 안정적이지만, 46건은 명명·문맥 제거에 민감하다는 점을 나타낸다. 이 46건을 외부 조정 우선 표본으로 사용한다.
2. 고유 후보 McNemar 결과 6:1, `p=0.125`이므로 RAG 정확도 향상을 확정하지 않는다. clone group 단위 표본 확대와 cluster-aware 검정이 필요하다.
3. threshold 75는 탐색적 선택값이며 bootstrap 선택 안정성과 음성 표본이 부족하다. 연속적인 음성 확률을 보정하는 값으로 간주하지 않는다.
4. 현재 proxy split은 held-out 결과까지 이미 공개되었으므로 외부 GT 확증 평가에 재사용하지 않는다. 외부 GT를 열람하기 전에 sealed 265 occurrence 전체의 clone group을 단위로, 라벨과 무관한 새 dev/held-out 배정 규칙·salt·ID manifest를 사전등록하고 동결해야 한다. 이후 각 분할 안에서 외부 GT가 위반 또는 비위반으로 확정한 binary-eligible occurrence만 성능 분모에 포함하고, threshold를 dev에서 선택·고정한 다음 새로 봉인한 confirmatory held-out을 단 한 번만 평가한다.
5. 본 문서의 수치는 탐색적 프록시 결과로만 인용하며, KCMVP 준수 성능이나 외부 일반화 성능의 증거로 서술하지 않는다.
