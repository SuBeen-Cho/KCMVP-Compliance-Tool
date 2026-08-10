# Threshold calibration 하네스와 현행 자료 감사

## 결론

현재 보존된 탐색적 RAG/no-RAG 결과만으로는 65~74 재판정 구간이나 최종 판정 임계값을 보정할 수 없다. 따라서 기존 65~74 구간은 검증된 최적값으로 주장하지 않으며, 새 반복실험에서 후보별 `violation_probability`와 정답 라벨을 수집한 이후 개발 세트에서만 선택하고 고정된 held-out 세트에서 한 번 평가한다.

## 기존 자료 감사

- `/tmp/kcmvp-l2-rag-91cf6c4.json`과 `/tmp/kcmvp-l2-no-rag-91cf6c4.json`을 구조적으로 검사한 결과, 이름에 `confidence`가 포함된 scalar 경로는 각각 0개였다.
- 두 결과에는 세트별 집계와 제거 후보 정보가 있으나, 모든 후보의 1차·재판정 점수가 존재하지 않는다.
- 코드 L3 요청 원장 schema v2는 후보 ID·prompt·response의 해시와 토큰 메타데이터만 저장한다. 원 응답이나 점수를 해시로부터 복원할 수 없다.
- 그러므로 현재 자료를 이용한 Brier score, ECE, threshold/window sweep은 식별 불가능하다. 후보별 점수를 추정하거나 집계값을 후보 점수로 확장하지 않는다.

## 점수 의미와 폐쇄형 스키마

신규 스키마는 점수 의미를 `violation_probability`로 고정한다. 0은 준수 확실, 100은 위반 확실을 의미한다. 이는 “모델이 출력한 verdict에 대한 확신도”와 다르다. `not_violation`이면서 확률이 50보다 크거나 `violation`이면서 50보다 작은 상충 행은 즉시 거부한다.

정식 JSON Schema는 `backend/evaluation/calibration_dataset.schema.json`에 둔다. 실행 시 Python 검증기는 최상위 및 행·판정 객체의 미지 필드를 거부하고, 중복 observation ID, 범위 밖 점수, 비정수 점수, 잘못된 정답형, 상충 verdict를 거부한다.

`group_id`에는 동일 구현체·파일 계열 또는 동일 원천에서 파생되어 누출 위험이 있는 후보군을 부여한다. 동일 그룹은 개발 세트와 held-out 세트로 나뉘지 않는다. 반복 횟수와 RAG 조건은 occurrence 단위로 별도 행에 기록한다.

## 선택 및 평가 절차

1. 전체 그룹을 고정 salt의 SHA-256 순위로 결정론적으로 개발/held-out으로 분리한다.
2. 개발 세트에서 threshold와 재판정 window의 사전 정의 grid를 탐색한다.
3. 최소 재현율 제약을 만족하는 정책만 남긴다.
4. 개발 세트 정밀도, F1, 재판정 호출 수 순으로 정책을 선택한다.
5. 선택된 정책을 변경하지 않고 held-out 세트에서 한 번 평가한다.
6. held-out 그룹 bootstrap으로 정밀도·재현율·F1의 95% 구간을 산출한다.
7. 개발 그룹 bootstrap에서 선택 정책 빈도를 산출하여 선택 안정성을 보고한다.

재판정 window에 포함된 행의 2차 판정이 하나라도 누락되면 해당 분석은 실패한다. 이를 통해 window별 결측 자료가 유리한 후보만 포함하는 편향을 방지한다.

## 오프라인 실행 예

```bash
cd backend
python scripts/calibrate_threshold.py evaluation/calibration_rows.json \
  --output evaluation/calibration_report.json \
  --threshold 50 --threshold 55 --threshold 60 --threshold 65 \
  --window none --window 55:64 --window 65:74 --window 75:84 \
  --minimum-recall 1.0 --heldout-fraction 0.3 \
  --bootstrap-iterations 2000 --seed 42
```

이 명령은 외부 API를 호출하지 않으며 API 키 인자를 제공하지 않는다.

## 검증 결과

- 신규 threshold calibration 및 기존 연구 지표 단위 테스트: `11 passed`
- CLI 정상 입력 보고서 생성, 잘못된 score semantics 거부, 폐쇄형 스키마 거부, 상충 verdict 거부, 그룹 간 분리, 누락 재판정 거부를 검증하였다.

## 논문 반영 조건

현재 단계에서는 “65~74가 최적”이라고 기술하지 않는다. 동일 동결 L1 후보의 반복실험 결과에 occurrence별 1차·2차 `violation_probability`가 완전하게 저장되고, 독립 정답 라벨과 그룹 정보가 결합되며, 위 절차의 held-out 결과와 불확실성 구간이 산출된 이후에만 선택 임계값을 논문 성능 주장에 반영한다.
