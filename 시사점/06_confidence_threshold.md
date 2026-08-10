# 6단계: confidence threshold와 재판정 구간

- 기존 65~74 재판정 범위는 코드에 구현되어 있으나 선택 근거 데이터가 없다.
- `experiments.calibration`에 Brier score, ECE, window sweep을 추가했다.
- 최종 분석은 개발 세트에서 구간을 선택하고 고정된 테스트 세트에서 검증해야 한다.
- 비교 구간 예: 55~64, 65~74, 75~84. 각 구간의 오류 포착 수, 추가 호출 수, FN/FP 변화를 보고한다.
- raw per-candidate confidence/GT가 없는 aggregate JSON만으로는 calibration을 계산하지 않는다.
