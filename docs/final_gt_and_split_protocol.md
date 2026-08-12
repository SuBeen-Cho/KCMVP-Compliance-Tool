# 최종 GT 및 clone-group 분할 프로토콜

265 occurrence 전체를 라벨을 열람하기 전 clone group 단위 development/held-out으로 동결한다. 같은 group은 절대 두 분할에 나누지 않는다. 공개 산출물은 분할 hash와 분모만 포함하고 occurrence 배정표는 mode 0600 private artifact로 보존한다.

최종 GT는 minimal cue-controlled view에서 독립 인간 리뷰어 2명이 각각 4-class(`violation`, `non_violation`, `insufficient_context`, `not_applicable`)로 판정한다. 서로의 라벨은 제출 완료 전 비공개하고, 불일치만 제3의 조정자가 근거 locator와 함께 확정한다. Claude/Gemini 기반 `ground_truth_design.json`과 동일 Gemini test-retest proxy는 보조 분석으로만 유지하고 최종 GT에 합치지 않는다.
