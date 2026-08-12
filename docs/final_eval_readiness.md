# 최종 성능평가 준비도 게이트

7개 ZIP을 직접 검사한 결과, 세트 1–4는 C/H 소스만 있고 build manifest가 없으며 세트 5–7은 각각 4개의 build manifest 파일을 포함한다. 현재 build-context 외형 coverage는 3/7이며, 세트 5–7도 컴파일러·인자·include graph·macro·출력이 재실행 후 일치해야 authenticated context로 승격한다. 세트 1–4에 임의 Clang 옵션을 부여하는 경우는 synthetic shadow로만 표시한다.

최종 accuracy/F1/McNemar는 7세트 build manifest, 독립 인간 GT, authenticated program-fact coverage 95%, citation entailment 95%, clone-disjoint split 동결이 모두 통과할 때만 허용한다. 현 상태의 결정은 `continue_priority_development`이다.
