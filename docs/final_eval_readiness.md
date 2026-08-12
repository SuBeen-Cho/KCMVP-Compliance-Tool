# 최종 성능평가 준비도 게이트

7개 ZIP을 직접 검사한 결과, 세트 1–4는 C/H 소스만 있다. 세트 5–7은 각각 build 관련 파일 4개를 포함하지만, 루트 build definition/compile database가 아닌 하위 CMake 조각과 과거 절대경로가 박힌 생성 Makefile이다. 따라서 “build 파일 존재”는 3/7이지만 authenticated compile-context 재구성 가능은 0/7이다. 임의 Clang 옵션은 synthetic shadow로만 표시한다.

최종 accuracy/F1/McNemar는 7세트 build manifest, 독립 인간 GT, authenticated program-fact coverage 95%, citation entailment 95%, clone-disjoint split 동결이 모두 통과할 때만 허용한다. 현 상태의 결정은 `continue_priority_development`이다.
