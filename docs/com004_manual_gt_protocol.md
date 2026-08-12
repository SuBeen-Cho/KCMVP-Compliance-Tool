# COM-004 clone-disjoint GT 사전등록

현재 16 occurrence는 10 clone group으로 구성되며, 중복 occurrence를 독립 표본으로 계수하지 않는다. 인간 판정은 minimal-cue view의 clone-group 대표에 대해 2명이 독립적으로 시행하고, 불일치는 제3 검토자 또는 문서화된 합의로 해소한다. 동일 모델의 temperature-0 반복 결과는 GT로 사용하지 않는다.

라벨을 보기 전에 clone-group 단위 dev/held-out 분할을 동결한다. authenticated preprocessing coverage 95% 이상, reviewer kappa 0.8 이상, citation entailment 95% 이상이 되기 전에는 accuracy/F1을 보고하지 않는다. production 승격 게이트의 목표 오탐률은 2% 이하이며, 현 소표본에서 이 수치를 입증할 수 없으므로 외부 확장 fixture가 필요하다.
