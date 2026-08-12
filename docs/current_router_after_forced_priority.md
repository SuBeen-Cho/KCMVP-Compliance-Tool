# forced-in 보정 후 clean router 재평가

clean commit `8023f85` 기준으로 sets 1–7 L1 snapshot 265건을 재생성했다. selector 내부 선택 합계는 173건으로, forced-in 21건이 cap에 의해 손실되지 않았다. 다만 공식 근거·stage contract까지 통과한 최종 분포는 deterministic 30, AI-ready 45, hold 190으로 기존과 같다.

따라서 이 보정은 민감 후보의 silent drop을 제거했지만, 근거 없는 AI 호출을 추가하지 않았다. API 호출은 0이며 정확도 주장은 하지 않는다. warm batch 평균은 596.93ms, median 588.46ms, p95 631.62ms였다.
