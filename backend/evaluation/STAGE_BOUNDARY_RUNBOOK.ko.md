# L2→L3 경계 오프라인 실측

이 실험의 목표는 AI 호출을 늘리는 것이 아니라, 운영 코드의 `run_l2_rag_context`가 생성한 닫힌 계약이 L3 진입 직전에서 어떻게 분포하는지 재현하는 것이다. 스크립트는 LLM 함수를 호출하지 않는다.

```bash
cd backend
tmp_dir=$(mktemp -d)
python -m experiments.stage_boundary_adapter \
  evaluation/stage_boundary_candidate_fixtures.json \
  --work-dir "$tmp_dir" \
  -o evaluation/stage_boundary_observations.json
python -m experiments.staged_pipeline_eval \
  evaluation/stage_boundary_observations.json \
  -o evaluation/stage_boundary_result.json
```

`retrieval`은 공식 근거가 확인되어 AI 판단을 요청할 수 있는 경계 상태이지, AI가 실제 호출됐다는 뜻이 아니다. 따라서 어댑터는 이 사례의 `actual_llm_calls` 및 `baseline_llm_calls`를 0으로 남겨 연기된 호출을 “회피”로 과대 계산하지 않는다.

`controlled_ablation` 사례는 중요한 안전 회귀다. RAG를 끄면 운영 계약은 `hold + AI prohibited`가 되어야 한다. 이를 “no-RAG LLM” 조건과 같은 것으로 표본하면 retention-only 조건을 AI 실험으로 오해하게 된다. 비근거 AI ablation이 반드시 필요하면 운영 모듈이나 일반 환경변수를 열지 말고, 라벨된 별도 실험 runner에서만 비용·정확도 비교를 수행한다.
