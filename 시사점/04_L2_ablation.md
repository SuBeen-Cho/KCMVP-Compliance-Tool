# 4단계: L2 독립 ablation

## 구현

- `ABLATION_NO_RAG=1`이면 prompt retrieval, L2 context injection, final evidence attachment를 모두 비활성화한다.
- RAG 제외 시 stale evidence가 남지 않도록 빈 문자열과 `rag_ablation=true`를 기록한다.
- 단위 테스트는 검색 함수가 호출되면 실패하도록 구성했다.

## 필요한 paired run

- 동일 L1 후보, 모델, temperature=0, seed=42, 프롬프트 정책을 고정한다.
- baseline과 no-RAG를 최소 3회 반복한다.
- TP/FN/FP, 판정 flip, evidence 적합성, McNemar 또는 paired bootstrap CI를 보고한다.

## 실행 상태

2026-08-11 재실행에서 구성된 API 키가 `API_KEY_INVALID`를 반환했다. 실행을 중단했으며 새 성능 수치는 생성하지 않았다.
