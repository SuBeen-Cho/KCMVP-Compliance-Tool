# 265건 proxy GT 단계형 router 선택적 성능평가

## 평가 성격

본 평가는 동결된 과거 265 occurrence에 현재 단계형 정책을 재생한 탐색적 평가이다. 참조 라벨은 `gemini-2.5-flash-lite`, temperature 0, 동일 prompt와 동일 입력을 두 번 실행하여 완전 일치한 라벨이다. 두 실행은 같은 모델의 test–retest이므로 독립 판독자가 아니며 인간 전문가 정답도 아니다. 따라서 아래 수치는 현재 end-to-end 시스템의 precision·recall·F1 또는 외부 일반화 성능으로 주장하지 않는다.

현재 stage contract의 `deterministic`는 routing disposition만 기록하고 `violation`/`non_violation` final verdict를 기록하지 않는다. 따라서 이 재생에서는 결정적 층의 정확도를 임의로 산출하지 않고 `null`로 둔다. `ai_ready`는 공식 evidence를 검증하여 AI 호출을 허가한 상태일 뿐 아직 판정하지 않은 상태이고, `hold`는 근거 부족으로 호출과 판정을 금지한 상태이다.

## 결과

전체 265건의 proxy 라벨은 위반 104건, 비위반 18건, 문맥 불충분 30건, 비적용 113건이다. 단계별 분배는 다음과 같다.

| 단계 | 건수 | 전체 coverage |
|---|---:|---:|
| 결정적 판정 | 30 | 11.32% |
| AI-ready | 8 | 3.02% |
| hold | 227 | 85.66% |

위반·비위반으로 확정된 binary-eligible 122건만 보면 결정적 routing 23건(18.85%), AI-ready 3건(2.46%), hold 96건(78.69%)이다.

결정적 routing 30건은 모두 parser가 확인한 구조적 근거 경로이다. 그러나 final verdict가 없으므로 21건의 proxy `violation`, 2건의 `non_violation`, 7건의 `insufficient_context`는 층화 분포로만 보고한다.

- abstention 제외 결정적 정확도: 산출 불가(`null`, final verdict 미기록)
- selective risk: 산출 불가(`null`, final verdict 미기록)
- binary 모집단 중 결정적 coverage: 23/122 = 18.85%

hold 227건의 proxy 분포는 위반 81건, 비위반 15건, 문맥 불충분 22건, 비적용 109건이다. hold는 정답으로 세지 않는다. 특히 proxy 위반 81건이 hold에 있다는 점은 fail-closed 안전성과 탐지 coverage 사이의 비용을 보여준다.

AI-ready 8건의 proxy 분포는 위반 2건, 비위반 1건, 문맥 불충분 1건, 비적용 4건이다. 이들은 retrieval과 선택 게이트를 통과했을 뿐 실제 LLM을 호출하지 않았다. 따라서 원문 span·locator·entailment를 모두 통과한 final-decision verifier coverage는 이 재생에서 0/265이며 정확도는 `null`이다.

## 해석과 다음 측정

현재 정책은 전체를 자동 판정하는 시스템이 아니다. 공식 근거와 selector를 통과해 AI로 넘길 수 있는 사례도 전체 8건에 불과하고 227건은 의도적으로 fail-closed 된다. 즉 현재 병목은 AI 모델의 호출 횟수가 아니라 rule-to-source 검증 coverage이다. 또한 정확도를 계산하려면 stage contract에 검증 가능한 final verdict와 그 근거를 추가해야 한다.

다음 확증 평가는 외부 전문가 occurrence 라벨을 확정하기 전에 새 corpus와 split을 봉인한 뒤 수행해야 한다. 결정적 단계, AI-ready 완료 판정, hold를 모두 포함한 end-to-end 결과에서 coverage-risk 곡선, violation/non-violation별 precision·recall, abstention rate를 함께 보고한다. 본 265건과 동일 모델 proxy는 개발 과정에서 이미 열람되었으므로 확증 test로 재사용하지 않는다.

재현 가능한 aggregate artifact는 `backend/evaluation/stage_selective_proxy_eval.json`에 기록한다. artifact에는 occurrence 내용이나 API 키를 포함하지 않고 입력 SHA-256, snapshot ID, proxy GT ID, 집계 결과만 저장한다.
