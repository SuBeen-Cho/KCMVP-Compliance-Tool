# LEA-011 def-use extractor current-HEAD 그림자 평가

## 목적

현재 HEAD에 봉인된 동일 AI-ready 41건을 대상으로 LEA-011 프로그램 사실 추출기를 API 호출 없이 평가하였다. 이 평가는 탐지 정확도나 의미 정확도를 산출하지 않으며, 완전한 소스의 안전한 재결합 가능성과 보수적 추출 coverage만 측정한다.

## 입력과 개인정보 보호

- 대상 universe: exact AI-ready 41건
- LEA-011 occurrence: 2건
- 완전 소스 재결합: 2/2건
- 재결합 방법: snapshot 내부 opaque `source_id`와 SHA-256, byte 수, line 수를 모두 검증한 뒤 메모리에서만 결합
- 공개 산출물: 집계값과 provenance hash만 포함
- 공개하지 않는 항목: 소스, snippet, source ID, 파일 경로, occurrence ID, runtime seal secret
- 외부 API 호출: 0건

따라서 complete source 자체는 안전하게 해석할 수 있었다. 다만 source identity나 내용이 공개 결과에 포함된다는 의미는 아니다. 중복 source ID, content hash 불일치, byte/line metadata 불일치는 실행 즉시 실패한다.

## 결과

| 항목 | 결과 |
|---|---:|
| exact AI-ready | 41 |
| LEA-011 | 2 |
| complete source resolved | 2 |
| observed | 0 |
| contradicted | 0 |
| unknown | 2 |
| production authorized | 0 |

두 소스 모두 전처리 지시문을 포함했다. 현재 extractor는 전처리 결과와 include graph provenance를 검증하지 않으므로 두 건을 `preprocessor_context_present`로 중단했다. 이는 def-use 실패나 위반 판정이 아니라, 컴파일러가 보는 translation unit을 현재 입력만으로 확정할 수 없다는 뜻이다.

별도 synthetic 공격감사에서는 세 key-size 함수에서 배열 참조가 보이더라도 regex만으로는
canonical symbol, live reachability, round-key 출력 영향, alias 및 variant별 정확한 index를
증명하지 못했다. `if (0)` 내부 사용, 고정 `constants[0]`, 잘못된 offset도 lexical
pattern을 통과할 수 있어, 해당 경로 역시 `semantic_defuse_and_reachability_unproved`로
`unknown` 처리한다. 잘못된 표도 실제 operative table이라는 SSA proof 전에는
`contradicted`로 승격하지 않는다.

## 해석과 다음 단계

이번 결과는 파일 경로나 함수명을 근거로 승격하지 않아도 snapshot에 포함된 원문을 안전하게 연결할 수 있음을 보여준다. 동시에 단순히 complete source가 존재한다는 사실만으로 프로그램 사실을 승인하면 안 된다는 경계도 확인했다.

다음 단계는 동일 source hash에 대해 전처리 명령, include graph, macro 정의와 preprocessed output hash를 별도로 봉인하는 것이다. 이어 canonical symbol/USR, CFG reachability, SSA def-use, variant별 index 및 round-key output influence를 증명해야 한다. 그 전까지는 두 occurrence를 hold로 유지한다.

공개 집계 산출물은 `backend/evaluation/public_lea011_defuse_current_head.json`에 저장했다.
