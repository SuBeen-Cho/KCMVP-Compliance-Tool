# LEA-001 current HEAD 전처리·AST shadow 평가

## 목적과 모집단

current HEAD에서 봉인한 동일 AI-ready 41건을 다시 선택하고, 그중 LEA-001 후보만
프로그램 사실 증명 경계에 투입했다. 별도 후보 선택이나 파일명·함수명 기반 정답 추정은
사용하지 않았다. 외부 API 호출도 수행하지 않았다.

## 결과

| 항목 | 결과 |
|---|---:|
| exact AI-ready 모집단 | 41 |
| LEA-001 후보 | 2 |
| snapshot 완전 소스 결합 | 2/2 |
| usable trusted preprocessing | 0/2 |
| AST structural complete | 0/2 |
| `unknown` | 2/2 |
| production 자동 승인 | 0 |
| API 호출 | 0 |

두 후보의 완전 소스는 opaque source ID와 SHA-256으로 안전하게 재결합됐다. 그러나
snapshot에는 compiler binary/version, argv, cwd, ordered include·macro event 및
preprocessed output digest를 담은 원래 build manifest가 없다. 소스에 전처리 지시문이
없어 보인다는 이유나 독립적인 기본 compiler 옵션을 manifest로 간주하지 않았다.

따라서 두 후보는 모두 `trusted_preprocessing_manifest_unavailable`로 분류했다. 검증되지
않은 source blob을 `preprocessed=True`로 AST proof에 투입하지 않았으므로
`structural_complete`도 0이다. 이는 구현 실패가 아니라 snapshot이 보유하지 않은 build
provenance를 사후에 만들어 내지 않는 fail-closed 결과다.

## 해석과 다음 경계

이번 수치는 detector 정확도나 LEA-001 위반 비율이 아니다. 동일 모집단에서 신뢰 가능한
프로그램 사실까지 도달할 수 있는지를 측정한 coverage 결과다. 현재 production 승격은
정당하게 0건이다.

다음 단계는 별도의 재현 가능한 fixture에서 실제 compile manifest를 capture/replay한 후,
동일 preprocessed bytes에 대해 CFG dominance, memory reaching-definition 및 호출자까지의
output influence를 증명하는 것이다. 실제 corpus는 원 build manifest가 확보될 때만 같은
경로에 편입한다.

별도 reaching-definition substrate는 branch·call·alias가 없는 직선형 함수의 직접 output
store와 동일 위치 overwrite를 Clang canonical declaration identity로 추적한다. 다중 동적
index는 주소 비중첩을 추론하지 않으며 pointer-to-pointer, function pointer와 `void *`도
차단한다. verified preprocessing capture와 source hash가 직접 결합되기 전에는 이 구조
결과 역시 production 승격에 사용하지 않는다.
