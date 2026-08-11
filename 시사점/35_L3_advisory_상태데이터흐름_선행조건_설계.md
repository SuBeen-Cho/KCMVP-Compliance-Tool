# L3 advisory 상태·데이터흐름 선행조건 설계

## 목적과 정책

GCM-006, CTR-006, PAD-002는 단일 regex 부재로 위반을 확정할 수 없다. 본 단계는 세 항목을 L1 확정 규칙으로 등록하지 않고, closed-schema `l3_advisory` 사전조건과 결정적 관찰 사실만 정의한다. 기본 enforcement는 `disabled`이며 실험 결과는 후보 제거나 성능 평가 GT로 사용하지 않는다.

## 원문 재확인

- GCM-006은 Part 1(2024.11) p.85 blocks 27~33에서 동일 키 암호화 호출을 2^32번 이하로 제한하고 상한에서 중단·키 갱신을 요구한다. 키 식별, IV 구성, 재기동 복구, 영구 계수기가 필요하다.
- CTR-006은 Part 2(2024.03) p.23 block 6의 권고사항이다. 카운터 폭, 증가, 최대값 guard, 중단·rekey, 동일 키 유일성을 함께 봐야 한다. 권고를 필수 위반으로 승격하지 않는다.
- PAD-002는 Part 2 p.14 blocks 25~26과 p.16 blocks 23~24에서 패딩 유효성 검증 후 패딩을 제거하도록 요구한다. 복호화·검증·제거·평문 공개 사이의 순서가 필요하다.

## 실험 checker

PAD-002만 가장 작은 관찰 면적으로 구현한다. checker는 주석과 문자열을 마스킹하고 pycparser로 파싱된 단일 C 함수 내에서 decrypt, padding validation, padding removal, plaintext release 이벤트를 수집한다. 검증 실패 조기 return 가드가 모든 removal/release 경로를 지배할 때만 `satisfied`를 반환한다. 분기 없는 직선 경로에서 검증 전 release를 직접 관찰한 경우만 `unsafe_observed`를 반환하며, 나머지는 `unknown`이다. 기본 실행은 `findings=[]`, `gate=no_fp_default`를 반환하며 `--enable-experimental`을 지정해야만 advisory를 반환한다.

```bash
cd backend
python3 -m experiments.l3_advisory_checker tests/fixtures/pad002_unsafe.c
python3 -m experiments.l3_advisory_checker tests/fixtures/pad002_unsafe.c --enable-experimental
```

## 검증과 한계

positive, negative, conditional branch, early-return, unknown fixture와 주석·문자열 비탐지, default no-FP gate를 테스한다. macro·C++·파싱 실패·loop/switch/goto·함수 포인터·미지 호출·복수 관련 함수는 모두 `unknown`으로 보존한다. alias와 interprocedural dataflow를 증명하지 않으므로 `unsafe_observed`도 L1 확정 위반이 아니라 L3 검토 후보이며 `enforcement=none`을 유지한다. macOS/Python 3.14 로컬 환경에서 early-return positive fixture 1,000회를 반복한 단일 관찰치는 총 334.661 ms, 평균 0.3347 ms, 초당 2,988.1건이다. 이는 서비스 SLO가 아니라 로컬 미세 벤치마크이다.

공격 회귀 17건을 포함한 최종 backend 테스트는 557건 중 556건이 통과하고 1건은 skip한다. 이 결과는 fact extractor의 구현 일관성을 보이며 PAD-002 enforcement 승격을 의미하지 않는다.

## 반환값 polarity 독립 공격감사

Validator 함수명만으로 반환값 polarity를 추론하면 `0=success`와 `1=success`를 구분하지 못해 거짓 `satisfied`가 발생한다. 따라서 단순 `if (validate_padding(x))`, 부정, `==0`, `!=0`, `==1`은 모두 `unknown`으로 처리한다. `satisfied`는 `PADDING_VALID` 또는 `PADDING_INVALID`라는 의미 상수와 명시적으로 비교하고, 그 guard가 모든 관찰된 removal/release sink에 선행하는 경우로 제한한다.

추가 공격 테스는 nested branch, multiple sink, cleanup/helper call, `do/while`, ternary, `goto`, function-pointer alias, release wrapper, release-before-validation을 포함한다. 분석기가 제어흐름이나 callee effect를 증명하지 못하면 `unknown`을 반환한다. 모든 경우에 `enforcement=none`이며 기본 gate는 계속 `findings=[]`이다.
