# L3 advisory 상태·데이터흐름 선행조건 설계

## 목적과 정책

GCM-006, CTR-006, PAD-002는 단일 regex 부재로 위반을 확정할 수 없다. 본 단계는 세 항목을 L1 확정 규칙으로 등록하지 않고, closed-schema `l3_advisory` 사전조건과 결정적 관찰 사실만 정의한다. 기본 enforcement는 `disabled`이며 실험 결과는 후보 제거나 성능 평가 GT로 사용하지 않는다.

## 원문 재확인

- GCM-006은 Part 1(2024.11) p.85 blocks 27~33에서 동일 키 암호화 호출을 2^32번 이하로 제한하고 상한에서 중단·키 갱신을 요구한다. 키 식별, IV 구성, 재기동 복구, 영구 계수기가 필요하다.
- CTR-006은 Part 2(2024.03) p.23 block 6의 권고사항이다. 카운터 폭, 증가, 최대값 guard, 중단·rekey, 동일 키 유일성을 함께 봐야 한다. 권고를 필수 위반으로 승격하지 않는다.
- PAD-002는 Part 2 p.14 blocks 25~26과 p.16 blocks 23~24에서 패딩 유효성 검증 후 패딩을 제거하도록 요구한다. 복호화·검증·제거·평문 공개 사이의 순서가 필요하다.

## 실험 checker

PAD-002만 가장 작은 관찰 면적으로 구현한다. checker는 주석과 문자열을 마스킹하고 decrypt, padding validation, padding removal, plaintext release 이벤트의 존재와 순서를 수집한다. 결과는 `satisfied`, `unsafe_observed`, `unknown`의 3값이다. 기본 실행은 `findings=[]`, `gate=no_fp_default`를 반환하며 `--enable-experimental`을 지정해야만 advisory를 반환한다.

```bash
cd backend
python3 -m experiments.l3_advisory_checker tests/fixtures/pad002_unsafe.c
python3 -m experiments.l3_advisory_checker tests/fixtures/pad002_unsafe.c --enable-experimental
```

## 검증과 한계

positive, negative, unknown fixture와 주석·문자열 비탐지, default no-FP gate를 테스한다. 현재 구현은 이름이 명시적인 직접 호출의 source-order fact extractor이며 AST 지배관계, error path, alias, function pointer, interprocedural dataflow를 증명하지 않는다. 따라서 `unsafe_observed`도 L1 확정 위반이 아니라 L3 검토 후보이다. 후속 승격 조건은 CFG 상의 모든 plaintext-release path를 padding validation guard가 지배함을 증명하는 것이다.
