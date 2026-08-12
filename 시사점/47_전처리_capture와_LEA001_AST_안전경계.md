# 신뢰 전처리 capture와 LEA-001 AST 안전 경계

## 목적

프로그램 사실을 코드 문자열이나 파일명으로 추정하지 않고, 컴파일러가 실제로 본 입력과
AST 관찰을 재현 가능하게 결합하기 위한 기반을 구현했다. 이 단계는 production 판정을
늘리는 것이 아니라 전처리·타입·구조 증거가 부족한 경우를 명시적으로 `unknown`으로
남기는 fail-closed 경계를 확립한다.

## 신뢰 전처리 capture/replay

private capture는 컴파일러 바이너리와 버전, argv 순서, 작업 디렉터리, 제한된 환경,
ordered include trace와 각 파일 content hash, macro event 순서, 진단·종료 상태와 정확한
preprocessed output hash를 HMAC으로 봉인한다. replay는 같은 입력을 다시 실행해 모든
digest와 출력 바이트가 일치할 때만 usable로 인정한다.

response file, 추가 translation unit, 출력·dependency 옵션, 강제 include, plugin loader,
target/sysroot 변경, 작업 디렉터리 밖 include는 거부한다. include trace의 어떤 항목이라도
regular readable file과 64자리 content hash로 확인되지 않으면 capture 전체를 unavailable로
처리한다. 현재 LEA-011 두 후보에는 원래 build manifest와 translation-unit 경로가 없으므로
인증된 부재 envelope 2건만 생성되고 usable context와 production 승격은 0건이다.

## LEA-001 구조 증명

Clang AST proof는 canonical `lea_encrypt_block`에서 정확한 octet input/output type,
16바이트 loop bound와 동일 index의 input→output 관계만 구조 후보로 인정한다. 공격감사에서
`typedef unsigned short uint8_t`가 단위 혼동을 일으키는 경로를 발견하여, desugared type이
정확한 `unsigned char`인 경우만 octet으로 인정하도록 보정했다. 무관한 16, 15 bound,
dead branch, helper call, fixed index, const output, 후속 overwrite는 차단한다.

그러나 이 AST 모양은 실제 LEA 알고리즘 identity, 호출자까지의 output 영향 및
interprocedural SSA를 증명하지 않는다. 따라서 구조가 완전해도 state는 `unknown`, 사유는
`interprocedural_ssa_and_algorithm_identity_unproved`이고 production 승격은 없다.

## 검증과 다음 단계

- 전체 backend: `718 passed, 1 skipped`
- 외부 API 호출: 0
- 공개 artifact에 source, 경로, 후보 ID, runtime secret 없음
- 현재 자동 승인 증가: 0

다음 단계는 current HEAD의 LEA-001 두 후보를 동일 안전 계약으로 재평가하고, capture가
가능한 독립 fixture에서 CFG dominance와 memory/reaching-definition proof를 구현하는 것이다.
