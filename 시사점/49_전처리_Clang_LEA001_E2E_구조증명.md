# 전처리–Clang–LEA-001 end-to-end 구조 증명

## 목적

신뢰할 수 있는 빌드 문맥을 보유한 케이스에서 전처리 capture·replay, 분석 바이트 binding, Clang reaching-definition, LEA-001 128-bit block 구조 검사가 연결되는지 확인했다. 이 실험은 실제 성능 추정이 아닌 합성 fixture 기반 기능·공격 검사이다.

## 결과

- 전처리 provenance 검증 및 `VerifiedPreprocessingBinding`: 1/1
- 직선형 output reaching-definition 구조 증명: 1/1
- LEA-001 16-byte/128-bit block 구조 증명: 1/1
- canonical direct-copy RHS octet coverage: 16/16
- reaching definition RHS AST digest coverage: 2/2
- 분석 바이트 변조, runtime secret 변조, reaching source 재결합, LEA extent 재결합 차단: 4/4
- 반복 결과 불변성: 3/3
- API 호출: 0
- 의미론적 자동 승인: 0

지연시간은 cold 581.774 ms, warm 평균 238.655 ms, 중앙값 236.134 ms, 최대 251.538 ms였다. 이 값은 현재 실행 환경의 합성 fixture 측정치이며 production SLA로 해석하지 않는다.

## 해석 경계

`structural_complete` 결과는 전처리된 동일 바이트에 특정 AST 구조와 reaching definition이 존재함을 뜻한다. RHS digest 2/2는 RHS 의미가 LEA 표준과 동치한다는 뜻이 아니다. 알고리즘 identity, 호출 가능성, 호출자의 결과 사용, 표준 RHS 등가성을 증명하지 않았으므로 상태는 계속 `unknown`이며 semantic authorization은 0이다.

직접 same-index copy도 input/output 비중첩을 증명하지 않으므로
`input_output_non_aliasing_proved=false`로 기록한다. 공격감사에서는 `_Bool` loop index가
1에서 포화되어 16회 coverage가 되지 않는 단위 혼동을 발견해 `_Bool`·char 폭 induction
type을 차단했다. runtime binding은 프로세스 내부 capability로서 비신뢰 Python 코드에
대한 암호학적 보안 경계가 아니며, 신뢰된 분석 프로세스 내부에서만 사용한다.

## 다음 개발 경계

다음 단계는 표준에서 추출한 closed RHS 스키마와 AST RHS를 canonical operation graph으로 변환하여 동치성을 검사하는 것이다. 그 전까지는 합성 positive fixture를 production 자동 승인에 사용하지 않는다.
