# LEA 라운드 공식 근거–연산 그래프–호출 지점 봉인 체인 평가

## 목적과 판정 경계

공식 LEA 규격서의 라운드 수식 evidence unit, 검증된 전처리 결과에서 추출한
연산 그래프, `restrict` 인자의 실제 비중첩 호출 지점을 하나의 shadow 체인으로
결합하였다. 이 평가는 구조 증명기의 폐쇄성 평가이며 detector 정확도나 구현의
KCMVP 적합성 평가가 아니다.

세 단계가 모두 통과하더라도 caller가 실제 LEA 암호화 경로인지, 해당 rule의
applicability가 성립하는지, 독립 GT와 일치하는지는 아직 증명되지 않는다. 따라서
사실 상태는 항상 `unknown`, 의미 승인과 production 승격은 0건으로 유지한다.

## 구현 계약

1. 공식 근거 단계는 로컬 공식 index, 원 PDF SHA-256, evidence unit 원문 hash,
   rule mapping과 atomic claim의 완전한 수식 조각 및 applicability를 결합한다.
2. 전처리 단계는 compiler binary, argv, 작업 디렉터리, include trace, macro event,
   출력 bytes를 HMAC 봉인하고 동일 argv replay가 일치할 때만 AST 입력 capability를
   발급한다.
3. 연산 그래프 단계는 32비트 XOR, modulo addition, rotate, 네 output store만
   허용하며 공식 수식 그래프와 정확히 일치해야 한다.
4. 호출 지점 단계는 단 하나의 직접 호출과 서로 다른 고정 배열 `out[4]`,
   `in[4]`, `rk[6]`만 허용한다. alias, pointer arithmetic, 부족한 extent는 거부한다.
5. 두 하위 증명 결과의 canonical SHA-256과 전체 chain SHA-256을 남긴다.

## 합성 평가 결과

- 정상 체인: 1건, 세 구조 단계 모두 통과
- 변조 공격: 5건
  - 잘못된 회전량
  - 동일 배열 alias
  - pointer arithmetic
  - 부족한 round-key 배열
  - 봉인 이후 분석 소스 변경
- 전체 분류: 6/6
- false accept: 0
- false reject: 0
- end-to-end 지연시간: 평균 350.794 ms, 중앙값 351.877 ms, 최대 352.569 ms
- API 호출: 0건
- 의미 승인: 0건

지연시간에는 전처리 capture와 replay, 공식 evidence registry 검증, 두 차례의 Clang
AST 분석이 모두 포함된다. 합성 6건은 보안 경계 회귀용이며 실제 모집단 성능의
precision·recall 추정치로 사용해서는 안 된다.

## 결론과 다음 단계

이번 단계는 “근거가 맞고, 수식 구조가 맞고, 직접 배열 호출도 안전하다”는 세
구조 명제를 동일 소스·toolchain provenance 아래 연결했다. 아직 남은 핵심은
caller의 algorithm identity와 entrypoint부터 해당 호출까지의 도달 가능성,
rule별 applicability, 독립 occurrence GT이다. 다음 단계에서는 실제 전처리 가능한
translation unit에 동일 체인을 shadow 적용하되, 독립 GT가 마련되기 전에는
자동 승격을 금지한다.
