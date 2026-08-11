# CMAC-004 KCMVP 인증값 길이

## 공식 근거

암호모듈 구현안내서 Part 2(2024.03) CMAC 생성·검증 고려사항은 ARIA·SEED·LEA의 MAC 길이를 112~128비트로, HIGHT의 MAC 길이를 64비트로 명시한다. 원문 위치는 PDF p.49 blocks 25~26과 p.51 blocks 24~25이다.

## 탐지 범위

실행 코드의 정수 literal CMAC tag/MAC 길이 대입, enum, 단순 `#define`만 탐지한다. `_bits`는 비트, `_bytes`는 바이트로 판독한다. 알고리즘 prefix가 없으면 파일 내에 ARIA·SEED·LEA·HIGHT 중 단 하나만 명시된 경우에만 판독한다. 주석, 문자열, 혼합 알고리즘 모듈, 런타임 변수와 매크로 표현식은 보수적으로 탐지하지 않는다.

## 한계

본 규칙은 명시적 정수 설정의 KCMVP 프로파일 불일치만 보고한다. 함수 인자로 전달되는 값의 범위 분석은 별도 AST/data-flow 규칙이 필요하다.
