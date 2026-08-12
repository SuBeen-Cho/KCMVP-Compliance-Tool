# 세트 1–7 합성 컴파일 shadow 평가

원 빌드 문맥을 재구성할 수 없으므로, 아카이브 내 C translation unit에 `clang -fsyntax-only -std=c11 -I <archive>/include`만 적용한다. 이 조건은 합성 profile이며 원 컴파일, macro/include graph, 실행 의미, 규칙 정답을 입증하지 않는다.

공개 결과는 세트별 translation-unit 수, 구문 통과/실패, 실패 분류, 시간, compiler hash만 보존한다. 소스 내용과 경로는 공개 artifact에 남기지 않는다. authenticated compile-context coverage와 semantic authorization은 항상 0이다.
