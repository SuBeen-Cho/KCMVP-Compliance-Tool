# 공식 Evidence RAG 고도화 구현과 검증

## 1. 연구 문제와 결론

기존 RAG/no-RAG 비교에서 고유 이진 후보 78건의 불일치는 no-RAG만 정답 6건, RAG만 정답 1건이며 exact McNemar `p=.125`였다. 이는 RAG와 no-RAG가 동등하다는 증명이 아니다. 기존 경로가 공식 PDF를 검색하지 않고, `rule_id`에 고정된 저자 해설 Markdown을 주입하며, 일부 규칙을 의미적으로 무관한 문서에 연결한 상태에서 수행한 프록시 파일럿이다. 따라서 현재 결론은 “RAG가 불필요하다”가 아니라 “기존 RAG는 공식 근거 검색의 독립 기여를 평가할 구조가 아니었다”로 한정한다.

## 2. 공식 근거 코퍼스

로컬에 고정된 KCMVP 및 LEA 관련 PDF 7종을 오프라인에서 파싱한다. 최초 12,462개 unit을 생성했으나, 페이지별 copyright·무단전재 footer 332개가 requirement로 오인덱싱된 것을 독립 감사에서 확인하여 제거했다. 최종 인덱스는 12,130개 evidence unit이다. unit은 source ID, 발행처, 버전·효력일, 페이지·블록·절·표·각주 locator, 역할, 적용 범위, 원문 SHA-256을 가진다. Git에 보존하는 public index는 원문을 포함하지 않고 locator와 hash만 보존하며, 검색용 local text index는 Git 제외·권한 `0600`으로 생성한다.

두 번의 재생성 실행에서 public/local 산출물은 각각 byte-identical이었다. 감사 후 재생성 계측은 7 sources, 12,130 units이다. 입력 PDF hash drift, 경로 traversal·symlink, locator–unit ID 불일치, source unit count 불일치, public/local pair 불일치는 fail-closed 처리한다.

## 3. Rule-to-evidence 전수 감사

활성 규칙 166개 전부를 `rule_evidence_audit.json`에 등록했다. 제출물·시험 규칙의 1차 자동 승격 62개 중 24개는 독립 entailment 감사에서 원문보다 의무를 확대한 것으로 판정하여 다시 차단했다. 이후 `CMAC-004`와 LEA 규칙 8개를 normative unit에 직접 대조했다. 최종 상태는 `verified` 50개, `review_required` 109개, `unmapped` 7개로, 116개는 공식 근거 경로에서 fail-closed한다. `verified` 커버리지 30.12%는 평가된 규칙 비율이지 전체 규칙 정확도가 아니다.

기존의 item ID 첫 파일 선택 heuristic을 제거하고, CTR-001, CBC-LEA-005, LEA-001, COM-002, COM-003, COM-005의 명백한 오매핑을 제거했다. 서버 startup validator는 활성 규칙과 감사 레지스트리의 100% 일치, verified 항목의 권위·역할·적용범위·locator·source hash·unit ID를 검증한다. 저자 해설은 명시적 legacy opt-in에서만 자신의 rule에 한해 열린다.

## 4. Adaptive router와 근거 검증

파서가 확인한 명시적 구조 모순은 검색을 생략한다. 부재, 적용성, 예외, 표·버전 판단이 필요한 후보만 검색한다. 검색 대상이나 검증된 매핑이 없으면 후보를 제거하지 않고 `insufficient_context`로 유지한다.

L3 출력은 evidence unit ID, 원문 support span, applicability, exception 확인, counterevidence, entailment를 포함해야 한다. 결정론적 verifier는 무인용, 존재하지 않는 ID, 저자 해설만의 인용, 폐기·상충 근거, span 불일치, 알고리즘·모드 적용 불일치, entailment·예외 미확인을 차단한다. 이 검증을 통과하지 못한 RAG 판정은 L1 후보를 제거할 수 없다.

## 5. 실행 검증과 성능

- 전체 backend: LEA 매핑 배치 및 독립 공격 감사 기준 `540 passed, 1 skipped`이다.
- 최종 50개 verified mapping의 exact unit set, source binding, bundle recall은 모두 1.0이고, 116개 unverified의 fail-closed rate도 1.0이다. 캐시 조회는 중앙값 약 0.399 ms, p95 약 0.473 ms였다.
- GCM-002는 2개, CCM-003은 1개, CMAC-004는 4개, LEA-048은 18개의 검증된 unit을 반환한다. CTR-001은 오매핑 제거 후 0개를 반환한다.
- router smoke에서 명시 AST 모순은 skip, 검증된 GCM 규칙은 retrieve, 미검증 CTR 규칙은 evidence-absent abstention으로 분기했다.
- 공식 원문·API key·workstation 절대경로는 Git 대상 산출물에 포함하지 않았다.
- footer 제거 전 12,462-unit 산출물 hash는 historical audit로만 유지한다. 현행 local 인덱스는 실행 환경에서 재생성 검증하며 Git에 포함하지 않는다.
- 최종 12,130-unit 재생 산출물 SHA-256는 public `efcfb358caecbf14093a28ee480006fbba8b0dcb5c71eb27548b3e0c4db555e5`, local `e7e747b52ef568227292a132917dff1d2f570456088e5d342475d3a8d7bd2846`이다. 50-rule retrieval 평가 산출물 SHA-256는 `138b48d9cd8fac3852c8c96962b7e3ff6508f2a40bb23d0554e2f01fe3ccf29b`이다.

## 6. 문헌과 설계 근거

Self-RAG는 고정 passage의 무조건 주입보다 retrieval-needed/relevant/supported/useful 판단을 적응적으로 수행하는 방식을 제시한다. CRAG은 retrieval evaluator와 오류 교정을 분리하며, ALCE는 인용 존재와 실제 entailment가 다른 문제임을 보인다. ARES는 context relevance, answer faithfulness, answer relevance를 분리 평가한다. 본 구현은 이들을 직접 재학습하지 않고, retrieve-needed router, 권위적 evidence gate, span-bound verifier, abstention으로 분해해 적용한다.

- Self-RAG: <https://arxiv.org/abs/2310.11511>
- CRAG: <https://arxiv.org/abs/2401.15884>
- ALCE: <https://arxiv.org/abs/2305.14627>
- ARES: <https://arxiv.org/abs/2311.09476>
- BRIGHT: <https://arxiv.org/abs/2407.12883>

## 7. 주장 범위와 후속 평가

본 단계는 공식 근거 RAG의 안전한 기반을 구축한 것이지, RAG의 정확도 개선을 입증한 것이 아니다. 다음 단계에서는 (1) 나머지 162개 규칙의 원문 매핑 검토, (2) normative/exception/non-applicable query의 evidence-unit GT 구축, (3) BM25, dense, hybrid, reranker, router 절제 실험, (4) Evidence Bundle Recall, exception recall, wrong-authority rate, citation entailment·completeness, abstention accuracy, (5) 고정된 occurrence GT에서 no-RAG·oracle evidence·irrelevant evidence·verified RAG의 paired 비교를 수행해야 한다. 이 평가가 완료되기 전에는 기존 `p=.125`를 신규 RAG의 효과 결론으로 재사용하지 않는다.
