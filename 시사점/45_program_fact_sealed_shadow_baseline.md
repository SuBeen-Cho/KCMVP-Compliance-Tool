# Program-fact sealed shadow baseline

## 목적

현재 HEAD의 AI-ready 41건에서 정식 근거가 아닌 프로그램 사실이 어느 단계까지
재생성 있게 입증되는지 API 호출 없이 측정했다. 이 실험은 코드 snippet을
사실로 재해석하지 않고, 추출기가 작성한 봉인된 구조화 assertion만 인정한다.

## 결과

- 동일 AI-ready universe: 41건, universe hash `a699bfb2…b4`
- snippet 가용성: 41/41
- project artifact evidence 가용성: 0/41
- 봉인된 program fact 가용성: 0/41
- 구조 유효성: 0/41
- 독립적 의미 승인: 0/41
- API 호출: 0

snippet 41건이 존재한다는 것은 사실 입증 41건을 의미하지 않는다. 현재 candidate에는
AST/dataflow 추출기 버전, 입력 소스 hash, candidate/rule/claim provenance,
content digest와 HMAC seal을 모두 포함한 `sealed_program_fact` 필드가 없다. 따라서
정확도를 주장하지 않고 현재 값을
0으로 종료하는 것이 fail-closed 계약에 맞다.

## 구현된 수용 계약

후속 추출기는 정확히 다음 필드만 제출해야 한다.

1. schema version
2. extractor ID·version·SHA-256와 source SHA-256
3. candidate ID·rule ID·atomic claim ID
4. `observed|contradicted|unknown` 중 하나인 state
5. locator와 value를 갖는 구조화 observations와 missing-context 목록
6. 전체 body의 canonical content digest와 runtime-only key로 생성한 HMAC-SHA256 seal

provenance 재바인딩, content 변조, seal 불일치, 미지 state는 모두 차단한다.
seal key는 공개 산출물에 저장하지 않는다.

## 다음 구현 우선순위

1. 가장 폐쇄적으로 검증 가능한 LEA-011의 8개 delta 상수표를 완전한 typed
   initializer에서 먼저 구조화한다.
2. LEA-001의 operative block-size 선언·호출 인자와 byte/bit 단위를 함께 resolve한다.
3. LEA-021의 LEA-128 적용성과 6-word assignment를 같은 경로에서 확인한다.
4. CTR-001 14건의 호출 변환이 encryption transform인지와 encrypt/decrypt path를
   같이 봉인한다.
5. CBC-001은 ENC 입력까지의 def-use를 확인한 뒤 처리한다.
6. CTR-002 5건은 로컬 literal만으로 승인하지 않고, same-key reuse domain과 invocation
   boundary가 모두 확인될 때만 fact를 발행한다.
7. project-scope LEA absence 규칙은 파일 inventory와 preprocessing/compile manifest를 봉인한
   전역 증거가 생기기 전에는 `insufficient`를 유지한다.

첫 LEA-011 extractor는 정확한 `uint32_t[8]` hex literal initializer를 lexical
observation으로만 봉인한다. 선언만으로 실제 key schedule 사용과 모든 key-size
variant 적용성을 증명할 수 없으므로 정확한 표도 의미 상태는 `unknown`이다. 잘못된
임의 배열 역시 normative delta table이라는 identity가 확인되지 않으므로 즉시
`contradicted`로 승격하지 않는다. include·매크로·표현식·부분 snippet·모호한 복수
배열·주석/문자열 속 가짜 선언은 모두 차단하며 shadow 결과는
`production_authorized=false`로 고정한다.

아직 fact provenance에는 candidate applicability/context digest가 없고,
`complete_source` 존재 자체도 외부에서 증명된 source-completeness attestation은 아니다.
따라서 향후 `observed|contradicted` 승격 전에는 `candidate_context_sha256`와 전처리·파일
inventory에 결합된 completeness artifact를 계약에 추가해야 한다.

다음 성능평가는 `fact availability → schema validity → independent semantic authorization`을
분리해야 한다. GT가 없는 동안 precision, recall, F1은 계산하지 않는다.

## 재현

```bash
cd backend
python3 -m experiments.program_fact_shadow_eval \
  /path/to/private.snapshot.json \
  --output evaluation/public_program_fact_shadow_current_head.json
python3 -m pytest -q tests/unit/test_program_fact_shadow_eval.py
```

공개 산출물은 aggregate-only이며 occurrence ID, snippet, 절대경로, API key를 포함하지 않는다.
