# AES·ARIA·SEED 외부 공식 출처 및 저작권 감사

## 1. 범위와 방법

현재 review-required 규칙 중 `AES-001`–`AES-003`, `ARIA-001`, `SEED-001`의 알고리즘 사실 근거를 감사한다. 먼저 workspace의 PDF·TXT·MD를 탐색했으나 FIPS 197-upd1, RFC 5794, RFC 4269 원문은 발견하지 못한다. job storage의 ARIA 시험벡터는 실행 산출물이므로 규범적 출처로 승격하지 않는다.

로컬 미보유 출처는 발행기관의 HTTPS 원문을 임시 디렉터리에 다운로드하여 파일 형식, byte length와 SHA-256를 확인한다. 다운로드 원문은 repository에 복사하지 않고, 공개 registry에는 메타데이터·locator·hash·비인용 claim summary만 기록한다.

## 2. 확인된 일차 출처

| source | 발행 지위 | 파일 | SHA-256 | 역할 |
|---|---|---:|---|---|
| [NIST FIPS 197-upd1](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf) | 2023-05-09 active federal standard | PDF, 1,184,436 bytes | `62c86e...ecd1` | AES 알고리즘 정의의 규범적 표준 |
| [RFC 5794](https://www.rfc-editor.org/rfc/rfc5794.txt) | 2010-03, Independent Stream, Informational | TXT, 31,049 bytes | `e83bde...9d` | ARIA 알고리즘 교차검증 설명 |
| [RFC 4269](https://www.rfc-editor.org/rfc/rfc4269.txt) | 2005-12, Informational, RFC 4009 obsoletes | TXT, 34,390 bytes | `a1132b...f54` | SEED 알고리즘 교차검증 설명 |
| [ISO/IEC 18033-3:2010](https://www.iso.org/standard/54531.html) | edition 2, International Standard | 유료 표준 | 미산출 | AES·SEED를 포함하나 라이선스 원문 없이 unit 매핑 금지 |

RFC 문서 내부에 “Normative References” 절이 있다는 사실은 RFC 자체의 publication status를 Standards Track으로 변경하지 않는다. RFC 5794와 RFC 4269는 모두 Informational이며 KCMVP 요구사항의 규범적 근거로 사용하지 않는다. 다만 키 길이·라운드 수·블록 길이와 같은 알고리즘 정의 사실의 교차검증에는 사용할 수 있다.

## 3. 저작권과 저장 정책

FIPS 197-upd1은 미국 연방정부 저작물로서 미국 저작권 제한이 일반적으로 적용되지 않지만, 현재 단계에서는 원문 재배포가 필요하지 않으므로 hash-only 정책을 선택한다. RFC 본문은 IETF Trust Legal Provisions의 적용을 받으므로, 저작권 고지·수정·재배포 조건을 별도 검토하지 않은 상태에서는 원문을 commit하지 않는다. ISO 표준 본문은 유료·저작권 자료이므로 메타데이터 외의 저장·인덱싱·요약 생성을 하지 않는다.

## 4. 매핑 후보와 fail-closed 결론

- `AES-001`: FIPS 197-upd1 §2.1의 128-bit block 정의를 후보로 연결한다.
- `AES-002`, `AES-003`: FIPS 197-upd1 §5 Table 3의 키 길이·라운드 대응을 후보로 연결한다.
- `ARIA-001`: RFC 5794 §1.1을 informational cross-check로만 연결한다.
- `SEED-001`: RFC 4269 §1.2를 informational cross-check로만 연결한다.

위 locator는 `external_evidence_candidates.json`의 nonverbatim candidate이며 runtime RAG unit이 아니다. 따라서 5개 규칙의 `rule_evidence_audit.json` 상태는 모두 review-required로 유지한다. 정확한 hash의 원문을 로컬 private index에 재현하고, exact span·locator·span hash를 검증하고, 제3자가 rule entailment를 독립 검토하기 전에는 verified로 승격하지 않는다.

FIPS 197은 AES 알고리즘 정의에 대해 규범적이지만 특정 제품이 KCMVP 검증대상이라는 사실을 입증하지 않는다. RFC는 이보다 더 제한적인 informational cross-check이다. KCMVP 적용성은 KISA/NIS의 현행 검증대상 목록·시험방법·구현안내서로 별도 증명해야 한다.

workspace 규칙 전수 검색에서 `GCM-005`, `CMAC-003`, `CCM-005`, `CTR-003`–`CTR-005`, `CBC-003`–`CBC-004`, `LEA-042`, `LEA-044`, `COM-001`도 KS X ISO/IEC 19790:2015를 인용하는 review-required 규칙으로 확인한다. 해당 KS/ISO 원문의 적법한 로컬 본문이 없으므로 이 11개 규칙에도 evidence unit을 만들지 않는다. ISO/IEC 18033-3:2010은 AES·SEED 알고리즘의 소속을 확인하는 discovery metadata로만 유지한다.

## 5. 구현과 검증

- `external_official_sources.json`에 발행기관, status, version, URL, SHA-256, byte length, 권위·증거 역할, 저장 정책을 등록한다.
- `external_evidence_candidates.json`에 4개 nonverbatim locator unit과 5개 rule candidate 연결을 등록한다.
- registry 테스트는 HTTPS, 64-hex source hash, RFC Informational 역할, ISO 미인덱싱, 본문·span 비저장, 5개 규칙의 fail-closed 상태를 검증한다. 외부 registry·mapping validator 집중 테스트는 12건 모두 통과한다.
