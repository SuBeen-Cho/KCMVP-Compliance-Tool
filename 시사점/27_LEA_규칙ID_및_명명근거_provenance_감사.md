# LEA 규칙 ID 및 명명 근거 provenance 감사

## 1. 감사 목적

본 감사는 활성 LEA 규칙, `rule_to_guideline.json`, `ruleset/LEA` 파생 문서가 동일한 규칙 ID를 서로 다른 의미로 사용하는지 확인하고, 참조 배포본의 API 이름을 보편적 KCMVP 보안 요구사항으로 오인하는 문제를 차단하는 데 목적이 있다.

## 2. 원문 확인 결과

`LEA 검증시스템`은 KAT, MMT, MCT의 REQUEST, RESPONSE, FACTS 교환 절차와 `LEA[키길이][운영모드명][시험유형].req` 등의 파일명을 명시한다. 따라서 `LEA-048`의 파일명은 LEA MOVS 시험 교환 산출물을 판단하는 경우에는 규범적 근거로 사용한다. 그러나 이를 일반 LEA 구현 소스의 파일명이나 내부 API 명명 요구사항으로 확장하지 않는다.

`블록암호 LEA 소스코드 사용 매뉴얼(v1.0)` §4.3은 LEA 단독 C 배포 소스가 제공하는 `lea_set_key`, `LEA_KEY`, `lea_ecb_enc`, `lea_online_init` 등의 인터페이스를 설명한다. 이러한 이름은 해당 배포본을 식별하고 코드 역할을 추정하는 근거로 활용한다. 다만 매뉴얼은 모든 독자 LEA 구현이 동일한 함수명과 타입명을 사용해야 한다는 KCMVP 보안 요구사항을 설정하지 않는다.

또한 §4.3.12는 `lea_online_init`에서 에러 발생 시 음수를 반환하는 계약을 명시한다. 이는 해당 배포 API에 한정된 계약이며, 모든 LEA API 또는 독자 구현 전체에 `return -N`이 존재해야 한다는 프로젝트 단위 missing 규칙을 지지하지 않는다.

## 3. ID 충돌

| ID | 활성 YAML의 의미 | 파생 ruleset에서 사용한 다른 의미 | 조치 |
|---|---|---|---|
| LEA-048 | MOVS 시험 파일 형식 | 동일 시험 파일 형식 | 적용 범위를 MOVS 산출물로 한정한다. |
| LEA-051 | 활성 규칙에서 제거함 | API 명명, RESPONSE 내용 | 폐기 상태로 명시하고 `LEA-REF-*` 증거 ID로 분리한다. |
| LEA-052 | 활성 규칙에서 제거함 | 구조체 명명, KAT 값 일치 | 폐기 상태로 명시하고 증거 ID를 분리한다. |
| LEA-053 | API 음수 반환 | 모드별 함수명, MOVS 절차 | 활성 missing 규칙을 제거하고 파생 문서의 ID를 증거 ID로 분리한다. |
| LEA-044 | 비밀키 제로화 | API 에러 반환 문서 | 에러 반환 문서의 requirements 연결을 제거한다. |

## 4. 구현 방향

`rule_to_guideline.json`의 문제 항목에 `provenance` 객체를 추가한다. 해당 객체는 `status`, `authority_class`, `evidence_role`, `source_title`, `source_locator`, `applies_to`, `does_not_establish`를 구분한다. 이를 통해 참조 구현 예시를 규범적 요구사항으로 승격하는 것을 방지한다.

## 5. 잔여 한계

현재 provenance 필드는 충돌이 확인된 LEA 항목에 우선 적용한다. 모든 AES, SEED, ARIA, 문서 규칙에 대한 전수 provenance 승격은 별도 원문 감사 후 수행해야 한다. 또한 파생 ruleset의 설명은 원문을 대체하지 않으며, 정량 성능 평가에서는 원문 locator가 고정된 항목만 확정 근거로 사용한다.

## 6. 규칙 수량 drift 목록

`LEA-053`을 활성 YAML에서 제거함에 따라 현재 inventory는 총 165개, 코드 지향 96개, 문서 65개, 추적성 4개로 구성된다. 다음 문서는 166개 스냅샷을 기록하므로 본 감사 변경의 커밋과 실험 manifest를 고정한 뒤 논문 수정 추적 절차에서 갱신해야 한다.

- `시사점/README.md`의 규칙 inventory 문구가 해당한다.
- `시사점/01_실험기준_및_재현성.md`의 YAML 자산 수량이 해당한다.
- `시사점/MDPI_논문_수정추적_영문_국문.md`의 영문·국문 초록, 기여 요약 및 하단 복제 본문이 해당한다.

위 수량은 논문 원문을 직접 수정하지 않는 운영 원칙에 따라 본 감사에 drift로 선기록한다.
