# KCMVP 논문·프로젝트 수정 시사점

이 폴더는 리뷰 대응 과정의 결정, 검증 근거, 실행 결과와 남은 위험을 단계별로 기록한다.
각 문서는 구현 내용뿐 아니라 독립 감사, 테스트 결과, 논문에 사용할 수 있는 주장 범위를 구분한다.

## 단계

1. 실험 기준 코드와 재현성 기반
2. canonical 결과 체계
3. 수치·산정 방식 교정
4. L2 독립 ablation
5. 비용·시간·토큰 계측
6. confidence calibration
7. AES·SEED 일반화
8. 제3자 blind labeling
9. MDPI 원고 수정
10. reviewer response 및 최종 검증
11. AES·SEED 평가 자료 후보와 고정 출처
12. 논문 수정추적본 완전성 검증

## 2026-08-11 현재 완료 상태

- 구현 및 정적 검증: 규칙 inventory(161개), 산술 감사, GT 주석 제거, no-RAG 경로, 실행 manifest, 토큰 카운터, confidence 입력 검증, L3 fail-fast를 반영했다.
- 테스트: backend `118 passed, 1 skipped`; manifest 직접 CLI 통과; MDPI PDF 24쪽 재컴파일 성공.
- 과거 결과: 코드·입력·프롬프트를 묶는 manifest가 없어 `legacy_unverified`로만 유지한다.
- 실제 재실행: 제공된 Gemini 키가 `API_KEY_INVALID`를 반환하여 canonical L2 paired 결과와 비용 결과를 만들지 못했다.
- 외부 검증: 제3자 blind annotator와 AES/SEED 정답 corpus가 없어 일반화 및 독립 검증 결과는 미완료다.
- 제출 원칙: 위 세 종류의 미완료 결과를 완료된 실험으로 표현하지 않는다. 현재 수정본은 범위를 LEA 중심의 feasibility study로 제한한다.

## 다음 실행 게이트

1. 유효한 모델 자격 증명과 clean commit/tag를 준비한다.
2. sidecar GT와 annotation 제거 입력을 고정하고 동일 L1 candidate snapshot을 만든다.
3. RAG/no-RAG를 동일 조건에서 반복 paired 실행한다.
4. 두 명 이상의 blind annotator가 candidate를 독립 라벨링하고 합의 전 원라벨을 보존한다.
5. AES·SEED에 대해 알고리즘별 독립 corpus와 confusion matrix를 확보한다.
6. 결과 bundle의 manifest, 입력·출력 hash, 비용 단가 snapshot, 실행 로그를 함께 동결한 뒤 논문 수치를 교체한다.
