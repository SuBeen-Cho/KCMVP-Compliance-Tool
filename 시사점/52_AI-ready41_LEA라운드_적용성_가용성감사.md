# AI-ready 41건 LEA 라운드 적용성 가용성 감사

## 목적

봉인된 historical AI-ready 41건에서 LEA-027~031 판정에 필요한 완전 소스, 빌드·전처리 매니페스트, 호출 지점 문맥이 존재하는지 API 호출 없이 점검했다. 개별 source ID, candidate ID, 경로, snippet은 공개 산출물에 기록하지 않았다.

## 집단 고정

현재 라우터를 재실행하면 근거 매핑 변경으로 멤버십이 변하므로, 이번 감사는 atomic-v3 실행 private ledger에 봉인된 candidate ID hash 41개를 snapshot과 재결합했다. 이는 과거 41건을 현재 규칙으로 소급 재라벨링하지 않기 위한 lineage 분리다.

## 결과

- 봉인 AI-ready: 41건
- LEA-027: 0건
- LEA-028: 0건
- LEA-029: 0건
- LEA-030: 0건
- LEA-031: 0건
- 대상 occurrence 합계: 0건
- API 호출: 0건
- production 승인: 0건

대상 occurrence가 없으므로 완전 소스, trusted build/preprocessing manifest, trusted callsite context의 가용 건수도 모두 0건이다. 이 0은 문맥 부족률이나 detector 성능이 아니라 단순히 해당 규칙 occurrence가 고정 집단에 없음을 의미한다. 따라서 분모 0인 coverage 비율을 산출하거나 100%/0%로 표현하지 않는다.

## 검증과 해석 경계

실험 러너는 private ledger가 중복 없는 41개 hash를 갖는지, snapshot에서 41건이 모두 재결합되는지, source content hash가 일치하는지를 fail-closed로 검증한다. 단위 테스트는 대상 0건, manifest/callsite 미제공, 불완전 membership 거부를 확인한다.

이 결과로 LEA 라운드 operation-graph 증명의 실제 coverage를 주장할 수는 없다. 다음 실증은 LEA-027~031 occurrence가 실제로 포함된 독립 holdout에서 완전 번역 단위, 폐쇄된 compile argv/cwd/include/macro, canonical callsite를 함께 capture해야 한다.

## 재현

```bash
cd backend
PYTHONPATH=. python3 experiments/lea_round_applicability_current_head_eval.py \
  <private-snapshot> --private-ledger <private-ledger> \
  --output evaluation/public_lea_round_applicability_frozen_ai_ready41.json
python3 -m pytest -q tests/unit/test_lea_round_applicability_current_head_eval.py
```
