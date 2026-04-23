# KCMVP 사전 적합성 검증 도구 (AI 기반)

> KCMVP 암호모듈을 실제 검증에 올리기 전에,
> **코드 + 제출 문서(설계서/시험서/형상관리/지침서)** 를 한 번에 점검하는 사전 검증용 도구입니다.
> 이 리드미는 전체 구조, 환경 설정, 서버 실행 방법, 설계 방향성, 파이프라인을 한 번에 정리합니다.

---

## 1. 프로젝트 개요

- **목표**
  - KCMVP 제출물(설계서, 시험서, 형상관리문서, 운영자/사용자 지침서)와 소스 코드를 대상으로
    - **기본 보안 룰(COM-001~006 등)**,
    - **알고리즘/모드별 룰(LEA, ARIA, CBC, CTR, CCM, CFB, CMAC, GCM, OFB, ECB)**,
    - **문서 작성 가이드라인(DOC-xxx) 준수 여부**,
    - **설계–코드–시험 간 추적성(Traceability, TRC-xxx)**
    를 **자동으로 사전 점검**하는 웹 기반 도구를 제공.
- **핵심 아이디어**
  - 코드 정적 분석(L1) + LLM 의미 분석(L2) + RAG 기반 근거 추출에,
  - **문서 규격 검사(DOC)** 와 **추적성 룰(TRC)** 를 더해
    "**설계(Design)–코드(Code)–시험(Test)**" 3단 일치 여부를 확인.

---

## 2. 전체 파일 구조 (요약)

```text
Kcmvp_main_최종/
├── .env.example                 # 환경 변수 템플릿
├── docker-compose.yml           # 통합 실행 설정
├── CLAUDE.md                    # Claude Code 가이드
│
├── backend/                     # FastAPI 백엔드
│   ├── app/                     # 앱 패키지
│   │   ├── main.py              # FastAPI 진입점
│   │   ├── config.py            # 설정 모듈 (backend/.env 사용)
│   │   ├── api/                 # API 계층
│   │   │   ├── routes/analyze.py# 분석 API (POST/GET /api/analyze/...)
│   │   │   └── routes/health.py # 헬스체크
│   │   ├── core/                # 예외, job_id 생성 등
│   │   ├── models/              # Job/Violation 모델
│   │   ├── schemas/             # 분석/보고서 스키마
│   │   ├── tasks/               # 비동기 태스크 (Celery stub — 현재 미사용)
│   │   │   └── analyze_task.py
│   │   └── services/            # 서비스 계층
│   │       ├── upload_service.py        # 업로드 (ZIP/GitHub + PDF)
│   │       ├── preprocess_service.py    # 코드 전처리 (AST/라인)
│   │       ├── preprocess_docs_service.py # 문서 전처리 (PyMuPDF+pdfplumber)
│   │       ├── ast_checker_service.py   # AST 전용 체커 (pycparser 완전 분석)
│   │       ├── symbol_graph_service.py  # 크로스파일 함수 콜그래프
│   │       ├── rule_engine_service.py   # L1 룰 엔진
│   │       ├── llm_service.py           # L2 AI 재판정 (Gemini), 패치/AI종합평가
│   │       ├── local_llm_service.py     # 로컬 LLM fallback (llama.cpp / HuggingFace)
│   │       ├── doc_rule_service.py      # 문서(DOC) 룰 엔진
│   │       ├── traceability_service.py  # 추적성(TRC) 룰 엔진
│   │       ├── rag_service.py           # RAG 근거 추출 (ChromaDB 선택 지원)
│   │       ├── mapping_service.py       # rule_id → KCMVP 가이드라인 조항 매핑
│   │       ├── report_service.py        # 위반 병합·요약·보고서 생성
│   │       └── code_slicer.py           # 위반 라인 주변 코드 스니펫 추출
│   ├── rules/                   # 룰셋 디렉터리
│   │   ├── common/security.yaml # COM-001~006 (공통 보안 룰)
│   │   ├── algorithm/lea.yaml   # LEA 알고리즘 룰 (LEA-001~062)
│   │   ├── algorithm/aria.yaml  # ARIA 알고리즘 룰
│   │   ├── mode/cbc.yaml        # CBC 모드 룰
│   │   ├── mode/ccm.yaml        # CCM 모드 룰
│   │   ├── mode/cfb.yaml        # CFB 모드 룰
│   │   ├── mode/cmac.yaml       # CMAC 모드 룰
│   │   ├── mode/ctr.yaml        # CTR 모드 룰
│   │   ├── mode/ecb.yaml        # ECB 모드 룰
│   │   ├── mode/gcm.yaml        # GCM 모드 룰
│   │   ├── mode/ofb.yaml        # OFB 모드 룰
│   │   ├── docs/design.yaml     # 설계서용 DOC 룰
│   │   ├── docs/config_mgmt.yaml# 형상관리 문서용 DOC 룰
│   │   ├── docs/test.yaml       # 시험서용 DOC 룰
│   │   ├── docs/keybiz.yaml     # 운영자/사용자 지침서 DOC 룰
│   │   └── traceability/traceability.yaml # 추적성 TRC 룰
│   ├── guidelines/              # 가이드라인 마크다운 (RAG 소스 텍스트)
│   │   ├── COM-001_zeroization.md
│   │   ├── COM-003_hardcoded_key.md
│   │   ├── LEA-042_timing_attack.md
│   │   ├── DOC-design-rules.md
│   │   └── ...
│   ├── mapping/                 # rule_id → 가이드라인 조항 매핑
│   │   └── rule_to_guideline.json  # 170+ 항목 매핑 테이블
│   ├── data/                    # ChromaDB 벡터 스토어 (RAG_USE_CHROMA=true 시)
│   │   └── chroma/
│   ├── docs/                    # 백엔드용 설계 가이드 텍스트
│   ├── scripts/                 # 샘플 ZIP 생성, API 테스트 스크립트
│   ├── testdata/                # 테스트용 ZIP 및 PDF 파일들
│   └── requirements.txt         # Python 의존성
│
└── frontend/                    # React 프론트
    ├── src/
    │   ├── App.jsx              # 루트 레이아웃
    │   ├── pages/
    │   │   ├── LandingPage.jsx  # 업로드 화면 + ChecklistForm
    │   │   └── AnalyzePage.jsx  # 분석 결과 페이지 (stub)
    │   ├── components/          # IDE 스타일 컴포넌트
    │   │   ├── TopNav.jsx
    │   │   ├── JobInfoBar.jsx
    │   │   ├── FileTree.jsx
    │   │   ├── CodeViewer.jsx
    │   │   ├── DocTree.jsx        # 문서 탭용 문서 목록
    │   │   ├── DocViewer.jsx      # 문서 전처리 텍스트·표 뷰어
    │   │   ├── ReportViewer.jsx   # 보고서 화면 (AI 종합 평가 포함)
    │   │   ├── AnalysisPanel.jsx  # 위반 목록 필터링 패널
    │   │   └── ChecklistForm.jsx  # 시험 신청서 형식 초기 체크리스트 UI
    │   ├── api/client.js        # API 클라이언트
    │   └── stores/
    │       ├── analysisStore.js # 분석 상태 (Zustand)
    │       └── checklistStore.js# 체크리스트 상태 (보안수준/운영모드 선택)
    └── package.json             # 프론트 의존성
```

---

## 3. 개발 환경 설정

### 3.1 필수 도구

- Python **3.10+**
- Node.js **18+** (프론트엔드 Vite/React)
- Git

### 3.2 백엔드 환경 설정

1. **가상환경 생성 및 활성화**

```bash
cd Kcmvp_main_최종/backend
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
```

2. **의존성 설치**

```bash
pip install -r requirements.txt
```

3. **환경 변수 설정 (`backend/.env`)**

```bash
cp ../.env.example .env   # 이미 있다면 생략
```

`backend/.env` 최소 설정값:

```env
API_V1_PREFIX=/api
CORS_ORIGINS=["http://localhost:5173","http://127.0.0.1:5173"]

STORAGE_ROOT=./storage
JOB_DATA_DIR=jobs

# L2 AI 재판정 설정 (Google AI Studio)
GOOGLE_API_KEY=AIza...실제키...
GEMINI_L2_MODEL=gemini-2.5-flash-lite
L2_PROVIDER=gemini

# RAG ChromaDB (선택 - 기본 비활성)
RAG_USE_CHROMA=false
RAG_EMBEDDING_MODEL=BAAI/bge-m3
```

> **참고**: `gemini-2.5-flash-lite`는 Google AI Studio에서 무료로 사용 가능합니다.
> Google AI Studio(https://aistudio.google.com)에서 API 키를 발급받아 사용하세요.

로컬 LLM을 사용하려면:

```env
L2_PROVIDER=local
LOCAL_LLM_BASE_URL=http://localhost:8080/v1
LOCAL_LLM_MODEL=kcmvp-judge
```

### 3.3 프론트엔드 환경 설정

```bash
cd Kcmvp_main_최종/frontend
npm install
```

---

## 4. 서버 실행 방법

### 4.1 백엔드 (FastAPI)

```bash
cd Kcmvp_main_최종/backend
source venv/bin/activate
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

- 헬스 체크: `http://localhost:8000/api/health`
- Swagger UI: `http://localhost:8000/docs`

### 4.2 프론트엔드 (Vite + React)

```bash
cd Kcmvp_main_최종/frontend
npm run dev
```

- 기본 접속: `http://localhost:5173`
- Vite가 `/api` 요청을 `http://localhost:8000`으로 프록시

### 4.3 Docker (풀스택)

```bash
docker-compose up -d
```

---

## 5. 설계 방향성 요약 (5-Layer 파이프라인)

### 5.1 Layer 1 — 데이터 추출 및 전처리

- **코드**
  - ZIP/GitHub → `upload_service` 로 job 디렉터리 생성.
  - `preprocess_service` 가 `.c/.h` 파일 AST 파싱 → `code_preprocess.json`.
  - `symbol_graph_service` 가 크로스파일 함수 콜그래프 → `symbol_graph.json`.
- **문서**
  - 설계서/형상관리/시험서/지침서 PDF → `preprocess_docs_service`.
  - PyMuPDF + pdfplumber 로 **섹션·표 구조** (`doc_preprocess_result.json`) 로 변환.

### 5.2 Layer 2 — 개별 규격 검사 (L1 룰 기반)

- **코드 L1** — `rule_engine_service`
  - COM-001~006, LEA-001~062, ARIA, CBC/CTR/CFB/CCM/CMAC/ECB/GCM/OFB 룰 적용.
  - `pattern_type`: `missing` / `regex` / `semantic` / `ast`
  - **AST 완전 구현 (20개)**: `ast_checker_service` 에서 pycparser 완전 분석.
  - **AST fallback (20개)**: regex fallback으로 후보 위반 생성 → L2 전송.
- **문서 L1** — `doc_rule_service`
  - `design.yaml`, `config_mgmt.yaml`, `test.yaml`, `keybiz.yaml` 적용.
  - `missing` / `regex` / `semantic` 타입으로 필수 섹션·표·문구 검사.

### 5.3 Layer 3 — AI 의미 재판정 (L2)

- **코드 L2** — `llm_service.run_l2_contextualizer()`
  - Gemini (`gemini-2.5-flash-lite`) 또는 로컬 LLM으로 L1 후보 위반 의미 판정.
  - 후보 선별: ast(최대 25건) + high severity regex/semantic(최대 25건) + 기타(최대 10건), 전체 60건 상한.
  - `missing` 타입 코드 룰은 L2 미전송 (즉시 위반 확정).
- **문서 L2** — `llm_service.run_doc_l2_contextualizer()`
  - 대상: `pattern_type`이 `semantic`/`missing` 이고 `needs_ai_review=True` 인 위반.
  - rule당 최대 5건, 전체 30건 상한.
- **RAG 근거 매핑** — `mapping_service` + `rag_service`
  - `rule_to_guideline.json` (170+ 항목)으로 rule_id → KCMVP 가이드라인 조항 매핑.
  - `RAG_USE_CHROMA=true` 설정 시 ChromaDB 벡터 검색으로 더 정밀한 근거 검색.

### 5.4 Layer 4 — 추적성 (TRC)

- **TRC 룰** — `traceability_service`
  - 설계서 인터페이스 명세표 ↔ 코드 헤더 함수 시그니처 일치 검사 (TRC-001).
  - 설계서 오류 코드 ↔ 시험서 결과 ↔ 코드 상수 일치 검사 (TRC-002).

### 5.5 Layer 5 — 보고서·패치·AI 종합 평가

- **보고서** — `report_service`
  - 모든 위반 병합·중복 제거 → `violations.json` + 심각도별 요약.
- **패치** — `llm_service.generate_patch_for_violation()`
  - 수정 전(`### ⚠️ 문제 코드`) / 수정 후(`### ✅ 수정 코드`, diff) / 수정 이유(`### 📝 수정 이유`) 3단 구조.
- **AI 종합 평가** — `llm_service.generate_ai_summary()`
  - 전체 위반 목록 검토 후 종합 판정·핵심 위험·우선 수정 권고 자동 생성.
  - ReportViewer 에 파란 박스로 표시.

---

## 6. API 엔드포인트

```
POST   /api/analyze                          # job 생성 (ZIP/GitHub + PDF + 필터)
GET    /api/analyze/{job_id}                 # 상태·진행률 폴링
GET    /api/analyze/{job_id}/report          # 위반 목록 + 요약 + AI 종합 평가
GET    /api/analyze/{job_id}/file            # 소스 파일 내용
GET    /api/analyze/{job_id}/files           # 파일 목록
GET    /api/analyze/{job_id}/ast             # 파일별 AST
GET    /api/analyze/{job_id}/docs            # 전처리된 문서 섹션
GET    /api/analyze/{job_id}/patches         # 패치 목록·본문
GET    /api/analyze/{job_id}/symbol-graph    # 함수 콜그래프
GET    /api/health
```

POST `/api/analyze` 업로드 필드:

| 필드 | 타입 | 설명 |
|---|---|---|
| `file` | UploadFile | 코드 ZIP (source 없을 때 필수) |
| `source` | str | GitHub URL 또는 owner/repo |
| `design_doc` | UploadFile | 설계서 PDF (선택) |
| `config_doc` | UploadFile | 형상관리 문서 PDF (선택) |
| `test_doc` | UploadFile | 시험서 PDF (선택) |
| `algorithm` | str | LEA, ARIA 등 (선택) |
| `mode` | str | CBC, CTR, GCM 등 (선택) |

---

## 7. 백엔드–프론트 파이프라인

```text
[사용자] ZIP 업로드 / GitHub URL + PDF 문서 (LandingPage + ChecklistForm)
    ↓
[프론트] POST /api/analyze
    ↓
[백엔드]
  upload_service            → src/, docs/ 저장
    ↓
  preprocess_service        → code_preprocess.json (AST/라인)
  symbol_graph_service      → symbol_graph.json (크로스파일 콜그래프)
  preprocess_docs_service   → doc_preprocess_result.json (섹션·표)
    ↓
  rule_engine_service       → L1 코드 위반 (COM/LEA/ARIA/모드)
  ast_checker_service       → AST 완전 분석 (20개 룰)
    ↓
  llm_service.run_l2_contextualizer      → L2 코드 AI 재판정 (Gemini)
    ↓
  doc_rule_service          → L1 문서 위반 (design/config_mgmt/test/keybiz)
  llm_service.run_doc_l2_contextualizer  → L2 문서 AI 재판정
    ↓
  traceability_service      → TRC 설계–코드–시험 일치성
    ↓
  rag_service / mapping_service          → 가이드라인 근거 매핑
    ↓
  llm_service.generate_ai_summary        → AI 종합 평가
  report_service            → violations.json + 요약
    ↓
[프론트]
  GET /report  → 위반 목록 / AI 종합 평가 / 파일 리스트
  GET /file    → CodeViewer (위반 라인 하이라이트)
  GET /docs    → DocViewer (섹션·표, 위반 배너)
  GET /patches → 패치 탭 (3단 diff 형식)
```

---

## 8. Rules 및 규칙 작성 가이드

- **`docs/YAML_룰과_코드_연동_설명.md`** — pattern_type 별 동작 방식, COM-001 전용 로직 등
- **`docs/DOC_설계서_룰_작성_가이드.md`** — DOC-xxx 룰 구조 및 keybiz 룰 작성법
- **`docs/LEA_코드_룰_작성_가이드.md`** — LEA/모드 룰 구조 및 AST 룰 확장 방법
- **`docs/RAG_연결_가이드라인.md`** — RAG 근거 검색 설계

### AST 룰 구현 현황 (총 40개)

| 상태 | 수 | 동작 방식 |
|---|---|---|
| 완전 구현 (`ast_checker_service`) | 20개 | pycparser AST 분석 → 정확한 판정 |
| fallback만 | 20개 | regex fallback → 후보 생성 → L2 AI 판정 |

**완전 구현 (20개):** LEA-003, LEA-010, LEA-030, LEA-031, LEA-034, LEA-035, LEA-040, LEA-042, LEA-046, LEA-047, LEA-056, LEA-057, CBC-001, CBC-002, ECB-002, GCM-001, CCM-001, CMAC-001, CTR-001, CTR-002

---

## 9. 테스트 데이터

`backend/testdata/` 에 준비된 파일들:

| 파일명 | 용도 |
|---|---|
| `lea_cbc_only.zip` | LEA + CBC 단일 모드 테스트 소스 |
| `LEA_origin.zip` | LEA 원본 소스코드 |
| `lea_rule_test.zip` | LEA 룰 테스트용 |
| `lea_mode_rules_fail_v2.zip` | 모드 룰 위반 케이스 테스트 |
| `accuracy_test.zip` / `accuracy_test_v8.zip` / `accuracy_test_v12.zip` | 정확도 검증용 버전별 테스트 |
| `fake_design_doc.pdf` | 의도적 위반 포함 가짜 설계서 (DOC-003, DOC-012, DOC-022, DOC-040, DOC-048) |
| `keybiz설계서예시.pdf` | 운영자 지침서 예시 |
| `SECUI설계서.pdf` / `sifr_kit설계서 예시.pdf` / `한컴위드설계서예시.pdf` | 실제 설계서 예시 |
| `암호모듈+구현+안내서_설계서.pdf` | 구현 안내서 설계서 예시 |

테스트 스크립트:

```bash
cd backend && source venv/bin/activate
python scripts/create_sample_zip.py    # 기본 샘플 ZIP 생성
python scripts/create_sample_zip_2.py  # 고급 샘플 ZIP 생성
python scripts/test_upload.py          # API 엔드포인트 테스트
```

---

## 10. 현재 상태 (2026-03 기준)

### 완료

- **L1 룰 엔진**: COM-001~006, LEA-001~062, ARIA, CBC/CTR/CFB/CCM/CMAC/ECB/GCM/OFB 전체 적용.
- **L2 AI 재판정**: Gemini(`gemini-2.5-flash-lite`) 또는 로컬 LLM. 코드 60건·문서 30건 상한.
- **AST 완전 분석**: `ast_checker_service` 에서 20개 룰 pycparser 완전 구현.
- **문서 연동**: 설계서/형상관리/시험서/지침서 PDF 개별 업로드 → 섹션·표 구조화 → DOC 룰 적용 → L2 재판정.
- **RAG 근거 매핑**: `rule_to_guideline.json` 170+ 항목 매핑, ChromaDB 벡터 검색 선택 지원.
- **추적성**: TRC-001(인터페이스 일치), TRC-002(오류코드 일치) 기본 구현.
- **AI 종합 평가**: `generate_ai_summary()` — 전체 위반 검토 후 종합 판정·핵심 위험·권고 자동 생성.
- **패치 노트**: 3단 구조(문제 코드 / 수정 코드 diff / 수정 이유) 표준화.
- **프론트**: IDE 스타일 UI, CodeViewer/DocViewer 위반 하이라이트, ChecklistForm(시험 신청서 형식).
- **체크리스트 UI**: 보안수준·운영모드 선택 (`checklistStore.js` + `ChecklistForm.jsx`).

### 진행 예정

- fallback-only AST 룰 20개 완전 구현 (현재 regex + L2 판정으로 동작).
- L2 프롬프트 품질 튜닝, ChromaDB RAG 인덱스 구축.
- `traceability_service` TRC 룰 확장.
- 비동기 파이프라인 (`analyze_task.py` Celery 연동).

### 알려진 한계

- **COM-001 FN**: 제로화 함수 호출은 탐지하나, 실제 키 변수에 호출되는지 추적 안 함.
- **TRC regex 취약**: 매크로 함수·함수 포인터·멀티라인 선언 누락 가능.
- **진행률 조악**: 파일 존재 여부로만 진행률 추정 (전처리 완료 시 80% 표시).
- **L2 캡 초과**: 대형 프로젝트에서 우선순위 낮은 위반은 AI 재판정 미처리 가능.

---

## 11. 개발 참고 문서 (`docs/`)

| 파일 | 내용 |
|---|---|
| `YAML_룰과_코드_연동_설명.md` | 룰 pattern_type, COM-001 전용 로직 |
| `LEA_코드_룰_작성_가이드.md` | LEA/모드 YAML 룰 작성법 |
| `DOC_설계서_룰_작성_가이드.md` | DOC YAML 룰 작성법 |
| `Frontend_UI_구현_가이드라인.md` | React 컴포넌트 설계 결정사항 |
| `RAG_연결_가이드라인.md` | RAG 근거 검색 설계 |
| `PROJECT_방향성_및_AI_온보딩_가이드.md` | 프로젝트 방향성 및 AI 온보딩 |
