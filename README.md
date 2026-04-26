# KCMVP Pre-Compliance Validator

> KCMVP(암호모듈 검증) 제출 전, **소스 코드 + 제출 문서**를 AI 기반으로 자동 사전 점검하는 풀스택 웹 도구

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)]()
[![FastAPI](https://img.shields.io/badge/backend-FastAPI-009688)]()
[![React](https://img.shields.io/badge/frontend-React%20%2B%20Vite-61DAFB)]()
[![Gemini](https://img.shields.io/badge/LLM-Gemini%202.5%20Flash-4285F4)]()

---

## Overview

KCMVP 암호모듈을 공식 검증에 올리기 전, **코드 정적 분석 + LLM 의미 판정 + 문서 규격 검사**를 5단계 파이프라인으로 수행합니다.

**주요 기능:**
- **코드 분석** — COM/LEA/ARIA + 8개 운용 모드(CBC, CTR, GCM 등) 총 170+ 규칙 자동 점검
- **문서 분석** — 설계서·형상관리·시험서·지침서 PDF 섹션/표 구조화 + DOC 규칙 적용
- **AI 재판정** — Gemini LLM으로 L1 후보 위반의 의미적 타당성 검증, FP 제거
- **추적성 검사** — 설계서 ↔ 코드 ↔ 시험서 간 일관성 자동 확인
- **패치 생성** — 위반 항목별 수정 전/후 코드 + 수정 이유 자동 생성

---

## Pipeline Architecture

```
ZIP/GitHub + PDF 업로드
     │
     ▼
┌─ L0  전처리 ──────────────────────────────────────┐
│  AST 파싱 (libclang + pycparser fallback)         │
│  Symbol Graph (크로스파일 콜그래프)                  │
│  PDF 섹션·표 구조화 (PyMuPDF + pdfplumber + OCR)   │
└───────────────────────────────────────────────────┘
     │
     ▼
┌─ L1  정적 분석 (Rule Engine) ─────────────────────┐
│  YAML 기반 170+ 규칙 (missing/regex/semantic/ast) │
│  AST 완전 분석 25개 + regex fallback 15개          │
└───────────────────────────────────────────────────┘
     │
     ▼
┌─ L2  AI 의미 판정 ────────────────────────────────┐
│  Gemini 2.5 Flash — 코드 60건 / 문서 30건 상한    │
│  구조화 증거 기반 프롬프트 + confidence scoring     │
└───────────────────────────────────────────────────┘
     │
     ▼
┌─ L3  LLM 재판정 ─────────────────────────────────┐
│  Micro-rubric 프롬프트로 FP 2차 필터링             │
│  Precondition 필터로 불필요 호출 차단              │
└───────────────────────────────────────────────────┘
     │
     ▼
┌─ 보고서 + 패치 ──────────────────────────────────┐
│  위반 병합·중복 제거 → violations.json             │
│  AI 종합 평가 + 수정 패치 병렬 생성               │
└───────────────────────────────────────────────────┘
```

---

## Quick Start

### Prerequisites

- Python **3.10+**
- Node.js **18+**
- (선택) libclang — 설치 시 향상된 AST 분석 자동 활성화

### Backend

```bash
cd backend
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

cp ../.env.example .env
# .env에 GOOGLE_API_KEY 설정 (Google AI Studio에서 무료 발급)

uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Frontend

```bash
cd frontend
npm install && npm run dev
```

### Docker

```bash
docker-compose up -d
```

> **접속**: http://localhost:5173 | **API docs**: http://localhost:8000/docs

---

## Project Structure

```
Kcmvp_main_보완/
├── backend/
│   ├── app/
│   │   ├── main.py                    # FastAPI 진입점
│   │   ├── api/routes/                # analyze, health 라우트
│   │   └── services/                  # 핵심 서비스 레이어
│   │       ├── preprocess_service.py          # C/H AST 파싱
│   │       ├── symbol_graph_service.py        # 크로스파일 콜그래프
│   │       ├── enhanced_symbol_graph_service.py # libclang 심볼 그래프
│   │       ├── ast_checker_service.py         # AST 완전 분석 (25개 룰)
│   │       ├── rule_engine_service.py         # L1 YAML 룰 엔진
│   │       ├── doc_rule_service.py            # 문서 L1 룰
│   │       ├── traceability_service.py        # 추적성 TRC
│   │       └── llm/                           # LLM 서비스 패키지
│   │           ├── l2_judge.py                # 코드 L2 판정
│   │           ├── doc_judge.py               # 문서 L2 판정
│   │           ├── prompt_builder.py          # 프롬프트 빌더
│   │           ├── patch_generator.py         # 패치 생성
│   │           └── summary_generator.py       # AI 종합 평가
│   ├── rules/                         # YAML 룰셋
│   │   ├── common/security.yaml       #   COM-001~006
│   │   ├── algorithm/                 #   LEA, ARIA
│   │   ├── mode/                      #   CBC, CTR, GCM, CCM, CFB, CMAC, ECB, OFB
│   │   ├── docs/                      #   설계서, 형상관리, 시험서, 지침서
│   │   └── traceability/              #   TRC 룰
│   ├── guidelines/                    # RAG 소스 마크다운
│   ├── mapping/                       # rule_id → 가이드라인 매핑 (170+)
│   ├── scripts/                       # 평가·테스트 스크립트
│   └── testdata/                      # 테스트용 ZIP, PDF
│
└── frontend/                          # React + Vite
    └── src/
        ├── pages/                     # Landing, Analyze
        ├── components/                # CodeViewer, DocViewer, FileTree 등
        └── stores/                    # Zustand 상태 관리
```

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/analyze` | 분석 Job 생성 (ZIP/GitHub + PDF) |
| `GET` | `/api/analyze/{job_id}` | 상태·진행률 폴링 |
| `GET` | `/api/analyze/{job_id}/report` | 위반 목록 + AI 종합 평가 |
| `GET` | `/api/analyze/{job_id}/file` | 소스 파일 내용 |
| `GET` | `/api/analyze/{job_id}/files` | 파일 목록 |
| `GET` | `/api/analyze/{job_id}/ast` | 파일별 AST |
| `GET` | `/api/analyze/{job_id}/docs` | 전처리된 문서 섹션 |
| `GET` | `/api/analyze/{job_id}/patches` | 패치 목록 |
| `GET` | `/api/analyze/{job_id}/symbol-graph` | 함수 콜그래프 |
| `GET` | `/api/health` | 헬스 체크 |

<details>
<summary><b>POST /api/analyze 요청 필드</b></summary>

| 필드 | 타입 | 설명 |
|------|------|------|
| `file` | UploadFile | 코드 ZIP (source 없을 때 필수) |
| `source` | str | GitHub URL 또는 owner/repo |
| `design_doc` | UploadFile | 설계서 PDF |
| `config_doc` | UploadFile | 형상관리 문서 PDF |
| `test_doc` | UploadFile | 시험서 PDF |
| `algorithm` | str | LEA, ARIA 등 |
| `mode` | str | CBC, CTR, GCM 등 |

</details>

---

## Evaluation Results

### Code Violation Detection

| Metric | Value |
|--------|-------|
| **L1 Recall** | **89.5%** (베이스라인 49.5% → +40pp) |
| **L1+L3 Recall** | **87.6%** |
| **L3 FP 제거율** | **94.3%** (53건 중 50건 제거) |
| **KISA LEA FP 감소** | 208건 → 11건 (94.7% 감소) |

### Document Violation Detection

| Metric | Value |
|--------|-------|
| **Recall** | **100%** (10/10) |
| **Precision (L1+L2)** | **58.8%** |

### Evaluation Methodology

6단계 체계적 평가: Blind Test → Wilson CI → Mutation Testing → LOO Cross-Validation → External Blind → Mutation Automation

---

## Environment Variables

```env
# 필수
GOOGLE_API_KEY=AIza...          # Google AI Studio API 키

# 기본값 사용 가능
API_V1_PREFIX=/api
GEMINI_L2_MODEL=gemini-2.5-flash-lite
L2_PROVIDER=gemini              # 또는 local

# 선택
RAG_USE_CHROMA=false
LOCAL_LLM_BASE_URL=http://localhost:8080/v1
LOCAL_LLM_MODEL=kcmvp-judge
```

---

## Test Data

`backend/testdata/`에 사전 준비된 테스트 파일:

| 파일 | 용도 |
|------|------|
| `accuracy_test_v12.zip` | 최신 정확도 검증 세트 |
| `lea_mode_rules_fail_v2.zip` | 모드 룰 위반 케이스 |
| `testdata_libclang.zip` | libclang 심볼 그래프 테스트 |
| `fake_design_doc.pdf` | 의도적 DOC 위반 포함 |
| `sifr_kit설계서 예시.pdf` / `한컴위드설계서예시.pdf` | 실제 설계서 예시 |

```bash
# 테스트 실행
cd backend && source venv/bin/activate
python scripts/test_upload.py

# 분석 결과 초기화
rm -rf backend/storage/jobs/*
```

---

## Development Guides

| 문서 | 내용 |
|------|------|
| [`YAML_룰과_코드_연동_설명.md`](backend/docs/YAML_룰과_코드_연동_설명.md) | 룰 pattern_type별 동작 방식 |
| [`LEA_코드_룰_작성_가이드.md`](backend/docs/LEA_코드_룰_작성_가이드.md) | LEA/모드 YAML 룰 작성법 |
| [`DOC_설계서_룰_작성_가이드.md`](backend/docs/DOC_설계서_룰_작성_가이드.md) | DOC 룰 작성법 |
| [`RAG_연결_가이드라인.md`](backend/docs/RAG_연결_가이드라인.md) | RAG 근거 검색 설계 |
| `CLAUDE.md` | Claude Code 온보딩 가이드 |

---

