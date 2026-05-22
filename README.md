<p align="center">
  <img src="assets/screenshot-report.png" width="800" alt="KCMVP Pre-Compliance Validator"/>
</p>

<h1 align="center">KCMVP Pre-Compliance Validator</h1>

<p align="center">
  KCMVP 암호모듈 검증 제출 전, 소스 코드와 제출 문서를 자동으로 사전 점검하는 웹 도구
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white"/>
  <img src="https://img.shields.io/badge/React_18-61DAFB?style=for-the-badge&logo=react&logoColor=black"/>
  <img src="https://img.shields.io/badge/Vite-646CFF?style=for-the-badge&logo=vite&logoColor=white"/>
  <img src="https://img.shields.io/badge/Gemini_2.5-4285F4?style=for-the-badge&logo=google&logoColor=white"/>
</p>

<p align="center">
  <a href="https://github.com/SuBeen-Cho/KCMVP-Compliance-Tool/stargazers"><img src="https://img.shields.io/github/stars/SuBeen-Cho/KCMVP-Compliance-Tool?style=flat-square"/></a>
  <a href="https://github.com/SuBeen-Cho/KCMVP-Compliance-Tool/commits/main"><img src="https://img.shields.io/github/last-commit/SuBeen-Cho/KCMVP-Compliance-Tool?style=flat-square"/></a>
  <a href="https://github.com/SuBeen-Cho/KCMVP-Compliance-Tool"><img src="https://img.shields.io/github/repo-size/SuBeen-Cho/KCMVP-Compliance-Tool?style=flat-square"/></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/SuBeen-Cho/KCMVP-Compliance-Tool?style=flat-square"/></a>
</p>

---

## Demo

<a href="https://www.youtube.com/watch?v=6zdJuxVHgmE">
  <img src="https://img.youtube.com/vi/6zdJuxVHgmE/maxresdefault.jpg" width="700" alt="KCMVP Demo Video"/>
</a>

> 클릭하면 YouTube에서 데모 영상을 볼 수 있습니다.

---

## 주요 기능

|  | 기능 | 설명 |
|--|------|------|
| **L1** | 코드 정적 분석 | C/C++ 소스를 AST + regex로 분석. LEA/ARIA + 8개 운용 모드, 170+ 규칙 자동 점검 |
| **L1** | 문서 규격 검사 | 설계서, 형상관리, 시험서 PDF의 섹션/표 구조를 파싱 후 DOC 규칙 적용 |
| **L2** | 증거 매핑 | 규칙별 KCMVP 가이드라인 근거 연결 (RAG) |
| **L3** | LLM 재판정 | Gemini로 후보 위반의 의미적 타당성 검증, 오탐(FP) 제거 |
|  | 추적성 검사 | 설계서 - 코드 - 시험서 간 일관성 확인 |
|  | 패치 생성 | 위반 항목별 수정 전/후 코드 + 수정 이유 자동 생성 |

---

## 스크린샷

<p align="center">
  <img src="assets/screenshot-analysis-result.png" width="800" alt="코드 분석 결과 (IDE 스타일)"/>
</p>

<p align="center">
  파일 트리에서 파일 선택 → 위반 항목이 코드 위에 인라인 표시. 오른쪽 패널에서 심각도/확정 여부 필터링.
</p>

---

## 파이프라인

<p align="center">
  <img src="assets/pipeline.png" width="480" alt="분석 파이프라인"/>
</p>

ZIP 또는 GitHub URL로 소스를 올리고, PDF 문서를 함께 업로드하면 아래 순서로 분석이 진행된다:

1. **전처리** — AST 파싱(libclang/pycparser), PDF 섹션-표 구조화(PyMuPDF + pdfplumber), 스캔본 OCR
2. **L1 정적 분석** — YAML 규칙 매칭 (missing / regex / semantic / ast)
3. **L2 증거 매핑** — 규칙별 KCMVP 가이드라인 근거 연결 (RAG)
4. **L3 LLM 재판정** — Gemini가 코드/문서 컨텍스트를 보고 FP 필터링
5. **보고서 + 패치** — 위반 병합-중복 제거 → 종합 보고서 + 수정 코드 생성

---

## Quick Start

### 사전 준비

- Python 3.10+
- Node.js 18+
- (선택) libclang — 있으면 AST 분석 정확도 향상

### Backend

```bash
cd backend
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

cp ../.env.example .env
# .env에 GOOGLE_API_KEY 설정 (Google AI Studio에서 발급)

uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Frontend

```bash
cd frontend
npm install && npm run dev
```

> **접속**: http://localhost:5173 | **API 문서**: http://localhost:8000/docs

---

## 프로젝트 구조

```
├── backend/
│   ├── app/
│   │   ├── main.py                  # FastAPI 진입점
│   │   ├── api/routes/              # analyze, health 라우트
│   │   └── services/                # 핵심 서비스
│   │       ├── preprocess_service.py        # C/H AST 파싱
│   │       ├── symbol_graph_service.py      # 크로스파일 콜그래프
│   │       ├── rule_engine_service.py       # L1 YAML 룰 엔진
│   │       ├── doc_rule_service.py          # 문서 L1 룰
│   │       └── llm/                         # LLM 판정 + 패치 생성
│   ├── rules/                       # YAML 룰셋 (170+)
│   ├── guidelines/                  # RAG 소스 마크다운
│   └── mapping/                     # rule_id → 가이드라인 매핑
│
├── frontend/                        # React + Vite
│   └── src/
│       ├── pages/                   # Landing, Analyze
│       ├── components/              # CodeViewer, DocViewer, FileTree 등
│       └── stores/                  # Zustand 상태 관리
│
├── ruleset/                         # KCMVP 가이드라인 기반 룰셋 DB (RAG용)
│   ├── docs/                        # 상세설계서 항목별 마크다운
│   └── LEA/                         # LEA 알고리즘 + 운용모드 마크다운
│
├── docs/                            # 룰 작성 가이드
└── assets/                          # README 이미지
```

---

<details>
<summary><b>성능 측정 결과</b></summary>

### 코드 위반 탐지

| 지표 | 수치 |
|------|------|
| L1 Recall | 89.5% (베이스라인 49.5% → +40pp) |
| L1+L3 Recall | 87.6% |
| L3 FP 제거율 | 94.3% (53건 중 50건 제거) |
| KISA LEA FP 감소 | 208건 → 11건 (94.7% 감소) |

### 문서 위반 탐지

| 지표 | 수치 |
|------|------|
| Recall | 100% (10/10) |
| Precision (L1+L2) | 58.8% |

6단계 체계적 평가: Blind Test → Wilson CI → Mutation Testing → LOO Cross-Validation → External Blind → Mutation Automation

</details>

<details>
<summary><b>API 엔드포인트</b></summary>

| Method | Endpoint | 설명 |
|--------|----------|------|
| `POST` | `/api/analyze` | 분석 Job 생성 (ZIP/GitHub + PDF) |
| `GET` | `/api/analyze/{job_id}` | 상태-진행률 폴링 |
| `GET` | `/api/analyze/{job_id}/report` | 위반 목록 + 종합 평가 |
| `GET` | `/api/analyze/{job_id}/file` | 소스 파일 내용 |
| `GET` | `/api/analyze/{job_id}/files` | 파일 목록 |
| `GET` | `/api/analyze/{job_id}/ast` | 파일별 AST |
| `GET` | `/api/analyze/{job_id}/docs` | 문서 섹션 |
| `GET` | `/api/analyze/{job_id}/patches` | 패치 목록 |
| `GET` | `/api/analyze/{job_id}/symbol-graph` | 함수 콜그래프 |
| `GET` | `/api/health` | 헬스 체크 |

</details>

<details>
<summary><b>환경 변수</b></summary>

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

</details>

---

## 기술 스택

| 영역 | 기술 |
|------|------|
| Backend | Python, FastAPI, pycparser, libclang, PyMuPDF, pdfplumber |
| Frontend | React 18, Vite, Zustand |
| LLM | Google Gemini 2.5 Flash |
| DB | ChromaDB (RAG, 선택) |

---

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.
