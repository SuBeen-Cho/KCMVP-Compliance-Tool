# KCMVP 핵심 로직 코드 리뷰

> 대상: 3개 레이어(L1 → L2 → Report) 흐름 + 문서(DOC) · 추적성(TRC) + AI 관련 주요 로직  
> 진입점: `backend/app/api/routes/analyze.py` (`_run_pipeline_sync`)  
> 핵심 서비스: `rule_engine_service.py`, `llm_service.py`, `report_service.py`, `rag_service.py`  
> 난이도: ⭐⭐⭐☆☆

### 이 문서를 쉽게 읽는 법

- **폴더가 어디에 뭐가 있는지**: `관련 파일 트리 (백엔드)` → `프론트엔드 파일 트리` → `지식·데이터베이스` → `저장소 루트 기타` 순으로 보면 **저장소 지도**가 잡힌다.
- **파일 이름 끝 확장자**: `확장자 설명` — **어떤 역할의 파일인지** 빠르게 찾을 때 쓴다.
- **한 파일만 볼 시간**: `딱 한 파일만 본다면` — 백엔드는 `analyze.py`, 프론트는 `api/client.js` 부터.
- **한 번 분석이 어떻게 도는지**: `전체 흐름 요약` — **한 줄 표(큰 그림)** → **①~⑫ 친절 설명** → **함수 다이어그램** 순으로 보면 된다.
- **AI만 따로 보고 싶을 때**: `AI 흐름 요약` — L2·패치·문서 AI·RAG 근거·보고서 요약까지 **어디서 LLM이 호출되는지**만 모아 두었다.
- **쓰는 라이브러리**: `외부 라이브러리·API 요약` — FastAPI·Gemini·PDF·RAG 등 **의존성과 예시 코드**가 나온다.
- **세부 설계**: `1. analyze.py` → `2. rule_engine` → `3. llm_service` 순이 **구현 깊이**가 점점 들어간다.
- **남은 과제·이슈**: `지금 해야 할 일`, `4. 주요 버그 및 설계 이슈` — **TODO·기술 부채** 확인용.
- **정확도·오탐·누락을 줄이는 원칙**: `정확도를 높이기 위한 전략` — 레이어별(FN/FP) 대응과 **비용·정확도 트레이드오프**를 한곳에 정리했다.
- **각 절마다**: 제목 바로 아래 **`### 이 섹션을 쉽게 읽는 법`** 불릿을 먼저 읽고 본문으로 넘어가면 읽기 쉽다.

---

## 관련 파일 트리 (백엔드)

### 이 섹션을 쉽게 읽는 법

- **`app/services/`**: 전처리·L1·L2·RAG·문서·TRC까지 **실제로 도는 Python 코드**가 모인 폴더다.
- **`analyze.py`**: 위 서비스들을 **순서대로 호출**하는 “메인 스위치” (HTTP 진입점).
- **`rules/`**: 무엇을 위반으로 볼지 **YAML로 적어 둔 룰** (L1 탐지 정의).
- **`mapping/`**: 룰 ID와 **가이드 문서·검색어**를 잇는 JSON — RAG·근거 첨부의 중심.
- **아래 job 폴더 표**: 사용자가 한 번 분석을 돌릴 때마다 생기는 **결과 파일 이름**만 따로 정리했다.

---

아래는 **코드 분석 파이프라인과 직접 연결된** 백엔드 경로만 정리한 것이다. `venv/` 등은 제외.

```
backend/
├── app/
│   ├── api/routes/
│   │   └── analyze.py              # POST /api/analyze 진입, _run_pipeline_sync 전체 순서 정의
│   └── services/
│       ├── preprocess_service.py   # run_preprocess — C/C++ 파싱, 파일별 AST·줄 목록
│       ├── symbol_graph_service.py # build_symbol_graph — 정의/호출 그래프, COM-001 크로스파일
│       ├── rule_engine_service.py  # run_rule_engine — L1 YAML 룰, pattern_type 분기
│       ├── ast_checker_service.py  # AST 룰(L3 일부)용 pycparser 체커
│       ├── llm_service.py          # run_l2_contextualizer, 프롬프트·Gemini·L1.5 필터
│       ├── rag_service.py          # attach_evidence — 룰별 가이드라인 텍스트 첨부
│       ├── report_service.py       # post_process_violations, build_summary, 패치/보고서 저장
│       ├── code_slicer.py          # slice_code, extract_global_skeleton — L2 코드 컨텍스트
│       ├── preprocess_docs_service.py  # run_doc_preprocess — PDF → 섹션 텍스트
│       ├── doc_rule_service.py     # load_doc_rules, run_doc_rule_engine — 문서 룰
│       ├── traceability_service.py # build_code_index, run_traceability_checks — TRC
│       └── upload_service.py       # create_job_from_upload/github, job 루트 경로
├── rules/                          # algorithm/*.yaml, common/*.yaml, traceability/*.yaml 등
└── mapping/
    └── rule_to_guideline.json      # RAG/근거 매핑 (attach_evidence 등에서 참조)
```

| 경로 | 의미 |
|------|------|
| `analyze.py` | HTTP로 job 생성 후 **`asyncio.to_thread(_run_pipeline_sync)`** 로 동기 파이프라인만 스레드에서 실행. 이벤트 루프 블로킹 방지. |
| `preprocess_service.py` | job 루트 아래 소스 스캔 → **`preprocess_result`** (`files[]`: path, lines, ast). |
| `symbol_graph_service.py` | 전처리 결과에서 **`definitions` / `calls` / `call_graph` / `files_with_clearing_call`** 생성. |
| `rule_engine_service.py` | **`violations_l1`** — `missing` / `regex` / `semantic` / `ast` 등 pattern_type별 적용. |
| `llm_service.py` | **`violations_l2`**, L1.5 이름 필터, 버킷 선정, Gemini 단독/배치, **`l2_rejected_keys`** 추적. |
| `rag_service.py` | **`final_violations`** 병합 후 근거 문자열 **`evidence`** 필드 부여. |
| `report_service.py` | L1+L2 **`post_process_violations`**, 요약, **`save_patch`**, 마크다운/PDF 보고서 유틸. |
| `preprocess_docs_service.py` + `doc_rule_service.py` | **`doc_preprocess`**, **`violations_doc`**, (선택) **`run_doc_l2_contextualizer`**. |
| `traceability_service.py` | 설계/시험 PDF 섹션 vs 코드 인덱스 → **`violations_trc`**. |
| `rules/` | L1/L2가 참조하는 YAML 룰 정의. |
| `mapping/rule_to_guideline.json` | 룰 ID ↔ 가이드 문구 연결 (RAG·보고서용). |

**job 폴더(런타임 산출물)** — 분석 1회당 `upload_service`가 만드는 작업 디렉터리 안에 대략 다음이 생긴다:

| 파일 | 의미 |
|------|------|
| `preprocess_result.json` | 전처리 결과 스냅샷 (프론트 파일 트리·AST API의 근거). |
| `symbol_graph.json` | 해당 job 코드에 대한 심볼 그래프. |
| `violations.json` | **코드 위반 + 문서 위반 + TRC** 를 합친 최종 배열 (파이프라인 끝에서 한 번 더 덮어씀). |
| `doc_preprocess_result.json` | PDF에서 뽑은 섹션 목록. |
| `job_meta.json` | `algorithm`, `mode` (룰 필터·보고서 헤더). |
| `patches/*.md` | 코드/문서용 AI 패치 마크다운. |

---

## 프론트엔드 파일 트리 (`frontend/src`)

### 이 섹션을 쉽게 읽는 법

- **`pages/` + `components/`**: 사용자가 보는 **화면·패널** (업로드, 분석 진행, 코드 뷰, 리포트).
- **`api/client.js`**: 백엔드 주소를 부르는 **단일 통로** — “프론트가 뭘 호출하는지”는 여기만 보면 된다.
- **`stores/`**: job_id, 위반 목록 등 **화면 간 공유 상태** (zustand).
- **`main.jsx` / `App.jsx`**: 앱이 **어디서 시작해 어떤 페이지로 갈지** 고르는 최상단.
- **트리를 볼 때**: 폴더 이름만으로 **UI / API / 상태** 세 덩어리로 나눠 읽으면 된다.

---

React + Vite + Tailwind + Zustand 구성. **API 베이스 URL·엔드포인트**는 `api/client.js`에 모여 있다.

```
frontend/
├── index.html                    # Vite 엔트리 (루트)
├── package.json
├── vite.config.js
└── src/
    ├── main.jsx                  # React DOM 마운트
    ├── App.jsx                   # 라우팅·페이지 조합 (Landing / Analyze)
    ├── api/
    │   └── client.js             # fetch 래퍼: analyze, report, files, ast, symbol-graph, docs 등
    ├── pages/
    │   ├── LandingPage.jsx       # 업로드·체크리스트 진입
    │   └── AnalyzePage.jsx       # 분석 화면 (job_id 기반)
    ├── components/
    │   ├── AnalysisPanel.jsx     # 분석 진행·결과 패널
    │   ├── CodeViewer.jsx        # 소스 + AST / 심볼그래프 뷰
    │   ├── FileTree.jsx          # preprocess 기반 파일 트리
    │   ├── ReportViewer.jsx      # 위반·요약 표시
    │   ├── DocViewer.jsx         # PDF/문서 섹션 뷰
    │   ├── DocTree.jsx           # 문서 트리
    │   ├── ChecklistForm.jsx     # 체크리스트 폼
    │   ├── JobInfoBar.jsx        # job 메타 표시
    │   └── TopNav.jsx            # 상단 네비
    ├── stores/
    │   ├── analysisStore.js      # job_id, violations, 파일 목록 등 전역 상태 (zustand)
    │   └── checklistStore.js     # 체크리스트 상태
    └── styles/
        └── index.css
```

| 경로 | 의미 |
|------|------|
| `App.jsx` | 어떤 페이지를 보여줄지·레이아웃. **UI 흐름의 최상단**. |
| `api/client.js` | 백엔드와의 **계약서** — URL 조합, `POST /api/analyze`, `GET .../report`, `getSymbolGraph` 등. |
| `AnalyzePage.jsx` + `AnalysisPanel.jsx` | job 단위 분석 UX (진행률·결과). |
| `CodeViewer.jsx` | 선택 파일 코드 + `/ast`, `/symbol-graph` 연동. |
| `FileTree.jsx` | `GET /files` 또는 report의 `files`로 트리 구성. |
| `ReportViewer.jsx` | `violations`, `summary` 렌더. |
| `analysisStore.js` | 프론트 상태 단일 소스 (job_id, 로딩, 위반 목록 등). |

---

## 지식·데이터베이스 (`database/`, `backend/guidelines`, `mapping`)

### 이 섹션을 쉽게 읽는 법

- **`database/`**: LEA·운영모드·문서 스펙 등 **길게 정리된 Markdown 지식 베이스** — 검색·RAG의 “책장”에 가깝다.
- **`backend/guidelines/`**: 룰 ID별로 짧게 쓴 **요약 가이드 MD** — Direct-RAG로 바로 열기 좋게 모아 둔 것.
- **`mapping/rule_to_guideline.json`**: “`COM-001`이면 어떤 파일·어떤 검색어”인지 **표 형태로 연결**한다.
- **`backend/rules/*.yaml`**: **자동 탐지 규칙** (패턴·AST). 지식 폴더와 헷갈리면 **rules = 엔진이 읽는 설정, database/guidelines = 사람·AI가 인용하는 글**로 보면 된다.

---

RAG·근거 검색·문서 가이드에 쓰이는 **정적 텍스트 자산**이다. 런타임 job 폴더와는 별개다.

### `database/` (프로젝트 루트)

```
database/
├── LEA/                          # LEA·운영모드·소스구성 등 **주제별 Markdown 지식 베이스**
│   ├── 01_블록암호_LEA/          # 알고리즘 본체 (LEA-001 …)
│   ├── 02_운영모드/              # CBC, CTR, GCM … 모드별 요구
│   └── 03_소스코드_구성/         # API 명명, 보안 코딩 등
└── docs/                         # 설계·형상·시험 등 **문서 요구** 관련 MD (상세설계서 스타일)
    └── 상세설계서/...
```

| 항목 | 의미 |
|------|------|
| `database/LEA/**` | `rag_service`의 `_DB_DIRS` 등에서 참조 — **룰·가이드 검색용 본문**. |
| `database/docs/**` | 문서 적합성·DOC 룰과 연계 가능한 **긴 형태 스펙 텍스트**. |

### `backend/guidelines/` (요약·룰별 조각)

COM-001, COM-003, LEA-API 등 **짧은 마크다운** — Direct-RAG 시 `rule_id`로 직접 로드하기 좋은 형태.

### `backend/mapping/`

| 파일 | 의미 |
|------|------|
| `rule_to_guideline.json` | **룰 ID → guideline 파일 경로·검색 쿼리** — `mapping_service` + `rag_service.search_evidence`의 중심. |

### `backend/rules/` (탐지 규칙 — YAML)

```
backend/rules/
├── algorithm/     # lea.yaml 등 알고리즘별 L1 룰
├── common/        # 공통 보안 COM-***
├── mode/          # CBC, GCM 등 모드별
├── doc/           # 문서 DOC 룰
├── docs/          # (문서 룰 보조·메타)
└── traceability/  # traceability.yaml — TRC
```

| 항목 | 의미 |
|------|------|
| `*.yaml` | L1 `pattern_type`, 정규식, AST 룰 ID 등 **기계-readable 탐지 정의**. |
| `traceability/traceability.yaml` | 설계↔코드↔시험 연결 검사 룰. |

---

## 저장소 루트 기타 (문서만)

### 이 섹션을 쉽게 읽는 법

- **`docs/`**: 이 `code_review_core_logic.md`처럼 **개발·연동·가이드용 마크다운**이 모인 곳이다.
- **레포 루트의 큰 `.md`**: `프로젝트_설명서.md`, `CLAUDE.md` 등 **사람·에이전트용 한눈에 보기** 문서.
- **실행 코드(`backend/app`, `frontend/src`)와 구분**: 여기는 **설명만** 있고, 분석 파이프라인 본체는 아니다.

---

| 경로 | 의미 |
|------|------|
| `docs/` | 본 `code_review_core_logic.md` 포함 **개발·가이드 문서** (프로젝트 설명, RAG 설명 등). |
| `프로젝트_설명서.md`, `CLAUDE.md` 등 | 사람용 개요·에이전트 힌트. |

(`backend/venv/`, `frontend/node_modules/` 는 의존성 설치본이라 **소스 트리 설명에서 제외**.)

---

## 확장자 설명 (이 프로젝트에서 쓰는 것)

### 이 섹션을 쉽게 읽는 법

- **`.c` / `.h` / `.cpp` / `.hpp` / `.py`**: 도구가 **소스 코드로 분석**하는 대상이다.
- **`.yaml`**: L1 룰·TRC 등 **규칙 정의** (사람이 편집 → 프로그램이 읽음).
- **`.json`**: 룰↔가이드 **매핑**, job **중간·최종 결과**, npm **의존성 잠금**처럼 **기계가 주고받는 데이터**.
- **`.md` / `.MD`**: 가이드·문서·패치 설명 등 **읽기용 텍스트** (RAG도 여기서 긁는다).
- **`.pdf` / `.zip`**: 사용자가 **올리는** 설계서·코드 묶음, 또는 **만들어 내는** 보고서.
- **`.jsx` / `.js` / `.css` / `.html`**: **프론트** UI·빌드 설정.
- **아래 표**: 같은 확장자라도 **역할이 다를 수 있**으니, 용도별 소절을 따라가면 된다.

---

아래는 **저장소·코드·런타임 job**에서 실제로 등장하는 확장자를 묶은 것이다. (의존성 패키지 내부의 수만 가지 확장자는 제외.)

### 분석 대상 소스 코드 (`SOURCE_EXTENSIONS`)

`preprocess_service.SOURCE_EXTENSIONS` 및 룰 엔진·추적성에서 **헤더/구현 구분** 등에 사용한다.

| 확장자 | 의미 | 코드에서의 쓰임 |
|--------|------|----------------|
| **`.c`** | C 구현 파일 | 전처리·AST·L1/L2 분석 대상. `ast_checker` 임시 전처리 파일 접미사로도 사용. |
| **`.h`** | C/C++ 헤더 | 전처리·심볼 연결에 포함. 룰에서 “헤더만 있는 선언” vs “`.c` 구현” 구분 시 참조. |
| **`.cpp`** | C++ 소스 | 전처리 대상 (pycparser 기반 경로와 함께 사용). |
| **`.hpp`** | C++ 헤더 | 전처리 대상. |
| **`.py`** | Python | 전처리 시 `ast` 모듈로 파싱해 **파일별 요약** 등에 사용 (C 계열과 동일 파이프라인 슬롯). |

### 룰·설정·매핑

| 확장자 | 의미 | 코드에서의 쓰임 |
|--------|------|----------------|
| **`.yaml`** | YAML 설정 | `backend/rules/**/*.yaml` — L1 룰, `rules/docs/*.yaml` — 문서 룰, `traceability/traceability.yaml` — TRC. `doc_rule_service`는 `*.yaml`만 글로브. |
| **`.yml`** | YAML (대체 확장자) | YAML 문법은 동일. 본 repo 룰 파일은 주로 **`.yaml`** 을 쓰고, 예외적으로 레포 루트 **`docker-compose.yml`** 등 인프라 관례에서 `.yml` 이 쓰일 수 있다. |

### 데이터 교환·job 산출물 (JSON)

| 확장자 | 의미 | 코드에서의 쓰임 |
|--------|------|----------------|
| **`.json`** | JSON | **`mapping/rule_to_guideline.json`** — 룰↔가이드 매핑; **job 폴더**: `preprocess_result.json`, `symbol_graph.json`, `violations.json`, `doc_preprocess_result.json`, `job_meta.json`; 프론트 **`package.json`**, **`package-lock.json`** — npm 의존성 잠금. |

### 지식·문서·근거 (Markdown)

| 확장자 | 의미 | 코드에서의 쓰임 |
|--------|------|----------------|
| **`.md`** | Markdown | `database/**`, `backend/guidelines/**`, `docs/**`, README, 패치/보고서 설명문. **`rag_service`**는 `*.md`와 **`*.MD`** 둘 다 수집(윈도우/복사본 대비). |
| **`.MD`** | Markdown (대문자) | 내용은 `.md`와 동일. RAG 인덱싱 시 동일 취급. |

### 업로드·보고서·바이너리 문서

| 확장자 | 의미 | 코드에서의 쓰임 |
|--------|------|----------------|
| **`.pdf`** | PDF | 사용자 **설계·형상·시험 문서** 업로드 (`analyze`에서 파일명·키워드 검증); `preprocess_docs_service`가 텍스트·표 추출; **`report.pdf`** — PyMuPDF로 생성된 최종 보고서. |
| **`.zip`** | ZIP 압축 | **`create_job_from_upload`** — 코드 묶음 업로드 시 압축 해제. 테스트 데이터 `testdata/*.zip` 등. |

### AI 패치·텍스트 보고서

| 확장자 | 의미 | 코드에서의 쓰임 |
|--------|------|----------------|
| **`.md`** (patches) | 패치 마크다운 | `patches/` 아래 **`*.md`** — `save_patch`, `GET .../patches` 에서 나열. |
| **`.md`** (report) | 마크다운 보고서 | `report_service.write_report_markdown` → **`report.md`**. |
| **`.pdf`** (report) | PDF 보고서 | `write_report_pdf` → **`report.pdf`**. |
| **`.txt`** | 순수 텍스트 | **`ai_summary.txt`** — `generate_ai_summary` 결과 캐시 (PDF 재생성 시 참고). |

### 프론트엔드 (Vite + React)

| 확장자 | 의미 | 코드에서의 쓰임 |
|--------|------|----------------|
| **`.jsx`** | React 컴포넌트 (JSX) | `src/components/**`, `pages/**`, `App.jsx` 등 UI. |
| **`.js`** | JavaScript | `src/api/client.js`, `stores/*.js`, `vite.config.js`, `tailwind.config.js`, `postcss.config.js`. |
| **`.css`** | 스타일 | `src/styles/index.css`, 빌드 산출 **`dist/assets/*.css`**. |
| **`.html`** | HTML | **`index.html`** — Vite 엔트리, `dist/index.html` — 빌드 결과. |
| **`.json`** | npm 메타 | `package.json`, `package-lock.json`. |

### 백엔드 애플리케이션

| 확장자 | 의미 | 코드에서의 쓰임 |
|--------|------|----------------|
| **`.py`** | Python | `backend/app/**`, `scripts/**` — FastAPI, 서비스, 스크립트 전부. |

### 환경·컨테이너·기타

| 확장자 / 파일 | 의미 | 코드에서의 쓰임 |
|---------------|------|----------------|
| **`.env`** | 환경 변수 (비밀) | `backend/.env` — API 키, `STORAGE_ROOT` 등 (`pydantic-settings`가 로드). |
| **`.example`** (관례) | 예시 env | **`.env.example`** — 키 이름만 공유 (실제 비밀 없음). |
| **`Dockerfile`** (확장자 없음) | 이미지 빌드 | `frontend/Dockerfile` 등 — 컨테이너 배포 시. |
| **`docker-compose.yml`** | Compose 정의 | 한 번에 백엔드·프론트 기동 등 (문서/README에서 언급). |

### 디렉터리만 있고 확장자 없는 것 (참고)

| 경로 | 의미 |
|------|------|
| Chroma 영속 디렉터리 (`CHROMA_PERSIST_DIR`) | SQLite 등 **폴더 단위** 저장 — 파일마다 확장자가 다름. |
| `node_modules/`, `venv/` | 의존성 트리 — **소스 문서에서는 제외**하는 것이 일반적이다. |

### 확장자 요약표 (빠른 검색용)

`.c` `.h` `.cpp` `.hpp` `.py` — 분석 소스 · `.yaml` — 룰 · `.json` — 매핑·job·npm · `.md`/`.MD` — 가이드·문서 · `.pdf` — 문서·보고서 · `.zip` — 코드 업로드 · `.md`(patches) — 패치 · `.txt` — AI 요약 · `.jsx`/`.js`/`.css`/`.html` — 프론트 · `.py` — 백엔드 · `.env` — 설정.

---

## 딱 한 파일만 본다면 (백엔드 vs 프론트)

### 이 섹션을 쉽게 읽는 법

- **시간이 없을 때** “어디만 열어볼까?”를 정해 주는 절이다.
- **백엔드**: **전체 파이프라인 순서**를 보고 싶으면 `analyze.py` **한 파일**이 지도 역할을 한다.
- **프론트**: **어떤 URL을 치는지**만 보고 싶으면 `api/client.js` **한 파일**이 계약서 역할을 한다.
- **표의 대안 파일**: 한 가지만 더 깊게 파고들 때(예: L2만) 쓰는 **차선**이다.

---

**목적에 따라 한 파일을 고르면 된다.** “전체 동작”과 “UI/API 계약”이 나뉜다.

### 백엔드에서 **한 파일만**

| 추천 파일 | 이렇게 보면 된다 |
|-----------|------------------|
| **`backend/app/api/routes/analyze.py`** | **가장 우선.** `create_analyze_job` → `asyncio.to_thread(_run_pipeline_sync, ...)` 안에 **전처리 → 심볼그래프 → L1 → L2 → evidence → 패치 → 문서 → TRC → `violations.json`** 순서가 한곳에 모여 있다. HTTP 엔드포인트(`GET /report`, `/files`, `/ast`, `/symbol-graph` …)도 같은 파일에 있어 **백엔드 전체 지도**로 쓰기 좋다. |
| (대안) `backend/app/services/llm_service.py` | **L2·Gemini·프롬프트만** 깊게 보고 싶을 때. 파이프라인 순서는 `analyze.py`를 봐야 한다. |

### 프론트엔드에서 **한 파일만**

| 추천 파일 | 이렇게 보면 된다 |
|-----------|------------------|
| **`frontend/src/api/client.js`** | **가장 우선.** 백엔드 **REST 경로·메서드·쿼리 파라미터**가 모여 있어 “프론트가 무엇을 호출하는지”가 한눈에 드러난다. |
| (대안) `frontend/src/App.jsx` | **화면 전환·페이지 조합**만 빠르게 보고 싶을 때. API 세부는 `client.js`를 봐야 한다. |

**정리**: 백엔드는 **`analyze.py`**, 프론트는 **`api/client.js`** 를 각각 “한 파일”로 보면 **파이프라인(또는 API 계약)** 을 가장 적은 이동으로 파악할 수 있다.

---

## 전체 흐름 요약 (실제 `_run_pipeline_sync` 기준)

### 이 섹션을 쉽게 읽는 법

- **①~⑫**은 “분석 한 번 눌렀을 때 서버가 **시간 순서대로 하는 일**”이다. 위에서 아래로 내려가면 된다.
- **앞쪽(①~⑦)**: 업로드한 **소스 코드**를 읽고, 규칙으로 훑고, AI로 한 번 더 물어보고, 필요하면 **수정 초안(패치)** 까지 만든다.
- **뒤쪽(⑧~⑫)**: 올려 둔 **PDF 문서**가 있으면 문서 검사를 하고, **설계↔코드↔시험**이 맞는지(TRC)도 본 뒤, **모든 위반을 한 목록으로** 합친다.
- **`violations.json`이 두 번 나오는 이유**: 중간에 **코드 위반만** 먼저 저장해 두었다가, 끝에서 **문서·TRC까지 합친 최종본**으로 파일을 다시 쓴다. 프론트·보고서는 보통 **최종본**을 본다고 생각하면 된다.
- **GET `/report`**: 위 파이프라인이 **끝난 뒤**, 사용자가 보고서 화면을 열 때 **추가로** 마크다운·AI 요약 등을 만들 수 있다. 분석 본체와는 **별도 요청**이다.

---

### 먼저 이것만 기억해도 됨 (큰 그림)

| 구간 | 한 줄로 |
|------|---------|
| **입력** | ZIP 또는 GitHub로 **코드**가 들어오고, 선택으로 **PDF 문서**가 붙는다. |
| **코드 쪽** | 파일을 읽고 → (선택) 함수 연결 그래프 → **규칙(L1)** → **AI 재판(L2)** → 가이드 **근거** 붙이기 → **패치 초안** 몇 개. |
| **문서·추적 쪽** | PDF에서 글 뽑기 → **문서 룰** (+ 필요 시 문서 AI) → 설계·시험과 코드 **대응(TRC)** 검사. |
| **출력** | **위반 목록 + 개수**가 JSON으로 돌아가고, 같은 내용이 `violations.json`에도 저장된다. |

비유하자면: **코드는 “소스 점검표”**, **문서/TRC는 “서류·추적 점검표”**를 한 번 더 돌린 뒤, **한 장의 종합 리스트**로 합치는 느낌이다.

---

### 단계별로 무슨 일이 일어나나 (①~⑫, 친절 모드)

| 단계 | 쉬운 말 | 조금만 기술적으로 |
|------|---------|---------------------|
| ① | 업로드된 소스 파일들을 **한 줄씩 읽고**, C면 **구조(AST)** 도 만든다. | `run_preprocess` → `preprocess_result.json` |
| ② | “이 함수가 **어느 파일의 어떤 함수**를 부르는지” **연결 지도**를 만든다. | `build_symbol_graph` (예: COM-001 크로스 파일) |
| ③ | YAML에 적힌 **규칙으로 위반 후보**를 찾는다. (아직 AI 아님) | L1 → `violations_l1` |
| ④ | 후보를 **AI에게 물어봐** 진짜 위반인지 판정한다. AI가 “오탐”이라고 한 건 나중에 빼 준다. | L2 → `violations_l2`, `l2_rejected_keys` |
| ⑤ | L1과 L2 결과를 **한데 합치고**, L2가 오탐이라고 한 건 **정리**한다. | `post_process_violations` |
| ⑥ | 각 위반에 **KCMVP 가이드 문구**를 붙인다. (RAG) | `attach_evidence` |
| ⑦ | 심각한 위반 위주로 **수정 예시(패치)** 를 몇 개 만든다. (상한 있음) | `generate_patch_for_violation` 등 |
| ⑧ | job 폴더의 **PDF**에서 글·표를 뽑는다. | `doc_preprocess_result.json` |
| ⑨ | **문서용 룰**을 적용하고, 필요하면 문서도 **AI로 한 번** 본다. | `violations_doc` |
| ⑩ | 문서 위반 중 일부에 **문서 패치** 초안을 만든다. (선택·상한) | — |
| ⑪ | 설계·시험 문서와 **코드가 서로 짝이 맞는지** 검사한다. | `violations_trc` |
| ⑫ | **코드 위반 + 문서 위반 + TRC**를 **한 배열**로 합친다. | 최종 `violations.json` |

---

### 개발자용 한 줄 다이어그램 (함수 이름 그대로)

```
사용자 ZIP 또는 GitHub → job_id, root = get_job_root(job_id)
      ↓
[analyze.py] POST /api/analyze → asyncio.to_thread(_run_pipeline_sync, root, algorithm, mode)
      ↓
① run_preprocess(root)              → preprocess_result → preprocess_result.json
② build_symbol_graph(preprocess_result) → symbol_graph → symbol_graph.json
③ run_rule_engine(..., symbol_graph=symbol_graph) → violations_l1
④ run_l2_contextualizer(l1_violations=violations_l1, _rejected_tracker=l2_rejected_keys)
      → violations_l2  (집합 l2_rejected_keys: L2가 FP로 본 (file,line,rule) 키)
⑤ post_process_violations(violations_l1, violations_l2, l2_rejected_keys=...)
      → merged_violations
⑥ attach_evidence(merged_violations, top_k=2) → final_violations
      → violations.json (1차 저장: 코드 위반만)
⑦ 패치 루프: generate_patch_for_violation + save_patch (high/medium, 카테고리·총량 상한)
⑧ run_doc_preprocess(root) → doc_preprocess → doc_preprocess_result.json
⑨ load_doc_rules + run_doc_rule_engine → run_doc_l2_contextualizer → attach_evidence → violations_doc
⑩ (선택) doc 패치
⑪ build_code_index(preprocess_result) + run_traceability_checks → violations_trc
⑫ all_violations = final_violations + violations_doc + violations_trc
      → violations.json (최종 덮어쓰기)
      ↓
응답 JSON: job_id, status, violations, violations_count
```

---

### 마지막으로 (보고서 화면을 열 때)

분석이 **끝난 뒤** 사용자가 **GET `/report`** 같은 걸로 보고서를 요청하면, 그때 `write_report_markdown`, `generate_ai_summary` 등이 **추가로** 돌 수 있다.  
**“분석 한 번”의 본체는 위 ①~⑫**이고, 보고서는 **그다음에 예쁘게 꾸미는 단계**라고 보면 된다.

---

## AI 흐름 요약 (LLM·RAG·호출 위치)

### 이 섹션을 쉽게 읽는 법

- **전체 흐름 요약**이 “분석 파이프라인 전체”였다면, 여기서는 그중 **AI(또는 가이드 검색)만** 떼어서 설명한다.
- **LLM(생성형 AI)**: Gemini / OpenAI / 로컬 서버가 **문장을 읽고 JSON·마크다운을 뱉는** 부분이다.
- **RAG(검색)**: `attach_evidence` 등에서 **가이드라인 문단을 찾아 붙이는** 부분이다. 임베딩·Chroma를 쓸 수도 있지만, **답을 “새로 쓰는” LLM과는 역할이 다르다**고 보면 된다.
- **TRC(추적성)** 단계는 **규칙 기반 매칭**이 중심이고, 본 문서 기준 **필수 LLM 호출은 없다** (코드·문서 L2와 구분).

---

### 먼저 이것만: AI가 끼어드는 순서 (한 장짜리)

| 순서 | 이름 | 한 줄로 |
|------|------|---------|
| 1 | **코드 L2** (`run_l2_contextualizer`) | L1이 만든 위반 후보 중 일부를 골라 **코드 맥락 + 가이드**를 넣고 LLM에 **진위 판정** 요청. |
| 2 | **RAG 근거** (`attach_evidence`) | 위반마다 **KCMVP 가이드 문단**을 검색해 `evidence` 필드에 붙임. (LLM이 아니라 **검색·조합**이 핵심) |
| 3 | **코드 패치** (`generate_patch_for_violation`) | 위반·근거를 넣고 **수정 초안 마크다운**을 LLM이 생성. (건수·카테고리 상한 있음) |
| 4 | **문서 L2** (`run_doc_l2_contextualizer`) | 문서 룰로 나온 **semantic/missing** 등을 LLM이 **실제 누락인지** 재판정. |
| 5 | **문서 패치** (`generate_doc_patch_for_violation`) | 문서 위반 중 일부에 **문서 수정 초안**을 LLM이 생성. (상한 있음) |
| 6 | **보고서 AI 요약** (`generate_ai_summary`) | `GET /report` 시 **전체 위반·요약·메타**를 넣어 **한 페이지짜리 요약 문장** 생성. (분석 본체와 별 요청) |

---

### 코드 L2 (`run_l2_contextualizer`) 안에서 일어나는 일

1. **대상 줄이기**  
   - L1 위반이 많으면 전부 LLM에 보내지 않는다. **`_select_l2_candidates`** 로 버킷·상한(대략 **최대 약 60건**) 안에서만 고른다.  
   - 그 전에 **`_l15_name_filter`** 로 변수명만 보고 FP/TP를 가를 수 있으면 **API를 아끼는** 단계가 있다 (L1.5).

2. **가이드 텍스트 넣기**  
   - 룰 ID마다 **`_fetch_guideline_text`** → 내부적으로 **`search_evidence`** 등으로 **프롬프트에 넣을 짧은 가이드**를 만든다.

3. **파일별로 나누기**  
   - 같은 파일의 위반끼리 묶고, **고위험 룰**(`_HIGH_ISOLATION_RULES`)은 **한 건씩** LLM 호출 + **CoT(단계적 추론)** + 점수가 애매하면 **재판정** 프롬프트.  
   - 나머지는 **배치**로 한 번에 여러 위반을 JSON 배열로 받는 방식이 될 수 있다.

4. **백엔드 연동**  
   - LLM이 “오탐”이라고 한 항목은 **`l2_rejected_keys`** 에 넣어 두고, 이후 **`post_process_violations`** 에서 L1 결과에서도 걷어 낸다.

5. **실제 API**  
   - **`L2_PROVIDER`**: `gemini`(기본) / `openai` / `local` — `llm_service`의 **`_call_llm`** → `_call_gemini` / `_call_openai` / `local_llm_service.call_local`.

---

### RAG 근거 (`attach_evidence`) — LLM과 헷갈리지 않기

- **하는 일**: 각 위반에 대해 `rag_service`가 **`search_evidence(rule_id, …)`** 로 가이드 청크를 찾아 **`evidence` 문자열**로 붙인다.
- **LLM과의 관계**: L2 프롬프트 안에도 가이드가 들어가지만, **`attach_evidence` 자체는 “저장용 근거 필드 채우기”**에 가깝다.  
- **Chroma**: 켜 두면 벡터 검색이 보강되고, 아니면 **MD 직접 로드 + TF-IDF** 등으로 동작한다 (`rag_service` 주석 참고).

---

### 패치·문서 AI·보고서 요약

| 함수 | 언제 | 비고 |
|------|------|------|
| `generate_patch_for_violation` | 코드 위반·근거가 있을 때 | **high/medium** 위주, 전체·카테고리별 **상한**으로 개수 제한. |
| `generate_doc_patch_for_violation` | 문서 위반 중 high 등 | **최대 건수** 제한 후 호출. |
| `generate_ai_summary` | **`GET /api/analyze/{id}/report`** 처리 중 | `violations` + `summary` + `meta` → **사용자에게 보여 줄 종합 코멘트** 텍스트. |

---

### AI 전용 흐름도 (함수 이름 중심)

```
                    [L1 위반 목록]
                           │
         ┌─────────────────┼─────────────────┐
         ▼                 ▼                 ▼
   _l15_name_filter   _select_l2_candidates   (일부 스킵)
         │                 │
         └────────┬────────┘
                  ▼
         run_l2_contextualizer
                  │
    ┌─────────────┴─────────────┐
    ▼                           ▼
 고위험 룰: 단독+CoT+재판정     나머지: 배치
    │                           │
    └─────────────┬─────────────┘
                  ▼
         post_process_violations  ← l2_rejected_keys 반영
                  ▼
         attach_evidence  ← search_evidence (RAG, LLM 아님)
                  ▼
         generate_patch_for_violation (루프, 상한)
                  │
                  │  (문서 파이프라인)
                  ▼
         run_doc_l2_contextualizer
                  ▼
         attach_evidence (문서 위반)
                  ▼
         generate_doc_patch_for_violation (선택)
                  │
                  │  (별도 HTTP)
                  ▼
         GET /report → generate_ai_summary
```

---

### 설정으로 바꿀 수 있는 것 (기억해두면 좋음)

| 환경 변수·설정 | 의미 |
|----------------|------|
| `L2_PROVIDER` | `gemini` / `openai` / `local` — 코드·문서 L2·패치 호출 경로가 같이 바뀐다. |
| `GOOGLE_API_KEY`, `GEMINI_L2_MODEL` | Gemini 사용 시. 키 없으면 **코드 L2는 빈 목록** 등으로 동작할 수 있다 (`run_l2_contextualizer` 초반 참고). |
| `OPENAI_API_KEY`, `LLM_MODEL_L2` 등 | OpenAI 선택 시. |
| `RAG_USE_CHROMA`, `CHROMA_PERSIST_DIR` | RAG 검색 방식 보강. |
| `LOCAL_LLM_*` | 로컬 OpenAI 호환 서버 또는 HF 모델 (자세한 건 `local_llm_service` 주석). |

---

## 외부 라이브러리·API 요약 (`backend/requirements.txt` 기준)

### 이 섹션을 쉽게 읽는 법

- **웹(FastAPI + uvicorn)**: 브라우저·프론트가 호출할 **주소(URL)와 업로드**를 받는 창구.
- **설정(pydantic-settings)**: API 키·모델 이름을 **`.env` 파일**에서 읽어온다.
- **룰(PyYAML)**: `COM-001` 같은 규칙이 **사람이 읽기 쉬운 YAML 파일**에 적혀 있고, 프로그램이 dict로 읽는다.
- **C 분석(pycparser)**: 소스 코드를 **문장 구조도(트리)** 로 바꿔서 “어떤 함수가 어디서 불리는지” 본다.
- **AI(google-genai / openai)**: “이게 진짜 위반인지” **문장으로 물어보고 JSON으로 답** 받는다.
- **RAG(Chroma + 임베딩)**: 가이드라인 긴 글에서 **비슷한 문단을 찾아** 위반 옆에 붙인다.
- **PDF(PyMuPDF·pdfplumber)**: 설계서 PDF에서 **글자·표를 긁어** 문서 룰에 넣는다 / 보고서 PDF를 **새로 그린다**.

---

### 한눈에 보는 표 (쉬운 말 + 기술 이름)

| 라이브러리 | 쉬운 설명 | 기술적으로 하는 일 | 주로 쓰는 파일 |
|------------|-----------|---------------------|----------------|
| **FastAPI** | “주소로 요청 오면 함수 실행해 주는 웹 프레임워크” | REST API, 파일·폼 업로드, JSON 응답 | `main.py`, `analyze.py` |
| **uvicorn** | “FastAPI 앱을 실제로 돌리는 서버 프로그램” | 터미널에서 `uvicorn app.main:app` | 실행 시만 (코드에 거의 안 씀) |
| **pydantic-settings** | “`.env`에 적은 값을 Python 변수로” | `BaseSettings`로 `GOOGLE_API_KEY` 등 로드 | `app/config.py` |
| **python-multipart** | “폼으로 파일+글자 같이 올릴 때 뒤에서 해석” | FastAPI가 ZIP+PDF+algorithm을 받을 때 사용 | `POST /api/analyze` (의존) |
| **PyYAML** | “YAML 텍스트 → Python 딕셔너리” | `yaml.safe_load`로 룰 파일 열기 | `rule_engine_service`, `doc_rule_service`, `analyze` |
| **pycparser** | “C 소스를 트리(AST)로 파싱” | `CParser().parse`, `c_ast` 순회 | `preprocess_service`, `ast_checker_service` |
| **google-genai** | “구글 Gemini에 프롬프트 보내기” | `Client` → `generate_content` | `llm_service` |
| **openai** | “OpenAI 채팅 API” | `chat.completions.create` | `llm_service._call_openai` |
| **chromadb** | “문장을 숫자 벡터로 저장해 두고 비슷한 것 검색” | `PersistentClient`, `collection.query` | `rag_service` |
| **sentence-transformers** | “한국어·영어 문장을 벡터로 바꾸는 모델” | Chroma가 내부적으로 로드 (예: bge-m3) | `rag_service` (Chroma 켰을 때) |
| **PyMuPDF (`fitz`)** | “PDF 읽고, 글 쓰고, 페이지 그리기” | `open`, `get_text`, PDF 보고서 생성 | `preprocess_docs_service`, `report_service` |
| **pdfplumber** | “PDF 안의 표(테이블)를 잘 뽑는 도구” | 표 bbox → 본문과 겹침 제거 | `preprocess_docs_service` |
| **requests** | HTTP 요청 라이브러리 | (직접 사용은 거의 없음, 다른 패키지가 쓸 수 있음) | `requirements.txt`만 |

---

### 사용 예시 (실제 코드 패턴)

#### FastAPI — 라우터와 업로드

브라우저가 `POST /api/analyze`로 ZIP·문서를 보내면, 아래처럼 **함수 인자로 파일·폼이 주입**된다.

```python
# app/api/routes/analyze.py (개념)
@router.post("")
async def create_analyze_job(
    file: UploadFile = File(None),
    algorithm: str = Form(None),
):
    content = await file.read()
    job_id = create_job_from_upload(content, file.filename or "upload.zip")
```

`APIRouter`로 `/api/analyze` 아래에 엔드포인트를 모은다 (`main.py`에서 `include_router`).

#### pydantic-settings — `.env` → 설정 객체

```python
# app/config.py (개념 — 실제는 _ENV_FILE = backend/.env 로 고정)
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    GOOGLE_API_KEY: str = ""
    GEMINI_L2_MODEL: str = "gemini-2.5-flash-lite"
    class Config:
        env_file = "/절대경로/backend/.env"  # 실제 코드는 Path로 지정
        extra = "ignore"

settings = Settings()
```

이후 `settings.GOOGLE_API_KEY`처럼 어디서든 읽는다 (실행 cwd와 무관하게 **`backend/.env`** 를 쓴다).

#### PyYAML — 룰 파일 읽기

```python
import yaml
with open("rules/common/com.yaml", encoding="utf-8") as f:
    data = yaml.safe_load(f)
# data["rules"] 안에 id, pattern_type, pattern 등이 들어 있음
```

`rule_engine_service`는 이렇게 읽은 룰을 돌며 `regex` / `missing` 등으로 분기한다.

#### pycparser — C 한 덩어리를 트리로

```python
from pycparser import c_parser
parser = c_parser.CParser()
ast = parser.parse(preamble + source_code, filename="foo.c")
# preprocess_service는 이 결과에서 함수 이름, 호출 목록 등을 뽑아 dict로 만든다.
```

`ast_checker_service`는 여기서 더 깊게 `c_ast` 노드를 돌며 LEA-003 같은 **구조 조건**을 본다.

#### google-genai — Gemini 한 번 호출

```python
import google.genai as genai

client = genai.Client(api_key=GOOGLE_API_KEY)
response = client.models.generate_content(
    model="gemini-2.5-flash-lite",
    contents="다음 C 코드가 COM-003 위반인지 JSON으로 답하라:\n...",
)
text = response.text  # 또는 candidates에서 추출 — llm_service._call_gemini 참고
```

실제로는 `_call_gemini_with_retry`가 JSON 파싱 실패 시 프롬프트에 한 줄 덧붙여 재시도한다.

#### openai — GPT 계열 (설정이 openai일 때)

```python
from openai import OpenAI
client = OpenAI(api_key=OPENAI_API_KEY)
resp = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": prompt}],
    temperature=0,
)
answer = resp.choices[0].message.content
```

`L2_PROVIDER=openai`일 때 `_call_openai`가 위와 같이 호출되고, 실패하면 Gemini로 넘어간다.

#### chromadb + 임베딩 — “가이드 중에서 이 룰과 관련된 문단 찾기”

```python
import chromadb
from chromadb.utils import embedding_functions

client = chromadb.PersistentClient(path="/path/to/chroma_data")
ef = embedding_functions.SentenceTransformerEmbeddingFunction(model_name="BAAI/bge-m3")
col = client.get_or_create_collection("kcmvp_guidelines", embedding_function=ef)
col.add(documents=["...가이드 본문 청크..."], ids=["chunk_0"], metadatas=[{"rule_id": "COM-001"}])

results = col.query(query_texts=["잔존정보 제거 memset"], n_results=2, where={"rule_id": "COM-001"})
# results["documents"] 에 가장 가까운 문단들이 들어옴
```

`RAG_USE_CHROMA=false`이거나 패키지 미설치면, 같은 파일 안에서 **MD 직접 로드 + TF-IDF**로 비슷한 일을 한다.

#### PyMuPDF — PDF에서 글자 뽑기 / 새 PDF 만들기

```python
import fitz  # PyMuPDF

# 읽기 (문서 전처리)
doc = fitz.open("설계서.pdf")
for page in doc:
    blocks = page.get_text("blocks")

# 쓰기 (보고서 PDF)
out = fitz.open()
page = out.new_page()
page.insert_text((72, 72), "KCMVP 보고서")
out.save("report.pdf")
```

`preprocess_docs_service`는 표 영역을 빼기 위해 블록 좌표를 쓰고, `write_report_pdf`는 카드·표 레이아웃을 그린다.

#### pdfplumber — 표만 정확히

```python
import pdfplumber
with pdfplumber.open("설계서.pdf") as pdf:
    for page in pdf.pages:
        tables = page.extract_tables()
# 표의 bbox는 본문 텍스트와 겹치지 않게 뺀다 (중복 방지)
```

---

### 표준 라이브러리 (Python 기본만으로 하는 일)

| 모듈 | 쉬운 설명 | 예시 |
|------|-----------|------|
| **asyncio** | “무거운 작업은 다른 스레드로” | `await asyncio.to_thread(_run_pipeline_sync, root, ...)` |
| **zipfile** | “ZIP 풀기” | `upload_service`에서 업로드 바이트 → job 폴더에 파일 생성 |
| **subprocess** | “gcc로 전처리” | `ast_checker`가 `gcc -E`로 C를 펼친 뒤 파싱 |
| **urllib.request** | “HTTP POST (로컬 LLM 서버)” | `local_llm_service`가 llama.cpp 호환 `/v1/chat/completions` 호출 |
| **re / json / hashlib / Counter** | “정규식·JSON·캐시키·단어 빈도” | 룰 매칭, L2 캐시, RAG TF-IDF |

**선택**: `torch` + `transformers` — 로컬에서 HuggingFace 모델을 직접 돌릴 때만 (`local_llm_service` Pattern B).

---

### API 호출 빈도가 큰 부분 (운영 시 유의)

| 구분 | 비고 |
|------|------|
| **Gemini / OpenAI** | L2 판정·재판정·패치·(보고서) AI 요약 — 호출 수·토큰이 비용·지연의 대부분. |
| **Chroma + sentence-transformers** | 최초 적재 시 모델 로드·임베딩 비용; 이후는 로컬 디스크 `CHROMA_PERSIST_DIR` 재사용. |
| **pycparser / gcc -E** | 파일 수·라인 수에 선형; `ast_checker`의 gcc 경로는 도구 설치 여부에 의존. |
| **PDF** | 페이지 수·표 수에 비례; PyMuPDF+pdfplumber 이중 패스. |

---

## 지금 해야 할 일 (문서·코드 기준 정리)

### 이 섹션을 쉽게 읽는 법

- **우선순위 표**: 코드·문서 기준으로 **아직 남은 과제**를 정리한 체크리스트다.
- **“높음”**: 정확도·누락(FN)에 직결되는 **먼저 손댈 항목**에 가깝다.
- **“중간”**: 비용·문서화·튜닝처럼 **다음 라운드**에서 다룰 이슈.
- **“낮음”**: 실험·선택 적용 등 **여유 있을 때** 검토.
- **완료하면**: 해당 행을 지우거나 “완료”로 바꾸고, **위의 다른 절(§2·§3·§4)** 과 코드를 같이 맞추면 된다.

---

아래는 본 마크다운 §4 및 실제 코드와 맞춘 **우선 과제**다. 완료 시 이 절을 갱신하면 된다.

| 우선순위 | 내용 | 비고 |
|----------|------|------|
| 높음 | **semantic `missing` 한계** — “보안 함수 자체가 없음” FN 줄이기: 룰을 `missing`으로 보강하거나 AST 체커 추가 | §2-4, v4 FN 관련 |
| 높음 | **`pattern_type` 누락** 위반의 L2 경로 정리 — 생성 시 항상 채우거나 L2에서 기본값 처리 | §4 표 |
| 중간 | **L2 후보 상한 60건** 초과분 정책 문서화 또는 상한/버킷 조정 | 비용·정확도 트레이드오프 |
| 중간 | **confidence 임계값(예: 70)** 설계 근거를 `llm_service` 주석 또는 별도 docs에 명시 | §3-7 |
| 중간 | **COM-003 / L1.5 FP 키워드** 목록 유지보수 (과탐·미탐 균형) | §2-3, §3-2 |
| 낮음 | **고립 룰 `_HIGH_ISOLATION_RULES`** 확장·축소 검토 | §3-4 |
| 낮음 | **배치 프롬프트에 CoT 선택 적용** 여부 실험 | §3-8 |

**문서 유지보수**: `analyze.py`의 단계 번호·함수명이 바뀌면 **본 문서의 표·요약 다이어그램**을 같이 수정할 것.

---

## 정확도를 높이기 위한 전략 (FN·FP·비용 균형)

### 이 섹션을 쉽게 읽는 법

- **정확도**를 말할 때 보통 **누락(FN)** 과 **오탐(FP)** 을 동시에 말한다. 한쪽만 좋아지면 다른 쪽이 나빠질 수 있어 **트레이드오프**가 항상 있다.
- **L1**은 빠르고 값이 싸지만 표현력에 한계가 있고, **L2**는 맥락은 좋지만 API 비용·지연이 크다. 그래서 “어디까지 규칙으로 할지, 어디부터 AI로 할지”가 전략의 핵심이다.
- 아래는 **이미 코드에 들어 있는 설계**와 **앞으로 조정할 수 있는 손잡이**를 함께 적었다. `지금 해야 할 일` 절과 겹치는 항목은 **실행 과제**로, 여기서는 **원칙** 위주로 읽으면 된다.

---

### 한눈에: 레이어별로 무엇이 정확도에 기여하나

| 레이어 | 주로 줄이는 것 | 아이디어 한 줄 |
|--------|----------------|----------------|
| **L1 (정적)** | 불필요한 후보(FP)·명백한 패턴 | AST·심볼그래프 우선, **키워드·룰 타입**으로 조기 필터 |
| **L1.5 (이름 필터)** | L2로 보낼 FP | 변수명·스니펫만으로 **API 호출 전** 걸러 냄 |
| **L2 (LLM)** | 맥락 오류·L1의 한계 | **고위험 단독+CoT+재판정**, 배치로 비용 절감, **JSON 재시도** |
| **RAG (`attach_evidence`)** | “근거 없는 판정” 체감 | 가이드 **검색 품질**·`top_k`·매핑(`rule_to_guideline.json`) |
| **데이터·룰** | 재현 가능한 품질 | **골든 샘플**·문서 정확도 스크립트·룰 YAML 리뷰 |

---

### L1에서: 오탐·누락을 줄이는 쪽

| 전략 | 설명 | 비고 |
|------|------|------|
| **탐지 순서 설계** | 예: COM-001은 AST `file_calls` → **심볼 그래프(크로스 파일)** → 정규식 순으로 본다. 앞 단계가 정확할수록 뒤 **노이즈 감소**. | `rule_engine_service` |
| **regex 룰의 사전 FP 제거** | COM-003처럼 **S-box·델타·KAT** 등 알려진 오탐은 L1에서 **키워드로 스킵**해 L2 부담을 줄인다. | 키워드 목록은 **데이터에 맞춰** 주기적 튜닝 |
| **`pattern_type` 선택** | “함수가 아예 없음”은 **`missing`** 이 잘 맞고, “잘못 쓴 경우”는 **regex/ast** 가 맞는 식으로 **룰 설계**를 나눈다. semantic만으로는 **키워드 없는 FN** 이 생기기 쉽다. | §2-4, `지금 해야 할 일` 과 연계 |
| **AST 체커 + 폴백** | 구조가 확실할 때만 AST로 위반을 내고, 애매하면 **fallback 정규식** 또는 **후보+ L2** 로 넘긴다. FP를 줄이려는 **보수적** 설계. | `ast_checker_service` |
| **전처리 품질** | pycparser/gcc 실패 시 AST가 비면 L1·L2 모두 약해진다. **헤더·매크로** 환경을 맞추는 것도 정확도의 전제다. | `preprocess_service` |

---

### L2에서: 판정 품질과 비용의 균형

| 전략 | 설명 | 비고 |
|------|------|------|
| **후보 상한·버킷** | L1 위반이 많아도 **ast / high / 기타** 버킷으로 나눠 한 룰이 독점하지 않게 한다. **전체 상한(~60건)** 으로 비용 상한도 잡는다. | 상한을 올리면 정확도는 오를 수 있으나 **비용·지연** 증가 |
| **L1.5 이름 필터** | `_l15_name_filter` 로 **FP 이름·TP 이름**을 사전에 나눠, 불필요한 L2 호출을 줄인다. | COM-003 L1 필터와 **역할이 겹치지만 적용 범위가 다름** (§3-2) |
| **고위험 룰 단독 처리** | `_HIGH_ISOLATION_RULES` 는 배치에 섞이지 않게 **한 건씩** 판정. **CoT** 로 단계적 추론, 점수 **65–74** 구간은 **재판정** 프롬프트로 경계 오판 완화. | 컨텍스트 오염 방지 |
| **프롬프트** | `PROMPT_TEMPLATES` 로 룰별 기준을 나누고, **오탐 조건·위반 조건**을 명시해 모델을 **보수적으로** 맞춘다. | 룰 추가 시 템플릿 동반 |
| **코드 컨텍스트** | `slice_code`·`extract_global_skeleton` 등으로 **토큰은 줄이되** 판정에 필요한 줄은 넣는다. | 라인 없는 semantic 등 |
| **temperature 0** | `_call_openai` 등에서 **0** 으로 두어 재현성·보수성을 높인다. | |
| **JSON 파싱 재시도** | `_call_gemini_with_retry` 등으로 **형식 오류 시** 한 줄 힌트를 붙여 재호출. | |
| **`l2_rejected_keys` 연동** | L2가 FP로 본 항목을 L1 결과에서도 제거해 **최종 목록 일관성** 유지. | `post_process_violations` |
| **confidence 임계값** | 예: 점수 **70** 미만은 “후보” 등 — **확정/후보** 라벨 정책을 문서화해 두면 운영·보고서 기준이 안정된다. | 설계 근거를 코드 주석·본 문서에 남기기 |

---

### RAG·근거 (LLM과 구분)

| 전략 | 설명 |
|------|------|
| **`rule_to_guideline.json` 품질** | 룰 ID와 가이드 파일·검색어가 어긋나면 **근거 필드가 빗나간다**. 매핑을 룰 추가·변경 때 같이 검토한다. |
| **Direct MD vs TF-IDF vs Chroma** | `search_evidence` 우선순위에 따라 동작한다. **Chroma** 는 의미 유사 검색에 유리하나 **적재·모델 비용**이 있다. 환경에 맞게 `RAG_USE_CHROMA` 등을 선택한다. |
| **`top_k`** | `attach_evidence`·프롬프트 주입에서 **너무 크면 노이즈**, 너무 작으면 근거 부족. 룰별로 조정 여지가 있다. |

---

### 문서·패치 AI (부가)

| 전략 | 설명 |
|------|------|
| **문서 L2** | `run_doc_l2_contextualizer` 는 **semantic/missing** 등을 **문서 전체 발췌**와 함께 재판정한다. **후보 상한**으로 비용을 제한한다. |
| **패치 생성** | `generate_patch_for_violation` / `generate_doc_patch_for_violation` 은 **수정 제안**용이며, 상한·심각도 필터로 **호출 횟수**를 제한한다. 판정 정확도와는 별개로 **사용자 체감 품질**에 영향. |
| **보고서 요약** | `generate_ai_summary` 는 **집계된 결과**를 요약하므로, 앞 단계 판정이 맞아야 요약도 의미가 있다. |

---

### 측정·운영 (정확도를 “관리”하려면)

| 전략 | 설명 |
|------|------|
| **골든 샘플·회귀** | 알려진 **양성/음성** 코드·ZIP을 두고 룰·프롬프트 변경 후 **위반 건수·rule_id** 가 기대와 맞는지 비교한다. |
| **문서 정확도 스크립트** | `backend/scripts` 계열의 **doc accuracy** 테스트는 DOC 룰·L2와 함께 **정밀도 재현**에 쓸 수 있다. |
| **모델·프로바이더** | `GEMINI_L2_MODEL`, `L2_PROVIDER` 변경 시 **재측정**이 필요하다. 가벼운 모델은 비용 대비 속도가 좋고, 무거운 모델은 어려운 케이스에서 유리할 수 있다. |
| **모니터링** | 운영 중 **재현되는 FP rule_id**·**L2 스킵(상한 초과)** 비율을 보면 다음 튜닝 우선순위가 잡힌다. |

---

### 정리: 우선 손대기 좋은 순서 (권장)

1. **룰·pattern_type** 정리로 L1 **FN/FP** 구조 개선 (가장 값싼 반복).
2. **L1.5·COM-003 키워드** 튜닝으로 **L2 호출 전** 노이즈 감소.
3. **프롬프트·고위험 룰 목록** 조정으로 L2 **판정·경계 구간** 안정화.
4. **RAG 매핑·검색 방식**으로 근거·프롬프트 맥락 품질 개선.
5. **상한·버킷·모델**은 비용 허용 범위 안에서 **단계적으로** 올리거나 바꾼다.

`지금 해야 할 일` 표의 항목은 위 원칙을 **구체 이슈**로 쪼개 둔 것으로 같이 보면 좋다.

---

## 1. analyze.py — 파이프라인 진입점

### 이 섹션을 쉽게 읽는 법

- **`analyze.py`만 파도** HTTP로 들어온 분석 요청이 **어떤 순서로 처리되는지** 전부 나온다.
- **`asyncio.to_thread`**: 서버가 멈추지 않게 **무거운 작업을 스레드로 넘기는** 이야기다.
- **표(1-2)**: 각 단계의 **함수 이름·변수 이름·저장 파일**을 한 번에 보려는 용도다.
- **패치 우선순위**: 위반이 많을 때 **어떤 것부터 패치 초안을 만들지** 정하는 규칙이다.

---

### 1-1. `asyncio.to_thread`: 이벤트 루프 보호

```python
# analyze.py (create_analyze_job 내부)
result = await asyncio.to_thread(
    _run_pipeline_sync, root, algorithm, mode
)
```

**왜 중요한가?**

FastAPI는 싱글 스레드 비동기(asyncio) 서버다.  
`async def` 안에서 **느린 동기 함수**를 직접 호출하면 그 구간 동안 다른 HTTP 요청 처리가 지연된다.

**핵심 규칙**: `async def` 안에서 무거운 동기 작업은 `await asyncio.to_thread(fn, *args)` 로 넘긴다.

---

### 1-2. `_run_pipeline_sync` — 함수·변수 이름 정리

| 단계 | 주요 함수 | 입력(변수) | 출력(변수) | 저장 파일 |
|------|-----------|------------|------------|-----------|
| 코드 전처리 | `run_preprocess` | `root` | `preprocess_result` | `preprocess_result.json` |
| 심볼 그래프 | `build_symbol_graph` | `preprocess_result` | `symbol_graph` | `symbol_graph.json` |
| L1 | `run_rule_engine` | `preprocess_result`, `RULES_DIR`, `job_root=root`, `algorithms`, `modes`, `symbol_graph` | `violations_l1` | — |
| L2 | `run_l2_contextualizer` | `preprocess_result`, `l1_violations=violations_l1`, `rules_meta`, `_rejected_tracker=l2_rejected_keys` | `violations_l2` | — |
| 병합 | `post_process_violations` | `violations_l1`, `violations_l2`, `l2_rejected_keys` | `merged_violations` | — |
| RAG | `attach_evidence` | `merged_violations`, `top_k=2` | `final_violations` | `violations.json`(중간) |
| 코드 패치 | `generate_patch_for_violation`, `save_patch`, `slice_code` | `final_violations`, `preprocess_result` | `patches/*.md` | — |
| 문서 | `run_doc_preprocess`, `load_doc_rules`, `run_doc_rule_engine`, `run_doc_l2_contextualizer`, `attach_evidence` | `root`, `doc_rules`, `doc_preprocess` | `violations_doc` | `doc_preprocess_result.json` |
| TRC | `build_code_index`, `run_traceability_checks` | `preprocess_result`, `design_sections`, `test_sections`, `trc_rules` | `violations_trc` | — |
| 최종 합치기 | (인라인) | `final_violations`, `violations_doc`, `violations_trc` | `all_violations` | `violations.json`(최종) |

**의미 있는 변수명 요약**

| 변수명 | 의미 |
|--------|------|
| `root` | job 작업 디렉터리 (`Path`). 업로드·전처리·JSON 산출물의 기준 경로. |
| `algorithm`, `mode` | 폼에서 온 룰셋 필터. `job_meta.json` 및 `run_rule_engine`에 전달. |
| `preprocess_result` | `files[]` / `errors` 등 — L1·L2·인덱싱의 단일 소스. |
| `symbol_graph` | 크로스 파일 호출·제로화 파일 목록 — 주로 COM-001. |
| `violations_l1` | L1만의 위반 후보 목록. |
| `l2_rejected_keys` | L2가 FP로 판정한 항목 키 집합. `post_process_violations`에서 L1 항목도 제거하는 데 사용. |
| `violations_l2` | L2가 판정·수정한 위반 목록. |
| `merged_violations` | L1+L2 병합·중복·FP 제거 후. |
| `final_violations` | 근거(`evidence`) 첨부된 **코드** 위반. |
| `doc_preprocess` | PDF 섹션 구조. |
| `violations_doc` | 문서 룰 + (선택) 문서 L2 + evidence. |
| `violations_trc` | 추적성 룰 위반. |
| `all_violations` | 코드 + 문서 + TRC 리스트 합본 — 프론트/보고서 최종 입력. |

---

### 1-3. 패치 우선순위 정렬

```python
def _patch_priority(v):
    conf_rank = 0 if (v.get("confidence") == "확정") else 1
    sev_rank  = 0 if (v.get("severity") or "").lower() == "high" else (
                1 if (v.get("severity") or "").lower() == "medium" else 2)
    return (conf_rank, sev_rank)
```

| 변수 | 의미 |
|------|------|
| `_patch_count` / `_MAX_PATCH_TOTAL` | 생성한 패치 개수 / 전체 상한(20). |
| `_cat_counts` / `_MAX_PATCH_PER_CAT` | 룰 ID 접두(COM, LEA, …)별 개수 / 카테고리당 상한(3). |
| `_rule_id`, `_file`, `_line`, `_msg`, `_evidence`, `_snippet` | 패치 생성에 넘기는 위반 필드·`slice_code`로 뽑은 주변 코드. |

패치는 "확정 + high" 우선, 카테고리당 최대 3개로 균형.

---

## 2. rule_engine_service.py — L1 룰 엔진

### 이 섹션을 쉽게 읽는 법

- **L1**: AI 없이 **정규식·AST·누락 여부**로 “위반 후보”를 만드는 층이다.
- **`pattern_type`**: 같은 룰 엔진이라도 **missing / regex / semantic / ast** 마다 완전히 다른 로직으로 돈다 — 먼저 이 네 가지를 머릿속에 나눠 두면 된다.
- **소절 2-2~2-6**: 대표적인 **COM-001, COM-003, semantic 한계, COM-005, AST 폴백**만 예시로 짚은 것이다.
- **YAML 파일**은 `rules/`에 있고, 이 절은 **그걸 어떻게 코드가 해석하는지**에 가깝다.

---

### 2-1. `pattern_type`별 분기 구조

L1 룰 엔진의 핵심은 `_apply_rule_to_file()` 함수다.  
YAML 룰의 `pattern_type`에 따라 동작이 달라진다.

```text
pattern_type == "missing"   → 패턴이 없으면 위반
pattern_type == "regex"     → 매칭마다 위반
pattern_type == "semantic"  → 키워드 있으면 AI 검토 대상, 없으면 후보 위반
pattern_type == "ast"       → pycparser AST / 폴백 정규식 / 파일 레벨 후보
```

---

### 2-2. missing 룰: COM-001 (잔존정보 제거)

**3단계 우선순위**: AST `file_calls` → `symbol_graph` (`call_graph`, `files_with_clearing_call`) → 원문 정규식.

`memset` 미인정 이유: 컴파일러 최적화로 제거될 수 있어 `memset_s`, `explicit_bzero` 등만 허용.

---

### 2-3. regex 룰: COM-003 L1 필터 (하드코딩 키)

`_COM003_FP_KEYWORDS` — S-box·델타·KAT 등 알려진 FP는 L1에서 스킵.

---

### 2-4. semantic 룰의 구조적 한계

키워드가 없으면 "함수 없음" 유형을 놓칠 수 있음 → FN.  
완화: `missing` 룰 분리 또는 AST 체커 추가.

---

### 2-5. COM-005: 라인 레벨 순서 검사

`init_lines`, `update_lines`, `final_lines` 로 최소 줄 번호 비교.

---

### 2-6. AST 룰: 3단계 폴백

`ast_checker_service` 체커 → `fallback_pattern` 정규식 → 파일 레벨 후보.

---

## 3. llm_service.py — L2 AI 판정

### 이 섹션을 쉽게 읽는 법

- **L2**: L1이 만든 후보를 **Gemini(또는 OpenAI)** 에 넘겨 “진짜 위반인지” **다시 판정**하는 층이다.
- **L1.5 이름 필터**: AI를 부르기 전에 **변수명만 보고** 명확히 FP/TP를 가를 수 있으면 API를 아낀다.
- **버킷·60건 상한**: 한 룰이 전부 독점하지 않게 **종류별로 나눠** L2에 보낸다.
- **고위험 룰 단독 처리**: 보안상 중요한 룰은 **배치로 묶지 않고** CoT·재판정으로 신중히 본다.
- **아래 소절**: 흐름도 → 필터 → 후보 선정 → 프롬프트·점수 순으로 읽으면 된다.

---

### 3-1. 전체 L2 흐름

```
L1 위반 목록
    ↓
[L1.5] _l15_name_filter()    변수명 기반 사전 필터
    ↓
_select_l2_candidates()      버킷 방식 (상한 약 60건)
    ↓
RAG 가이드라인 (룰별)
    ↓
파일별 그룹화 — 고위험 룰(_HIGH_ISOLATION_RULES) 단독+CoT+재판정 / 나머지 배치
    ↓
Gemini → confidence 라벨 (예: ≥70 확정)
```

---

### 3-2. L1.5 이름 필터

`_L15_FP_NAMES`, `_L15_TP_NAMES`, `_l15_name_filter(violation)` — L2 호출 전 결정론적 필터.

---

### 3-3. L2 대상 선정: 버킷

ast / high sev / 기타 버킷으로 상한 분산.

---

### 3-4. 고위험 룰 단독 처리

`_HIGH_ISOLATION_RULES`, `_build_single_prompt(..., use_cot=True)`, `_build_rejudge_prompt` — 65–74 구간 재판정.

---

### 3-5. 코드 컨텍스트 (`_get_code_context` 등)

`slice_code`, `extract_global_skeleton`, `_find_function_boundary` — 토큰 절약·맥락 유지.

---

### 3-6. 프롬프트

`PROMPT_TEMPLATES`, `_build_single_prompt`, `_build_rejudge_prompt` — 룰별 기준·오탐 조건.

---

### 3-7. confidence 기준

`confidence_label = "확정" if score >= 70 else "후보"` (코드 기준으로 본 문서 정렬).

---

### 3-8. 배치 vs 단독

배치는 호출 수 절감, 단독은 정확도·컨텍스트 오염 방지.

---

## 4. 주요 버그 및 설계 이슈 정리

### 이 섹션을 쉽게 읽는 법

- **알려진 문제 표**: “지금 코드/데이터에서 **어디가 약한지**”를 한눈에 모은 것이다.
- **영향 열**: 사용자·보고서에 어떻게 **드러나는지 (FN/FP/미판정)** 를 짐작할 때 쓴다.
- **개선 방향**: 표를 바로 **다음 스프린트 과제**로 바꿀 때 참고하는 불릿이다.
- **§2·§3과 연결**: 같은 주제가 **L1 한계**인지 **L2 한계**인지 구분해 읽으면 된다.

---

### 현재 알려진 문제

| 문제 | 위치 | 영향 |
|------|------|------|
| semantic 룰 FN | `rule_engine_service.py` | "보안 함수 없음" 패턴 탐지 어려움 |
| safe_code 등 FP | 데이터·룰 조합 | 보고서 노이즈 |
| L2 candidate 상한 | `llm_service.py` | 60건 초과는 AI 미판정 |
| confidence 임계값 | `llm_service.py` | 기준 문서화 필요 |
| pattern_type 누락 | 위반 객체 | L2 스킵 가능성 |

### 개선 방향

- missing / ast / regex 역할 분리 재검토  
- L1.5·COM-003 키워드 튜닝  
- 임계값·고립 룰·배치 CoT 실험  

---

## 5. 데이터 흐름 요약

### 이 섹션을 쉽게 읽는 법

- **`violations` 한 건**이 프론트·`violations.json`·보고서에 **어떤 필드로** 나가는지 정리한 절이다.
- **필드 이름**만 보면 “어디가 L1 / L2 / RAG 근거인지” 대략 짐작할 수 있다.
- **JSON 예시**는 실제 스키마 전부가 아니라 **대표 필드**만 적어 두었다.

---

```
violations 객체 구조 (대표 필드):
{
  "rule_id": "COM-003",
  "file": "src/lea_impl.c",
  "line": 42,
  "scope": "line-range",
  "message": "...",
  "severity": "high",
  "confidence": "확정",
  "confidence_score": 82,
  "snippet": "...",
  "pattern_type": "regex",
  "source": "L2",
  "l2_confirmed": true,
  "suggestion": "...",
  "evidence": "..."
}
```

### 필드별 의미 (위 예시 기준)

| 필드 | 대략 타입 | 무엇을 나타내나 | 프론트·보고서에서의 쓰임 |
|------|-----------|-----------------|---------------------------|
| **`rule_id`** | 문자열 | KCMVP 룰 식별자 (예: `COM-003`, `LEA-010`, `DOC-001`, `TRC-001`). | 목록 정렬·필터·카테고리(접두 COM/LEA/…) 구분, RAG·패치 시 키. |
| **`file`** | 문자열 | **코드 위반**: job 루트 기준 상대 경로 (예: `src/lea_impl.c`). **문서 위반**: `doc_design` 같이 논리 경로 또는 PDF 경로 조각일 수 있음. **TRC**: 설계·코드·시험 연결 문맥에 맞는 식별 문자열. | 파일 트리 하이라이트, `GET /file?path=…` 로 소스 열기, 보고서 “위치” 열. |
| **`line`** | 정수 또는 `null` | 위반이 가리키는 **소스 줄 번호**. `missing`·파일 단위·문서 위반 등에서는 **`null`** 인 경우가 많다. | 코드 에디터 줄 이동; `null` 이면 파일 전체만 강조하거나 줄 강조 생략. |
| **`scope`** | 문자열 | 위반 범위 표시 (예: `line`, `line-range`, `file`). 구현·룰에 따라 다를 수 있다. | UI에서 “한 줄” vs “구간” vs “파일 단위” 표시 보조. |
| **`message`** | 문자열 | 사람이 읽는 **위반 설명**. L1이면 룰의 `name`/메시지 템플릿, L2 통과 후면 **모델이 다듬은 설명**일 수 있다. | 리포트 본문·툴팁·요약에 그대로 노출. |
| **`severity`** | 문자열 | `high` / `medium` / `low` 등 **심각도**. 패치 생성 상한·정렬에 쓰인다. | 대시보드 색상·정렬, 패치 후보 필터 (`analyze.py`에서 high/medium만 패치 등). |
| **`confidence`** | 문자열 | `"확정"` 또는 `"후보"` 등 **신뢰도 라벨**. `report_service._confidence` 규칙으로 없을 때 보완되기도 한다. | “검토 필요” 배지, 보고서 요약 집계. |
| **`confidence_score`** | 정수(0~100) 또는 없음 | L2가 준 **숫자 점수**. L1만 거친 항목에는 없을 수 있다. | 세부 정렬, 재판정 구간(예: 65–74) 설명 시 참고. |
| **`snippet`** | 문자열 | 문제가 된 코드 **한 줄 또는 짧은 발췌**. L2 프롬프트·패치 생성에도 사용. | 화면에 코드 미리보기, 패치 문맥. |
| **`pattern_type`** | 문자열 | `missing` / `regex` / `semantic` / `ast` 등 **L1이 어떤 방식으로 잡았는지**. | L2 후보 선정·코드 슬라이스 범위 분기; **누락 시 L2 경로가 꼬일 수 있어** `지금 해야 할 일`에도 언급됨. |
| **`source`** | 문자열 | `"L1"` / `"L2"` 등 **어느 층에서 최종적으로 확정된 느낌**을 줄 때 사용 (병합 결과에 따라 다름). | 출처 표시, 통계. |
| **`l2_confirmed`** | 불리언 | L2를 거쳐 **위반으로 유지**되었는지 등. | `confidence` 보완 로직과 연동 (`report_service._confidence`). |
| **`suggestion`** | 문자열 | L2 또는 패치 흐름에서 나온 **수정 방향 제안** 문장. | 사용자 액션 가이드, 패치와 별도로 짧은 권고 표시. |
| **`evidence`** | 문자열 | `attach_evidence` 이후 붙는 **KCMVP 가이드라인 인용·출처** 텍스트 (RAG 검색 결과). | 보고서·상세 패널에서 “근거” 접기/펼치기. |

### 자주 같이 오는 추가 필드 (예시에 없을 수 있음)

| 필드 | 설명 |
|------|------|
| **`needs_ai_review`** | `true`이면 L2 전 **후보** 상태로 볼 수 있다. `pattern_type`이 `semantic` 등일 때 흔하다. |
| **`doc_type`** | 문서 위반(`DOC-*`, `CM-*` 등)에서 `design` / `config_mgmt` / `test` 등 **어떤 PDF 묶음**인지. |
| **`section`**, **`title`** | 문서 룰이 가리키는 **섹션 제목**·식별자. 문서 뷰어에서 해당 구간으로 안내할 때 사용. |
| **`l2_rejected` 관련 메타** | 병합 과정에서 L2가 FP로 처리한 항목은 최종 목록에서 빠지므로, 최종 JSON에는 **남지 않을 수 있다**. (추적은 `l2_rejected_keys` 등 파이프라인 내부.) |

### 중복 제거·식별 팁

- **`GET /report`** 등에서는 `(rule_id, file, line)` 조합으로 **중복 위반을 한 건으로 합치는** 처리가 있다 (`analyze.py`).  
  TRC처럼 **같은 `rule_id`라도 `file`·`line`이 다르면** 별건으로 남는다.

---

## 참고: 파이프라인 단계별 소요 시간 (대략)

### 이 섹션을 쉽게 읽는 법

- **대략적인 초**만 적어 두었다 — **실제는 파일 수·PDF·L2 건수**에 따라 크게 달라진다.
- **L2 행이 길게 나온 이유**: 전체 대기 시간의 **대부분이 여기**서 나온다고 보면 된다.
- **`asyncio.to_thread` 한 줄**: 분석이 오래 걸려도 **다른 HTTP 요청이 같이 처리**되려면 이게 필요하다는 뜻이다.

---

| 단계 | 소요 시간 | 비고 |
|------|-----------|------|
| preprocess | 1~3초 | 파일 수에 비례 |
| symbol_graph | ~0.5초 | |
| L1 rule_engine | 1~5초 | 룰 수에 비례 |
| L2 Gemini | 30초~3분 | 후보 건수·배치에 비례 |
| doc_preprocess | 1~10초 | PDF 크기 |
| doc_rule_engine + doc L2 | 가변 | |
| TRC | ~0.5초 | |

전체 시간의 대부분은 L2(Gemini) 호출이다. `asyncio.to_thread` 없이 동기 파이프라인을 `async` 안에서 직접 호출하면 그 구간 동안 서버 응답성이 크게 떨어진다.
