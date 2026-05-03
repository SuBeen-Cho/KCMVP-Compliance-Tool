# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

KCMVP (Korea Cryptographic Module Validation Program) Pre-Compliance Validation Tool — a full-stack web application that validates cryptographic module source code and documentation before official submission.

## Development Commands

### Backend (FastAPI + Python 3.10+)

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp ../.env.example .env
# Set GOOGLE_API_KEY for L2 LLM analysis

uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
# Health check: http://localhost:8000/api/health
# Swagger UI: http://localhost:8000/docs
```

### Frontend (React + Vite + Node 18+)

```bash
cd frontend
npm install
npm run dev        # Dev server at http://localhost:5173
npm run build      # Production build
```

### Docker (full stack)

```bash
docker-compose up -d
```

### Testing

```bash
cd backend && source venv/bin/activate
python scripts/create_sample_zip.py    # Generate basic test ZIP
python scripts/create_sample_zip_2.py  # Generate advanced test ZIP
python scripts/test_upload.py          # Test API endpoints

# Pre-built datasets (backend/testdata/):
#   accuracy_test_v12.zip              — latest accuracy test
#   fake_design_doc.pdf                — intentional violations: DOC-003, DOC-012, DOC-022, DOC-040, DOC-048
#   SECUI설계서.pdf / sifr_kit설계서 예시.pdf / 한컴위드설계서예시.pdf — real design doc examples

# Clear analysis artifacts (safe):
rm -rf backend/storage/jobs/*
```

## Architecture

The system implements a **5-layer compliance validation pipeline**:

```
Upload (ZIP/GitHub + PDFs)
  → Preprocess     — AST parse C/C++; extract PDF sections/tables
  → L1 Rule Engine — YAML pattern matching (missing/regex/semantic)
  → L2 LLM         — Gemini semantic judgment on L1 findings
  → DOC Rules      — PDF structure validation
  → TRC            — Design↔code↔test traceability [stub]
  → Report         — Aggregated violations + severity counts
```

### Pipeline Services (`backend/app/services/`)

Each service writes a JSON artifact to `storage/jobs/{job_id}/`:

| Service | Output artifact | Description |
|---|---|---|
| `upload_service.py` | `src/`, `docs/` | Extracts ZIP → src/; saves PDFs → docs/{design,scm,test}/ |
| `preprocess_service.py` | `code_preprocess.json` | Strips C/C++ comments, parses AST via pycparser |
| `preprocess_docs_service.py` | `doc_preprocess_result.json` | PDF sections + tables via PyMuPDF + pdfplumber |
| `symbol_graph_service.py` | `symbol_graph.json` | Cross-file function call graph (libclang primary, pycparser fallback) |
| `enhanced_symbol_graph_service.py` | — | libclang-based enhanced graph: USR, accurate end_line, params, type_aliases, array_inits |
| `rule_engine_service.py` | — | Loads YAML rules, emits `violations_l1` |
| `mapping_service.py` | — | Maps `rule_id` → KCMVP guideline clauses (170+ entries in `mapping/rule_to_guideline.json`) |
| `llm_service.py` | `patches/` | Sends L1 findings to Gemini; emits `violations_l2` |
| `local_llm_service.py` | — | Local LLM fallback (llama.cpp HTTP or Hugging Face) |
| `doc_rule_service.py` | — | YAML rules applied to doc sections |
| `traceability_service.py` | — | Design↔code↔test alignment [stub] |
| `rag_service.py` | — | KCMVP guideline citations [stub] |
| `report_service.py` | `violations.json` | Merges+deduplicates all violations; builds summary |
| `code_slicer.py` | — | Extracts code snippets around violation lines |

**L2 filter logic**: Only violations with `severity=high` OR `pattern_type` in `{semantic, regex, ast}` (never `missing`) are sent to Gemini for semantic re-judgment.

### API Routes (`backend/app/api/routes/analyze.py`)

```
POST   /api/analyze                      # Create job (ZIP/GitHub URL + PDFs + filters)
GET    /api/analyze/{job_id}             # Poll status
GET    /api/analyze/{job_id}/report      # Violations + summary
GET    /api/analyze/{job_id}/file        # Source file content
GET    /api/analyze/{job_id}/files       # File listing
GET    /api/analyze/{job_id}/ast         # AST for a file
GET    /api/analyze/{job_id}/docs        # Preprocessed document sections
GET    /api/analyze/{job_id}/patches     # Suggested code fixes
GET    /api/analyze/{job_id}/symbol-graph
GET    /api/health
```

### Rule System (`backend/rules/`)

Rules are YAML objects with fields: `id`, `name`, `category`, `pattern_type`, `pattern`, `severity`, `description`, `kcmvp_ref`, `scope`.

**Pattern types:**
- `missing` — violation if pattern is **absent** from a file (1 violation per file); never sent to L2
- `regex` — per-match violations with line numbers; sent to L2 for high severity
- `semantic` — keyword presence flags need for AI review (`needs_ai_review=True`); always sent to L2
- `ast` — structural AST check (partially stub; infrastructure exists but not all rules implemented)

**COM-001 special handling**: checks AST `file_calls` first → `symbol_graph` → regex fallback.

Rule files:
- `common/security.yaml` — COM-001 to COM-006 (zeroization, RNG, hardcoded keys, CSPRNG, API order/naming)
- `algorithm/{lea,aria}.yaml` — LEA-001 to LEA-062, ARIA rules
- `mode/{cbc,ctr,gcm,ccm,cfb,cmac,ecb,ofb}.yaml` — Mode-specific checks
- `docs/{design,config_mgmt,test,keybiz}.yaml` — Document structure rules
- `traceability/traceability.yaml` — TRC rules (stub)

See `docs/YAML_룰과_코드_연동_설명.md` for rule authoring guidance.

### Frontend (`frontend/src/`)

React 18 + Zustand SPA. Vite proxies `/api` → `http://localhost:8000`.

**Zustand stores:**
- `stores/analysisStore.js` — analysis pipeline state (job, violations, file/doc views, patches)
- `stores/checklistStore.js` — security level + operation mode selections (used by ChecklistForm)

**`analysisStore.js`** key state:
- `jobId`, `status`, `progress`, `report`, `violationsByFile`
- `fileList`, `fileContents`, `selectedFilePath`
- `docSections`, `selectedDocPath`, `docViolationsByDocType`
- `activeArtifactTab` — `"report" | "code" | "design" | "scm" | "test" | "combined"`
- `patches`, `focusedPatch`, `focusedLine`, `focusedDocViolation`

**Component roles:**
- `LandingPage.jsx` — upload form (ZIP, GitHub URL, PDFs, algorithm/mode filters)
- `ChecklistForm.jsx` — 시험 신청서 형식 checklist UI; security level + algorithm/mode selection
- `CodeViewer.jsx` — syntax-highlighted source with violation line highlights + inline patch display
- `DocViewer.jsx` — rendered doc sections/tables with violation highlights
- `ReportViewer.jsx` — report screen; shows AI comprehensive evaluation in blue box
- `AnalysisPanel.jsx` — filterable violation list (by file, severity, rule_id, confidence); click-to-focus
- `api/client.js` — fetch wrapper (`createAnalyzeJob`, `getReport`, `getDocPreprocess`, `getFileContent`, `getPatches`)

## Key Configuration

**`backend/.env`** (from `.env.example`):
- `GOOGLE_API_KEY` — Required for L2 Gemini analysis
- `GEMINI_L2_MODEL=gemini-2.5-flash-lite` — Gemini model to use
- `L2_PROVIDER=gemini` — Set to `"local"` to use `local_llm_service.py` instead
- `LOCAL_LLM_BASE_URL=http://localhost:8080/v1` — llama.cpp server URL (if L2_PROVIDER=local)
- `LOCAL_LLM_MODEL=kcmvp-judge` — Local model name
- `STORAGE_ROOT=./storage` — Job artifact root
- `CORS_ORIGINS` — Must include frontend URL

All config flows through `backend/app/config.py` (Pydantic Settings).

## Development Status

- **Functional:** L1 rule engine, L2 LLM (Gemini), DOC rules, code/PDF preprocessing, symbol graph, patch generation (병렬화), full React frontend, RAG evidence retrieval (170-entry mapping), TRC basic checks, scanned PDF OCR (Gemini Vision)
- **Stub/in-progress:** AST checker fallback-only rules (20개) — `ast_checker_service`에 전용 checker 없음, `fallback_pattern` regex로 후보 위반 생성 후 L2 전송. 완전 미구현(fallback조차 없는) 규칙은 0개.
- **Not configured:** No linting/formatting tools (eslint, prettier, black, flake8), no test suite, no auth

### 최근 개선 이력 (2026-04)

| 항목 | 변경 내용 | 파일 |
|---|---|---|
| **L2 프롬프트 도메인 수치 보강** | LEA-003/010/031/034/040/046 템플릿에 KS X 3246 정확 수치(라운드 수, 델타 상수, off-by-one 예시) + few-shot 위반/정상 코드 예시 추가 | `llm_service.py` |
| **패치 생성 병렬화** | 코드/문서 패치 생성 루프를 `ThreadPoolExecutor(max_workers=5)`로 병렬화. 순차 호출 대비 분석 시간 대폭 단축 | `analyze.py` |
| **스캔본 PDF OCR** | 페이지당 평균 텍스트 < 30자(임계값)이면 스캔본으로 판정. Gemini Vision (`gemini-2.0-flash`)으로 페이지 전체 OCR 후 텍스트 레이어 보완. 섹션에 `is_scanned` 플래그 기록 | `preprocess_docs_service.py` |
| **TRC AST 기반 함수 추출** | 헤더 파일 함수 선언 추출 시 AST 우선 + regex fallback. `_FUNC_DECL_RE`에 `re.MULTILINE` 추가로 멀티라인 파라미터 선언 지원 | `traceability_service.py` |
| **RAG 인덱스 사전 로딩** | FastAPI lifespan으로 서버 시작 시 TF-IDF 인덱스 + ChromaDB(사용 시) 사전 구축. 첫 분석 요청 지연 제거 | `main.py`, `rag_service.py` |
| **L2 candidate cap 동적화** | 위반 수 N ≤ 30이면 전체 심사, N > 80이면 min(100, N//2)로 확장. 소규모/대형 프로젝트 모두 적절한 심사 범위 | `llm_service.py` |
| **진행률 추적 세분화** | 파이프라인 8단계(preprocess→symbol_graph→rule_engine→l2_llm→patches→doc_preprocess→trc→report)마다 `status.json` 기록. GET 폴링 시 세분화된 progress 반환 | `analyze.py` |
| **AST 규칙 5개 완전 구현** | LEA-014(모듈러 덧셈)/LEA-015(델타 인덱싱)/LEA-021(라운드키)/LEA-043(스택 배열)/ARIA-001(키 스케줄) regex fallback → pycparser AST 완전 분석 전환. FP 감소 + L2 API 호출 절감 | `ast_checker_service.py` |
| **libclang 향상된 심볼 그래프** | `enhanced_symbol_graph_service.py` 신규 생성. libclang 설치 시 자동 활성화: USR 기반 크로스 파일 링킹, 정확한 end_line(닫는 `}`), 파라미터 타입, typedef 역변환, 정적 배열 초기화값 수집. `symbol_graph` 응답에 `"backend"` 필드로 엔진 표시. 미설치 시 pycparser 자동 fallback | `enhanced_symbol_graph_service.py`, `symbol_graph_service.py`, `analyze.py` |
| **심볼 그래프 버그 2건 수정** | (1) `analyze.py` `src_root=root/"src"` → `src_root=root` — 잘못된 경로로 인해 libclang이 항상 pycparser fallback되던 문제 수정. (2) GCC fake_libc 환경에서 `memset` → `__builtin___memset_chk` 확장 시 COM-001 탐지 실패 문제 수정 — `_CLEARING_NAMES`에 내부 이름 추가 | `analyze.py`, `symbol_graph_service.py`, `enhanced_symbol_graph_service.py` |
| **체커 symbol_graph 연동** | `check_rule()`에 `symbol_graph` 파라미터 추가. LEA-010에 Phase 2 delta 상수 실제값 검증(`array_inits`): 비표준 hex값 즉시 탐지, L2 AI 불필요. LEA-031에 `type_aliases` 기반 포인터 피연산자 FP 제거. LEA-034에 `type_aliases`로 파라미터 타입 포함한 위반 메시지. `rule_engine_service._apply_ast_rule()`이 symbol_graph를 체커에 전달. | `ast_checker_service.py`, `rule_engine_service.py` |

## AST Rule Implementation Status

전체 40개 `pattern_type: ast` 규칙의 구현 현황:

| 상태 | 수 | 동작 방식 |
|---|---|---|
| ✓ 구현 (`ast_checker_service` 있음) | 25개 | pycparser AST 완전 분석 → 정확한 위반/통과 |
| △ fallback만 | 15개 | regex fallback → 후보 위반 생성 → L2 AI 판정 |
| ✗ 완전 미구현 | 0개 | — |

**구현 완료 규칙 (25개):** LEA-003, LEA-010, LEA-014, LEA-015, LEA-021, LEA-030, LEA-031, LEA-034, LEA-035, LEA-040, LEA-042, LEA-043, LEA-046, LEA-047, LEA-056, LEA-057, ARIA-001, CBC-001, CBC-002, ECB-002, GCM-001, CCM-001, CMAC-001, CTR-001, CTR-002

**fallback만 있는 규칙 (15개):** LEA-005, LEA-006, LEA-022~025, LEA-032, LEA-039, LEA-059, ARIA-002, CTR-005, CTR-LEA-006, OFB-002, CFB-002, CBC-LEA-005

## L2 Filter Logic (Code)

`_select_l2_candidates()` in `llm_service.py` — 타입별 버킷:
- **버킷1 (ast):** 최대 25건, rule당 5건
- **버킷2 (high severity regex/semantic):** 최대 25건, rule당 8건
- **버킷3 (기타):** 최대 10건, rule당 4건
- **L1.5 이름 필터:** 파일명 기반 사전 강제포함/강제제외
- **전체 상한:** 60건

`missing` 타입 코드 규칙은 L2 미전송 (패턴 부재 = 즉시 위반 확정).

## DOC L2 Filter Logic

`run_doc_l2_contextualizer()` in `llm_service.py`:
- **대상:** `pattern_type` in `{"semantic", "missing"}` 이고 `needs_ai_review=True`인 위반 (severity 무관)
- **캡:** rule당 최대 5건, 전체 최대 30건
- **판정 단위:** 위반 인스턴스별 (`id(v)`) → 같은 rule_id라도 섹션마다 독립 판정; 미평가 인스턴스는 같은 rule_id 판정 전파
- **regex 타입** DOC 위반은 AI 미전송 (객관적 패턴 매칭 결과)

## Known Issues & Accuracy Limitations

### Critical (affects correctness)
- **AST fallback 규칙 FP 가능성:** fallback-only 20개 규칙은 regex로 후보 위반을 생성하므로 FP 가능 → L2가 필터링하지만 규칙당 5건 캡 초과 시 일부 미검토.
- **COM-001 false negatives**: 제로화 함수 이름(`memset_s` 등)은 탐지하지만 실제로 키 변수에 호출되는지 추적하지 않음. 직접 제로화 루프(`for(i=0;i<N;i++) buf[i]=0`)는 AST 분석으로 탐지.
- **TRC regex fragility**: `traceability_service`가 regex로 함수 선언 추출 → 매크로 함수, 함수 포인터, 멀티라인 선언 누락.

### Medium (affects usability)
- **코드 L2 candidate cap 60건:** 대형 프로젝트에서 규칙 수가 많으면 낮은 우선순위 위반은 AI 재판정 못 받음.
- **Progress tracking coarse**: `GET /api/analyze/{job_id}` only checks file existence → progress reports 80% when preprocessing done, even if L1/L2/DOC haven't run yet.
- **패치 병렬화 Rate limit**: `ThreadPoolExecutor(max_workers=5)` 사용. Gemini 무료 tier RPM 초과 시 일부 패치 생성 실패 가능 — `analyze.py`의 `_PATCH_MAX_WORKERS` 값 조정으로 제어.
- **스캔본 OCR 비용**: `_is_scanned_pdf()` 임계값(30자/페이지 평균), 페이지별 OCR 선별 임계값(30자). 완전한 스캔본(거의 텍스트 없음)만 OCR 대상으로 처리. `preprocess_docs_service.py`의 `threshold_chars_per_page` 및 페이지별 선별 상수로 조정 가능.

### Low (minor UX)
- **Patch filename format**: DOC patch files named `{rule_id}-doc_{doc_type}-{index}.md`; code patches named `{rule_id}-{safe_filename}-{line}.md`. `parsePatchPath()` in AnalysisPanel.jsx handles both but fragile if format changes.
- **L2 retry prompt inconsistency**: Retry suffix says "위 형식" but doesn't re-embed the expected JSON schema → occasional Gemini format drift.
- **스캔본 섹션 분리 미지원**: OCR로 텍스트를 복원해도 TOC 구조 인식률이 낮을 수 있음 → 전체 파일 단일 섹션으로 fallback 처리됨.

## Performance Measurement Principles (성능 측정 원칙)

**이 원칙은 모든 성능 평가에 반드시 적용한다. 예외 없음.**

### 1. 분모 조작 금지

도구가 탐지한 모든 항목은 Precision 분모에 포함한다.
- 도구가 보고한 탐지 결과를 "ARTIFACT", "REVIEW", "카테고리 분리" 등의 이유로 분모에서 제외하는 것을 **절대 금지**한다.
- 탐지 결과는 TP(진짜 위반) 또는 FP(오탐) 둘 중 하나로만 분류한다.
- `Precision = TP / (TP + FP)` — 모든 탐지 건이 분모에 들어가야 한다.
- `Recall = TP / (TP + FN)` — 모든 GT 위반이 분모에 들어가야 한다.

### 2. Train/Test 분리 (학습/평가 분리)

성능을 측정하는 데이터와 규칙을 개선하는 데이터를 반드시 분리한다.
- **Train 세트**: 이 데이터를 보고 규칙/프롬프트를 수정해도 됨 (예: 4세트)
- **Test 세트**: 규칙 수정에 절대 사용하지 않음. 최종 성능 측정에만 사용 (예: 블라인드 세트)
- Test 세트의 결과를 보고 규칙을 수정한 뒤 같은 Test 세트에서 재측정하는 것은 **과적합(overfitting)**이며 금지한다.
- 특정 데이터셋의 FP를 보고 그 항목만 제거하는 하드코딩 예외는 금지한다.

### 3. 라벨링과 코드 수정의 분리

수동 라벨링(GT 작성)과 규칙/코드 개선은 반드시 순차적으로 진행한다.
- **Step 1**: 현재 도구 상태에서 라벨링 완료 (코드 수정 금지)
- **Step 2**: 라벨링 결과로 성능 측정
- **Step 3**: 성능 분석 후 규칙 개선 (Train 세트 기반으로만)
- **Step 4**: Test 세트에서 최종 재측정
- 라벨링과 코드 수정을 동시에 하면 순환 논증(circular reasoning)이 되어 성능 수치가 무의미해진다.

### 4. 라벨링 근거 요건

모든 TP/FP 판정에는 반드시 근거를 명시해야 한다.
- **TP 근거**: 어떤 KCMVP 규격 조항(KS X ISO/IEC 19790 §X.X 등)에 의해 위반인지
- **FP 근거**: 왜 위반이 아닌지 (동등 구현, 규칙 범위 밖, 코드 증거 등)
- 근거 없는 라벨링은 유효하지 않다.

### 5. 허용되는 라벨

| 라벨 | 의미 | Precision 분모 포함 |
|---|---|---|
| TP | 실제 위반을 도구가 맞게 탐지 | **포함** |
| FP | 위반이 아닌데 도구가 탐지 | **포함** |
| UNREVIEWED | 아직 검토하지 않음 | 제외 (검토 완료 시 TP/FP로 변경) |

- "ARTIFACT", "REVIEW" 등 TP/FP 외의 분류로 분모를 줄이는 것은 금지한다.
- 검토가 어려운 항목은 UNREVIEWED로 남기되, 최종 보고 시에는 모두 TP/FP로 확정해야 한다.

## Key Documentation (in `docs/`)

- `YAML_룰과_코드_연동_설명.md` — Rule pattern types and authoring
- `LEA_코드_룰_작성_가이드.md` — LEA rule authoring guide
- `DOC_설계서_룰_작성_가이드.md` — Document rule authoring guide
- `Frontend_UI_구현_가이드라인.md` — React component design decisions
- `RAG_연결_가이드라인.md` — RAG evidence retrieval design
- `PROJECT_방향성_및_AI_온보딩_가이드.md` — Project direction and AI onboarding
