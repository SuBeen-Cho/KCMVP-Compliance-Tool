## KCMVP 프론트/백엔드 서버 실행 가이드

### 공통 사전 준비

- **필수 설치**
  - **Node.js / npm**: 프론트엔드(Vite + React) 실행용.
  - **Python 3.10+ / pip**: 백엔드(FastAPI) 실행용.
- **프로젝트 루트**: `/Users/subeen/Desktop/Kcmvp_main` 를 기준으로 설명합니다.

---

### 1. 백엔드 서버 실행 (FastAPI)

- **의존성 설치 (최초 1회 또는 변경 시)**

```bash
cd /Users/subeen/Desktop/Kcmvp_main/backend
pip install -r requirements.txt
```

- **venv일 경우**
  cd /Users/subeen/Desktop/Kcmvp_main/backend
  source /Users/subeen/Desktop/Kcmvp_main/backend/venv/bin/activate
  pip install -r requirements.txt
  uvicorn app.main:app --reload 

- **서버 실행**

```bash
cd /Users/subeen/Desktop/Kcmvp_main/backend
uvicorn app.main:app --reload
```

- venv일 경우 
cd /Users/subeen/Desktop/Kcmvp_main/backend
source venv/bin/activate
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000


- **접속 정보**
  - API 문서: `http://localhost:8000/docs`
  - 헬스 체크: `http://localhost:8000/api/health`


---

### 2. 프론트엔드 서버 실행 (Vite + React)

- **의존성 설치 (최초 1회 또는 변경 시)**

```bash
cd /Users/subeen/Desktop/Kcmvp_main/frontend
npm install
```

- **개발 서버 실행(프론트)**

```bash
cd /Users/subeen/Desktop/Kcmvp_main/frontend
npm run dev
```

- **접속 정보**
  - 프론트엔드: `http://localhost:5174`
  - 프록시 설정: `/api` 요청은 자동으로 `http://localhost:8000` (백엔드)로 프록시됨.

---

### 3. 서버 실행 순서 & 주의사항

- **권장 실행 순서**
  1. **백엔드**: `cd /Users/subeen/Desktop/Kcmvp_main/backend && uvicorn app.main:app --reload`
  2. **프론트엔드**: `cd /Users/subeen/Desktop/Kcmvp_main/frontend && npm run dev`
- **포트 충돌**
  - 백엔드 기본 포트는 `8000`, 프론트엔드 기본 포트는 `5174` 입니다.
  - 이미 사용 중이면 Vite가 다른 포트를 제안할 수 있으니, 터미널 메시지를 확인하세요.
- **가상환경(venv) 사용 시**
  - 이미 `backend/venv` 가 구성되어 있다면:

```bash
cd /Users/subeen/Desktop/Kcmvp_main/backend
source /Users/subeen/Desktop/Kcmvp_main/backend/venv/bin/activate  # 또는 . /Users/subeen/Desktop/Kcmvp_main/backend/venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

---

### 4. 기타 유틸리티 스크립트 (선택)

- **샘플 ZIP 생성 스크립트**

```bash
cd /Users/subeen/Desktop/Kcmvp_main/backend
python scripts/create_sample_zip.py
```

- **업로드 테스트 스크립트**

```bash
cd /Users/subeen/Desktop/Kcmvp_main/backend
python scripts/test_upload.py
```

> 위 스크립트들은 분석 파이프라인 테스트용이며, 서버 실행과는 직접적으로 무관합니다.

### 5. 저장 데이터 정리 (선택)

- 분석 결과는 `backend/storage/jobs/` 아래 job별 폴더에 저장됩니다. 필요 시 **전체 삭제**: `rm -rf backend/storage/jobs/*` (코드·설정에는 영향 없음).


