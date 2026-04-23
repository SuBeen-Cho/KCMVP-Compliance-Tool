# Frontend — KCMVP 사전 적합성 검증 UI

- React 18 + Vite, Tailwind CSS.
- IDE 스타일: TopNav, 파일 트리, 코드 뷰, 분석 결과 패널.

## 실행

```bash
cd frontend
npm install
npm run dev
```

- http://localhost:5173 (백엔드 프록시: /api → :8000)

## 디렉터리

- `src/components/`: TopNav, FileTree, CodeViewer, AnalysisPanel.
- `src/pages/`: AnalyzePage (라우팅 확장 시).
- `src/api/`: 백엔드 API 클라이언트.
- `src/stores/`: Zustand 분석 상태.
