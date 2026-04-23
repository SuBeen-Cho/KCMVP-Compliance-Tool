# KCMVP Frontend 전면 리디자인 구현 가이드

> **이 문서의 목적**: AI(Claude Code 등)가 직접 코드를 수정할 수 있도록 변경 범위, 적용 파일, 구체적인 코드 패턴을 명시한 구현 지침서입니다.

---

## 0. 핵심 제약사항 (절대 변경 금지)

다음 구조는 어떤 경우에도 변경하지 않습니다:

```
app-layout
├── TopNav          (최상단 고정 헤더)
├── JobInfoBar      (분석 메타 정보 바)
├── ArtifactTabs    (탭 전환 바)
└── app-body        ← 이 3컬럼 레이아웃 절대 유지
    ├── aside.sidebar     (왼쪽: FileTree / DocTree)
    ├── main.editor-area  (가운데: CodeViewer / DocViewer / ReportViewer)
    └── aside.result-panel (오른쪽: AnalysisPanel)
```

**변경 대상 파일 목록:**
1. `frontend/src/App.jsx` — 종합 탭 제거
2. `frontend/src/components/ReportViewer.jsx` — 보고서 전면 개선
3. `frontend/src/components/AnalysisPanel.jsx` — 위반 목록 카드화
4. `frontend/src/components/TopNav.jsx` — 브랜드 색상 적용
5. `frontend/src/components/JobInfoBar.jsx` — 진행 상태 피드백 개선
6. `frontend/src/styles/` (CSS 파일들) — 색상 토큰/타이포그래피 변수 교체

---

## 1. 색상 토큰 및 타이포그래피 변경

### 1.1 CSS 변수 교체

`frontend/src/styles/` 내 전역 CSS 파일(예: `index.css`, `globals.css`, `App.css`)에서 아래 변수를 교체하거나 추가합니다.

**기존 → 신규 색상:**

| 역할 | 기존 값 | 신규 값 | 이유 |
|------|---------|---------|------|
| Primary (브랜드 파랑) | `#1C4D8D` | `#0b49b5` | WCAG AA 6.5:1 대비 |
| Accent (강조) | `#FCC61D` | `#e7746f` | WCAG AA 4.8:1 대비, 색맹 친화 |
| BG | `#EEEEEE` | `#FFFFFF` / `#F8FAFC` | 21:1 대비 |
| HIGH 위반 | `#DC2626` (유지) | `#DC2626` | 유지 |
| MEDIUM 위반 | `#F59E0B` (유지) | `#D97706` | 명도 대비 확보 |
| LOW 위반 | `#6B7280` | `#4B5563` | 가독성 개선 |
| 통과/성공 | `#10B981` | `#059669` | |

**CSS 변수 선언 (`:root` 블록):**

```css
:root {
  /* Brand */
  --color-primary:       #0b49b5;
  --color-primary-dark:  #0F2854;
  --color-primary-light: #EFF6FF;

  /* Severity */
  --color-high:          #DC2626;
  --color-high-bg:       #FEF2F2;
  --color-high-border:   #FECACA;
  --color-medium:        #D97706;
  --color-medium-bg:     #FFFBEB;
  --color-medium-border: #FDE68A;
  --color-low:           #4B5563;
  --color-low-bg:        #F9FAFB;
  --color-low-border:    #E5E7EB;
  --color-pass:          #059669;
  --color-pass-bg:       #ECFDF5;

  /* Typography */
  --font-size-h1:   20px;
  --font-size-h2:   16px;
  --font-size-h3:   14px;
  --font-size-body: 13px;   /* 기존 10-11px → 13px */
  --font-size-sm:   12px;
  --font-size-xs:   11px;
  --line-height:    1.6;    /* 기존 1.4 → 1.6 */
}
```

**Tailwind를 사용하는 경우 (`tailwind.config.js`):**

```js
theme: {
  extend: {
    colors: {
      primary: {
        DEFAULT: '#0b49b5',
        dark:    '#0F2854',
        light:   '#EFF6FF',
      },
      severity: {
        high:   '#DC2626',
        medium: '#D97706',
        low:    '#4B5563',
      }
    },
    lineHeight: {
      relaxed: '1.6',
    }
  }
}
```

### 1.2 코드 내 하드코딩된 색상 일괄 교체

모든 파일에서 다음 치환을 수행합니다:

```
"#1C4D8D"  →  "#0b49b5"
"#0F2854"  →  "#0F2854"  (유지)
text-[#1C4D8D]  →  text-[#0b49b5]
border-[#1C4D8D]  →  border-[#0b49b5]
bg-[#1C4D8D]  →  bg-[#0b49b5]
```

---

## 2. App.jsx — 종합 탭 제거

**파일:** `frontend/src/App.jsx`

### 2.1 ArtifactTabs 컴포넌트 수정

`종합` 버튼 전체를 삭제합니다.

**삭제 대상 (현재 코드에서 이 블록을 찾아 완전히 제거):**

```jsx
<button
  type="button"
  className={btnClass("combined")}
  onClick={() => setActive("combined")}
  title={(countsByTab.trc || 0) > 0 ? `추적성(TRC) ${countsByTab.trc}건 포함` : undefined}
>
  종합{badge((countsByTab.combined || 0) + (countsByTab.trc || 0))}
</button>
```

### 2.2 AnalyzeLayout 컴포넌트 수정

`combined` 탭 관련 로직 제거:

```jsx
// 변경 전
const isCodeView = active === "code" || active === "combined";

// 변경 후
const isCodeView = active === "code";
```

### 2.3 탭 버튼 스타일 개선

탭 버튼의 active 상태 색상을 새 Primary 색상으로 교체:

```jsx
// 변경 전
"border-[#1C4D8D] text-[#0F2854] font-medium"

// 변경 후
"border-[#0b49b5] text-[#0b49b5] font-semibold"
```

탭 전체 컨테이너에 배경 약간 추가:

```jsx
// ArtifactTabs return 문의 최상위 div
<div className="px-4 md:px-6 border-b border-gray-200 bg-white shadow-sm">
```

---

## 3. ReportViewer.jsx — 보고서 전면 개선

**파일:** `frontend/src/components/ReportViewer.jsx`

### 3.1 전체 구조 개요 (변경 후)

```
ReportViewer (전체 스크롤 컨테이너)
├── StickyHeader (고정 헤더: 제목 + 종합 판정 뱃지 + 버튼)
└── ScrollBody (px-6 py-4 space-y-6)
    ├── SummaryCards (확정/후보/전체 숫자 카드 3개)
    ├── CategoryTable (카테고리별 판정 테이블) — 현재와 동일, 색상만 개선
    ├── TrcNotice (TRC 참고 정보 — 있을 때만)
    ├── AiSummaryBox (AI 종합 평가 — 있을 때만)
    ├── ViolationSections (카테고리별 위반 카드 목록) ← 핵심 개선
    └── FileFixSummary (수정 필요 파일 요약 테이블)
```

**주의:** `종합 판정` 섹션 제목(h3)과 위에 있던 판정 테이블은 그대로 유지하되 디자인만 개선합니다.

---

### 3.2 위반 카드 (ViolationCard) — 핵심 개선

현재 `ReportViewer`에서 각 위반을 `<table>` `<tr>` 한 줄로 보여주는 방식을 **카드 형태**로 교체합니다.

#### 심각도별 색상 규칙

| severity | 왼쪽 border | 배경 | 제목 색 |
|----------|------------|------|---------|
| high | `border-l-4 border-red-500` | `bg-red-50` | `text-red-700` |
| medium | `border-l-4 border-amber-400` | `bg-amber-50` | `text-amber-700` |
| low | `border-l-4 border-gray-300` | `bg-white` | `text-gray-700` |
| (후보) | 해당 severity에 `opacity-75` | | |

#### ViolationCard 컴포넌트 (새로 추가)

아래 컴포넌트를 `ReportViewer.jsx` 파일 상단(export default 위)에 추가합니다:

```jsx
function getSeverityStyle(severity, confidence) {
  const isCandidate = confidence !== "확정";
  const base = isCandidate ? "opacity-80" : "";
  switch ((severity || "").toLowerCase()) {
    case "high":
      return {
        card: `border-l-4 border-red-500 bg-red-50 ${base}`,
        badge: "bg-red-100 text-red-700 border border-red-300",
        label: "HIGH",
        dot: "bg-red-500",
      };
    case "medium":
      return {
        card: `border-l-4 border-amber-400 bg-amber-50 ${base}`,
        badge: "bg-amber-100 text-amber-700 border border-amber-300",
        label: "MED",
        dot: "bg-amber-400",
      };
    default:
      return {
        card: `border-l-4 border-gray-300 bg-white ${base}`,
        badge: "bg-gray-100 text-gray-600 border border-gray-300",
        label: "LOW",
        dot: "bg-gray-400",
      };
  }
}

function ViolationCard({ v, onClick }) {
  const conf    = getConfidence(v);
  const style   = getSeverityStyle(v.severity, conf);
  const isDoc   = (v.rule_id || "").toUpperCase().startsWith("DOC-") || !!v.doc_type;
  const lineNo  = typeof v.line === "number" && v.line > 0
    ? `L${v.line}`
    : isDoc ? "문서 전체"
    : v.pattern_type === "missing" ? "항목 부재"
    : "파일 전체";

  return (
    <div
      className={`rounded-lg border border-gray-200 overflow-hidden cursor-pointer hover:shadow-md transition-shadow ${style.card}`}
      onClick={onClick}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => e.key === "Enter" && onClick?.()}
    >
      {/* 카드 헤더 */}
      <div className="flex items-center justify-between px-3 py-2 border-b border-gray-100 gap-2">
        <div className="flex items-center gap-2 min-w-0">
          {/* rule_id */}
          <span className="font-mono font-bold text-[12px] text-[#0b49b5] shrink-0">
            {v.rule_id}
          </span>
          {/* severity badge */}
          <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold shrink-0 ${style.badge}`}>
            {style.label}
          </span>
          {/* confidence badge */}
          <ConfidenceBadge
            confidence={conf}
            score={v.confidence_score}
            insufficientCtx={v.insufficient_context}
          />
        </div>
        {/* 위치 정보 */}
        <span className="font-mono text-[11px] text-gray-400 shrink-0">{lineNo}</span>
      </div>

      {/* 카드 본문 */}
      <div className="px-3 py-2 space-y-1">
        {/* 위반 메시지 */}
        <p className="text-[12px] text-gray-800 leading-relaxed">{v.message}</p>

        {/* RAG 근거 (있는 경우만) */}
        {v.rag_evidence && (
          <p className="text-[11px] text-blue-700 bg-blue-50 rounded px-2 py-1 leading-relaxed border border-blue-100">
            📖 {v.rag_evidence}
          </p>
        )}

        {/* L2 AI 판정 이유 (있는 경우만) */}
        {v.l2_reason && (
          <p className="text-[11px] text-gray-500 italic leading-relaxed">
            AI: {v.l2_reason}
          </p>
        )}
      </div>
    </div>
  );
}
```

#### CollapsibleSection 내부 교체

현재 `CollapsibleSection` 안에 `<table>` 로 보여주던 부분을 ViolationCard 배열로 교체합니다.

**변경 전 (찾아서 교체):**

```jsx
<table className="w-full text-[11px]">
  <tbody className="divide-y divide-gray-100">
    {groupVs
      .sort((a, b) => (a.line || 0) - (b.line || 0))
      .map((v, idx) => {
        // ... 기존 tr/td 렌더링
      })}
  </tbody>
</table>
```

**변경 후:**

```jsx
<div className="p-2 space-y-2">
  {groupVs
    .sort((a, b) => (a.line || 0) - (b.line || 0))
    .map((v, idx) => (
      <ViolationCard
        key={`${v.rule_id}-${idx}`}
        v={v}
        onClick={() => handleViolationClick(v)}
      />
    ))}
</div>
```

---

### 3.3 AI 종합 평가 박스 개선

현재 파란 박스는 유지하되, 내부 마크다운 렌더링의 폰트 크기와 여백을 개선합니다.

**변경 전:**

```jsx
<section className="rounded-lg border border-blue-200 bg-blue-50 p-4">
  <h3 className="text-xs font-semibold text-blue-700 uppercase tracking-wide mb-3 flex items-center gap-1">
    🤖 AI 종합 평가
  </h3>
  <div className="leading-relaxed">
    {renderMd(aiSummary)}
  </div>
</section>
```

**변경 후:**

```jsx
<section className="rounded-xl border border-blue-200 bg-blue-50 p-5 shadow-sm">
  <div className="flex items-center gap-2 mb-3">
    <span className="text-blue-500 text-base">🤖</span>
    <h3 className="text-sm font-bold text-blue-800 tracking-wide">AI 종합 평가</h3>
  </div>
  <div className="leading-relaxed text-[13px] space-y-1">
    {renderMd(aiSummary)}
  </div>
</section>
```

`renderMd` 함수 내부 폰트 크기도 업데이트합니다:

```jsx
// 변경 전: text-[12px], text-[13px] 등 작은 값
// 변경 후: 아래와 같이 증가

function renderMd(text) {
  // ...
  if (/^### /.test(line)) {
    elements.push(<p key={i} className="font-semibold text-[13px] text-blue-800 mt-3 mb-1">{inlineMd(line.slice(4))}</p>);
  } else if (/^## /.test(line)) {
    elements.push(<p key={i} className="font-semibold text-[14px] text-blue-900 mt-3 mb-1">{inlineMd(line.slice(3))}</p>);
  } else if (/^# /.test(line)) {
    elements.push(<p key={i} className="font-bold text-[15px] text-blue-900 mt-2 mb-1">{inlineMd(line.slice(2))}</p>);
  } else if (/^[-*] /.test(line)) {
    elements.push(<li key={i} className="ml-4 list-disc text-[13px] text-gray-700 leading-relaxed">{inlineMd(line.slice(2))}</li>);
  } else if (/^\d+\. /.test(line)) {
    elements.push(<li key={i} className="ml-4 list-decimal text-[13px] text-gray-700 leading-relaxed">{inlineMd(line.replace(/^\d+\. /, ""))}</li>);
  } else if (line.trim() === "") {
    elements.push(<div key={i} className="h-2" />);
  } else {
    elements.push(<p key={i} className="text-[13px] text-gray-700 leading-relaxed">{inlineMd(line)}</p>);
  }
  // ...
}
```

---

### 3.4 종합 판정 숫자 카드 개선

헤더 영역의 숫자 카드 3개를 더 명확하게 수정합니다.

```jsx
{/* 상단 확정/후보 요약 카드 */}
<div className="grid grid-cols-3 gap-3 mb-4">
  {/* 확정 위반 */}
  <div className="rounded-xl border-2 border-red-200 bg-red-50 px-4 py-4 text-center shadow-sm">
    <p className="text-[11px] font-medium text-red-500 mb-1 uppercase tracking-wide">확정 위반</p>
    <p className="text-3xl font-black text-red-700">{totalConfirmed}</p>
    {summary.confirmed_high > 0 && (
      <p className="text-[10px] text-red-400 mt-1">HIGH {summary.confirmed_high}건 포함</p>
    )}
  </div>
  {/* 위반 후보 */}
  <div className="rounded-xl border-2 border-amber-200 bg-amber-50 px-4 py-4 text-center shadow-sm">
    <p className="text-[11px] font-medium text-amber-500 mb-1 uppercase tracking-wide">위반 후보</p>
    <p className="text-3xl font-black text-amber-600">{totalCandidate}</p>
    <p className="text-[10px] text-amber-400 mt-1">L2 재검토 필요</p>
  </div>
  {/* 전체 */}
  <div className="rounded-xl border-2 border-gray-200 bg-gray-50 px-4 py-4 text-center shadow-sm">
    <p className="text-[11px] font-medium text-gray-400 mb-1 uppercase tracking-wide">전체 (TRC 제외)</p>
    <p className="text-3xl font-black text-gray-700">{nonTrcViolations.length}</p>
  </div>
</div>
```

---

### 3.5 카테고리별 판정 테이블 — 행 색상 추가

테이블 행에 확정 위반이 있을 경우 배경 색상 추가:

```jsx
<tr key={cat} className={[
  "hover:bg-gray-50 transition-colors",
  c > 0 ? "bg-red-50" : k > 0 ? "bg-amber-50" : "",
].join(" ")}>
```

---

### 3.6 섹션 헤더 개선

각 카테고리 섹션(`공통 보안`, `알고리즘 구현` 등)의 헤더를 더 명확하게:

```jsx
{/* 변경 전 */}
<div className="flex items-center justify-between mb-2">
  <h3 className="text-xs font-semibold text-gray-700">
    {label}
    <span className="ml-1 text-gray-400 font-normal">({abbr})</span>
    <span className="ml-2 text-[10px] text-gray-400">{all.length}건</span>
  </h3>
  <Verdict confirmed={c_list.length} candidate={k_list.length} />
</div>

{/* 변경 후 */}
<div className="flex items-center justify-between mb-3 pb-2 border-b border-gray-100">
  <div className="flex items-center gap-2">
    <h3 className="text-[13px] font-bold text-gray-800">{label}</h3>
    <span className="text-[11px] text-gray-400 font-normal">({abbr})</span>
    <span className="px-2 py-0.5 rounded-full bg-gray-100 text-[10px] text-gray-500 font-medium">
      {all.length}건
    </span>
  </div>
  <Verdict confirmed={c_list.length} candidate={k_list.length} />
</div>
```

---

### 3.7 ConfidenceBadge 개선

현재 뱃지의 텍스트 크기를 11px → 11px 유지, 패딩만 조정:

```jsx
// 확정 뱃지
<span className="inline-flex items-center gap-0.5 px-2 py-0.5 rounded-full text-[11px] font-bold bg-red-100 text-red-700 border border-red-200"
      title={...}>
  ✓ 확정{scoreText}
</span>

// 후보 뱃지
<span className="inline-flex items-center gap-0.5 px-2 py-0.5 rounded-full text-[11px] font-bold bg-amber-50 text-amber-600 border border-amber-200">
  △ 후보{scoreText}
</span>

// 증거부족 뱃지
<span className="inline-flex items-center gap-0.5 px-2 py-0.5 rounded-full text-[11px] font-medium bg-gray-100 text-gray-500 border border-gray-300">
  ? 증거부족
</span>
```

---

## 4. AnalysisPanel.jsx — 위반 목록 패널 개선

**파일:** `frontend/src/components/AnalysisPanel.jsx`

### 4.1 위반 항목 카드화

현재 패널의 각 위반 항목(행)에 심각도별 왼쪽 색상 바를 추가합니다.

기존 코드에서 위반 항목이 렌더링되는 부분을 찾아 왼쪽 테두리 스타일을 추가합니다:

```jsx
// 위반 항목의 최상위 div에 severity 기반 border-l 추가
const severityBorderClass = {
  high:   "border-l-4 border-red-500",
  medium: "border-l-4 border-amber-400",
  low:    "border-l-4 border-gray-300",
}[v.severity?.toLowerCase()] || "border-l-4 border-gray-200";

// 기존 className에 severityBorderClass 추가
<div className={`... ${severityBorderClass}`}>
```

### 4.2 심각도 배지 개선

기존 `HIGH`/`MED`/`LOW` 텍스트 뱃지 스타일:

```jsx
// 심각도 뱃지 렌더링 함수 (기존 함수 교체)
function SeverityBadge({ severity }) {
  switch ((severity || "").toLowerCase()) {
    case "high":
      return (
        <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-bold bg-red-100 text-red-700 border border-red-300">
          HIGH
        </span>
      );
    case "medium":
      return (
        <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-bold bg-amber-100 text-amber-700 border border-amber-300">
          MED
        </span>
      );
    default:
      return (
        <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-bold bg-gray-100 text-gray-600 border border-gray-300">
          LOW
        </span>
      );
  }
}
```

### 4.3 필터 버튼 색상

패널 상단 필터 UI의 활성 상태 색상을 Primary 색상으로:

```jsx
// active 필터 버튼 className
"bg-[#0b49b5] text-white border-[#0b49b5]"  // 기존 #1C4D8D 교체
```

---

## 5. TopNav.jsx — 브랜드 색상 적용

**파일:** `frontend/src/components/TopNav.jsx`

### 5.1 배경 및 텍스트 색상

```jsx
// 네브바 최상위 div
<nav className="bg-[#0b49b5] text-white px-4 md:px-6 h-10 flex items-center justify-between shadow-md">

// 타이틀 텍스트
<span className="font-bold text-[14px] tracking-wide text-white">KCMVP 사전 적합성 점검</span>
```

---

## 6. JobInfoBar.jsx — 진행 상태 피드백 개선

**파일:** `frontend/src/components/JobInfoBar.jsx`

### 6.1 분석 진행 중 상태 표시

`status === "running"` 또는 `status === "processing"` 상태일 때, 단순 로딩 스피너 대신 **단계별 진행 표시기**를 보여줍니다.

현재 JobInfoBar에서 상태 텍스트를 렌더링하는 부분을 찾아 아래로 교체합니다:

```jsx
// 분석 파이프라인 단계 정의
const PIPELINE_STEPS = [
  { key: "upload",       label: "파일 업로드" },
  { key: "preprocess",   label: "전처리" },
  { key: "l1",           label: "L1 규칙 검사" },
  { key: "l2",           label: "L2 AI 판정" },
  { key: "doc",          label: "문서 검사" },
  { key: "report",       label: "보고서 생성" },
];

// status가 "running"/"processing"인 경우
function PipelineProgress({ progress, currentStep }) {
  // progress: 0~100 숫자
  // currentStep: 백엔드가 내려주는 현재 단계 문자열 (없으면 progress로 추정)
  const stepIndex = (() => {
    if (currentStep) {
      const idx = PIPELINE_STEPS.findIndex(s => currentStep.includes(s.key));
      return idx >= 0 ? idx : Math.floor((progress / 100) * PIPELINE_STEPS.length);
    }
    return Math.floor((progress / 100) * PIPELINE_STEPS.length);
  })();

  return (
    <div className="flex items-center gap-3 text-[11px]">
      {/* 단계 표시 */}
      <span className="text-[#0b49b5] font-semibold">
        분석 진행 중... ({Math.min(stepIndex + 1, PIPELINE_STEPS.length)}/{PIPELINE_STEPS.length} 단계)
      </span>
      {/* 현재 단계 이름 */}
      <span className="text-gray-500">
        ⏳ {PIPELINE_STEPS[Math.min(stepIndex, PIPELINE_STEPS.length - 1)]?.label}
      </span>
      {/* 프로그레스 바 */}
      <div className="flex items-center gap-1.5">
        <div className="w-24 h-1.5 bg-gray-200 rounded-full overflow-hidden">
          <div
            className="h-full bg-[#0b49b5] rounded-full transition-all duration-500"
            style={{ width: `${progress || 0}%` }}
          />
        </div>
        <span className="text-gray-400">{progress || 0}%</span>
      </div>
    </div>
  );
}
```

**JobInfoBar 내부에서 조건부 렌더링:**

```jsx
// status에 따른 분기 렌더링
{(status === "running" || status === "processing") ? (
  <PipelineProgress progress={progress} currentStep={currentStep} />
) : status === "failed" ? (
  <span className="text-red-600 font-semibold text-[11px]">❌ 분석 실패 — 파일을 확인하세요</span>
) : status === "done" || status === "completed" ? (
  <span className="text-green-600 font-semibold text-[11px]">✅ 분석 완료</span>
) : null}
```

---

## 7. LandingPage.jsx — 에러 메시지 개선

**파일:** `frontend/src/pages/LandingPage.jsx`

### 7.1 에러 알림 박스 개선

현재 `error` 상태를 보여주는 부분을 찾아 교체합니다:

```jsx
{/* 변경 전: 단순 빨간 텍스트 */}
{error && <p className="text-red-500 text-sm">{error}</p>}

{/* 변경 후: 구체적 에러 박스 */}
{error && (
  <div className="rounded-xl border-2 border-red-200 bg-red-50 p-4 mt-2">
    <div className="flex items-start gap-2">
      <span className="text-red-500 text-base shrink-0">⚠</span>
      <div>
        <p className="font-bold text-[13px] text-red-700 mb-1">업로드 실패</p>
        <p className="text-[12px] text-red-600 leading-relaxed">{error}</p>
        <p className="text-[11px] text-red-400 mt-2">
          ZIP 파일 크기, 형식, 네트워크 상태를 확인하고 다시 시도해 주세요.
        </p>
      </div>
    </div>
    <button
      type="button"
      className="mt-3 px-3 py-1.5 text-[12px] font-medium bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors"
      onClick={() => setError(null)}
    >
      다시 시도
    </button>
  </div>
)}
```

---

## 8. 전체 적용 체크리스트

AI가 작업 완료 후 아래 항목을 순서대로 확인합니다:

### 8.1 제거 확인
- [ ] `App.jsx`에서 `종합` 탭 버튼 완전 제거
- [ ] `App.jsx`에서 `combined` 관련 로직 제거 (`isCodeView` 조건에서)

### 8.2 색상 확인
- [ ] 모든 파일에서 `#1C4D8D` → `#0b49b5` 교체됨
- [ ] `TopNav.jsx` 배경이 `#0b49b5`
- [ ] 탭 active 상태가 `#0b49b5`
- [ ] 필터 버튼 active 상태가 `#0b49b5`

### 8.3 ReportViewer 확인
- [ ] HIGH 위반 카드: 왼쪽 빨간 border + 연빨간 배경
- [ ] MEDIUM 위반 카드: 왼쪽 주황 border + 연주황 배경
- [ ] LOW 위반 카드: 왼쪽 회색 border + 흰 배경
- [ ] 숫자 카드 3개: 확정(빨강)/후보(주황)/전체(회색)
- [ ] AI 종합 평가 박스: 파란 배경, 폰트 13px
- [ ] 카테고리 섹션 헤더: bold 13px + 건수 pill 뱃지
- [ ] ViolationCard 내부: rule_id + severity badge + confidence badge + 위치 + 메시지

### 8.4 AnalysisPanel 확인
- [ ] 각 위반 항목 왼쪽에 severity 색상 bar
- [ ] HIGH/MED/LOW 뱃지 색상 정확

### 8.5 JobInfoBar 확인
- [ ] 분석 중일 때 단계별 진행 표시 (n/6 단계)
- [ ] 프로그레스 바 표시

### 8.6 레이아웃 불변 확인
- [ ] 3컬럼 레이아웃(sidebar | editor-area | result-panel) 유지됨
- [ ] 보고서 탭 클릭 시 기존 레이아웃 동일하게 동작
- [ ] 코드/문서 탭 클릭 시 FileTree/DocTree 표시 정상

---

## 9. 변경 범위 요약

| 파일 | 변경 유형 | 주요 변경 내용 |
|------|----------|--------------|
| `App.jsx` | 수정 | 종합 탭 제거, combined 로직 제거, 색상 교체 |
| `ReportViewer.jsx` | 수정 | ViolationCard 추가, 위반 목록 카드화, 숫자카드 개선, AI박스 개선, 폰트 13px |
| `AnalysisPanel.jsx` | 수정 | severity border-l 추가, SeverityBadge 개선, 필터 색상 교체 |
| `TopNav.jsx` | 수정 | Primary 색상 #0b49b5 적용 |
| `JobInfoBar.jsx` | 수정 | PipelineProgress 컴포넌트 추가, 단계별 진행 표시 |
| `LandingPage.jsx` | 수정 | 에러 박스 개선 |
| CSS/tailwind | 수정 | 색상 변수 #1C4D8D→#0b49b5, 폰트/라인높이 개선 |

**건드리지 않는 파일:** `FileTree.jsx`, `CodeViewer.jsx`, `DocTree.jsx`, `DocViewer.jsx`, `ChecklistForm.jsx`, `analysisStore.js`, `checklistStore.js`, `client.js`

---

## 10. 참고: 현재 코드의 주요 위치

### App.jsx — 종합 탭 위치
`ArtifactTabs` 함수 내부, `<button type="button" className={btnClass("combined")}` 으로 시작하는 블록

### ReportViewer.jsx — 교체 대상 위치
- `CollapsibleSection` 안의 `<table className="w-full text-[11px]">` 블록 전체 → ViolationCard 배열로 교체
- `renderMd` 함수 내 text-[12px] → text-[13px] 상향
- 숫자 카드 `grid grid-cols-3 gap-3 mb-3` 블록 → 개선된 버전으로 교체
- AI 종합 평가 `section` 태그 → 개선된 버전으로 교체

### AnalysisPanel.jsx — severity 관련 위치
위반 항목을 렌더링하는 map 내부에서 각 항목의 최상위 div className에 `severityBorderClass` 추가

---

**작성일:** 2026-03-27
**기반 자료:** FRONTEND_IMPROVEMENT.md, KakaoTalk_Photo_2026-03-27 스크린샷 4장, 현재 코드 분석
