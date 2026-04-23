import { useEffect } from "react";
import TopNav from "./components/TopNav";
import JobInfoBar from "./components/JobInfoBar";
import FileTree from "./components/FileTree";
import CodeViewer from "./components/CodeViewer";
import AnalysisPanel from "./components/AnalysisPanel";
import DocTree from "./components/DocTree";
import DocViewer from "./components/DocViewer";
import ReportViewer from "./components/ReportViewer";
import LandingPage from "./pages/LandingPage";
import { useAnalysisStore } from "./stores/analysisStore";
import { getAnalyzeStatus, getReport, getPatches, getDocPreprocess } from "./api/client";

function ArtifactTabs() {
  const active = useAnalysisStore((s) => s.activeArtifactTab);
  const setActive = useAnalysisStore((s) => s.setActiveArtifactTab);
  const countsByTab = useAnalysisStore((s) => s.countsByTab || {});

  const btnClass = (tab) =>
    [
      "px-3 py-1.5 text-xs md:text-sm border-b-2 transition-colors whitespace-nowrap",
      active === tab
        ? "border-[#0b49b5] text-[#0b49b5] font-semibold"
        : "border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300",
    ].join(" ");

  const badge = (n) =>
    typeof n === "number" && n > 0 ? (
      <span className="ml-1 inline-flex items-center justify-center min-w-5 h-4 px-1 rounded-full bg-red-100 border border-red-200 text-[10px] font-semibold text-red-700">
        {n}
      </span>
    ) : null;

  return (
    <div className="px-4 md:px-6 border-b border-gray-200 bg-white shadow-sm">
      <div className="flex gap-1 overflow-x-auto text-xs md:text-sm">
        {/* 보고서 탭 */}
        <button type="button" className={btnClass("report")} onClick={() => setActive("report")}>
          📋 보고서
        </button>
        <span className="self-stretch w-px bg-gray-200 my-1.5" />
        {/* 문서 탭들 */}
        <button type="button" className={btnClass("design")} onClick={() => setActive("design")}>
          설계서{badge(countsByTab.design)}
        </button>
        <button type="button" className={btnClass("scm")} onClick={() => setActive("scm")}>
          형상관리{badge(countsByTab.scm)}
        </button>
        <button type="button" className={btnClass("test")} onClick={() => setActive("test")}>
          시험서{badge(countsByTab.test)}
        </button>
        <span className="self-stretch w-px bg-gray-200 my-1.5" />
        {/* 코드 탭 */}
        <button type="button" className={btnClass("code")} onClick={() => setActive("code")}>
          코드{badge(countsByTab.code)}
        </button>
      </div>
    </div>
  );
}

function AnalyzeLayout() {
  const active = useAnalysisStore((s) => s.activeArtifactTab);

  const isReportView = active === "report";
  const isCodeView   = active === "code";
  const docType      = active === "design" || active === "scm" || active === "test" ? active : null;

  if (isReportView) {
    return (
      <div className="app-body">
        {/* 보고서 뷰: 중앙 영역 전체 사용, 우측 패널은 유지 */}
        <main className="editor-area" style={{ flex: 1 }}>
          <ReportViewer />
        </main>
        <aside className="result-panel">
          <AnalysisPanel />
        </aside>
      </div>
    );
  }

  return (
    <div className="app-body">
      <aside className="sidebar">
        {isCodeView ? <FileTree /> : <DocTree docType={docType} />}
      </aside>
      <main className="editor-area">
        {isCodeView ? <CodeViewer /> : <DocViewer docType={docType} />}
      </main>
      <aside className="result-panel">
        <AnalysisPanel />
      </aside>
    </div>
  );
}

function App() {
  const jobId = useAnalysisStore((s) => s.jobId);
  const setStatus = useAnalysisStore((s) => s.setStatus);
  const setReport = useAnalysisStore((s) => s.setReport);
  const setPatches = useAnalysisStore((s) => s.setPatches);
  const setJobMeta = useAnalysisStore((s) => s.setJobMeta);
  const setDocSections = useAnalysisStore((s) => s.setDocSections);

  useEffect(() => {
    if (!jobId) return;
    let canceled = false;
    let timer = null;

    // 분석 완료 후 report/patches/docs 일괄 로드 (1회만)
    const loadFinalData = async () => {
      try {
        const reportRes = await getReport(jobId);
        if (!canceled && reportRes) {
          setReport(reportRes);
          setJobMeta({
            summary:   reportRes.summary,
            fileCount: Array.isArray(reportRes.files) ? reportRes.files.length : undefined,
            algorithm: reportRes.meta?.algorithm,
            mode:      reportRes.meta?.mode,
            date:      reportRes.meta?.date,
          });
        }
      } catch { /* report 로드 실패는 무시 */ }

      try {
        const patchesRes = await getPatches(jobId);
        if (!canceled && patchesRes) setPatches(patchesRes.patches || []);
      } catch { /* patches 로드 실패는 무시 */ }

      try {
        const docRes = await getDocPreprocess(jobId);
        if (!canceled && docRes && Array.isArray(docRes.sections)) {
          setDocSections(docRes.sections);
        }
      } catch {
        if (!canceled) setDocSections([]);
      }
    };

    // status 폴링 (1.5초 간격, 진행 중일 때만)
    const pollStatus = async () => {
      try {
        const statusRes = await getAnalyzeStatus(jobId);
        if (canceled) return;

        const { status, progress, current_step } = statusRes;
        setStatus(status, progress, current_step);

        // 완료 또는 실패 → 폴링 중단 후 최종 데이터 로드
        if (status === "completed" || status === "failed") {
          clearInterval(timer);
          timer = null;
          if (status === "completed") await loadFinalData();
        }
      } catch (e) {
        if (!canceled) setStatus("failed", 0, null);
        clearInterval(timer);
        timer = null;
      }
    };

    // 즉시 1회 + 1.5초 간격 반복
    pollStatus();
    timer = setInterval(pollStatus, 1500);

    return () => {
      canceled = true;
      if (timer) clearInterval(timer);
    };
  }, [jobId, setStatus, setReport, setPatches, setJobMeta, setDocSections]);

  if (!jobId) {
    return <LandingPage />;
  }

  return (
    <div className="app-layout">
      <TopNav />
      <JobInfoBar />
       <ArtifactTabs />
      <AnalyzeLayout />
    </div>
  );
}

export default App;
