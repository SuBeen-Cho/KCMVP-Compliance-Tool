import { useState, useRef, useEffect } from "react";
import { createAnalyzeJob } from "../api/client";
import { useAnalysisStore } from "../stores/analysisStore";
import { useChecklistStore } from "../stores/checklistStore";
import ChecklistForm from "../components/ChecklistForm";

const PIPELINE_STAGES = [
  { label: "파일 업로드 & 압축 해제", desc: "ZIP 파일을 서버에 전송하고 소스를 추출합니다.", threshold: 0 },
  { label: "전처리 (AST 파싱)", desc: "C/C++ 소스 구문을 분석하고 PDF 문서를 처리합니다.", threshold: 5 },
  { label: "L1 규칙 검사", desc: "YAML 룰 엔진으로 알려진 취약 패턴을 탐지합니다.", threshold: 15 },
  { label: "L2 AI 판정 (Gemini)", desc: "Gemini가 후보 위반을 심층 판단합니다. (가장 오래 걸림)", threshold: 30 },
  { label: "RAG 근거 수집 & 문서 검사", desc: "KCMVP 가이드라인 근거를 수집하고 문서 적합성을 검증합니다.", threshold: 70 },
  { label: "보고서 생성", desc: "모든 위반을 통합하고 최종 보고서를 작성합니다.", threshold: 80 },
];

function LoadingOverlay({ elapsed }) {
  // 현재 단계 계산
  let currentStageIdx = 0;
  for (let i = PIPELINE_STAGES.length - 1; i >= 0; i--) {
    if (elapsed >= PIPELINE_STAGES[i].threshold) {
      currentStageIdx = i;
      break;
    }
  }

  // 프로그레스바: 0→95% 시뮬레이션 (완료 전 95% 상한)
  const maxProgress = 95;
  const totalEstimate = 100; // 100초 기준으로 95%까지
  const rawProgress = Math.min((elapsed / totalEstimate) * maxProgress, maxProgress);
  const progressPct = Math.round(rawProgress);

  const formatElapsed = (s) => {
    if (s < 60) return `${s}초`;
    return `${Math.floor(s / 60)}분 ${s % 60}초`;
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-[#0F2854]/90 backdrop-blur-sm p-4">
      <div className="w-full max-w-lg bg-white rounded-2xl shadow-2xl p-6 md:p-8">
        {/* 헤더 */}
        <div className="flex items-center gap-3 mb-6">
          <div className="w-8 h-8 rounded-full bg-[#0b49b5] flex items-center justify-center shrink-0">
            <svg className="w-4 h-4 text-white animate-spin" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4l3-3-3-3v4a8 8 0 00-8 8h4z" />
            </svg>
          </div>
          <div>
            <p className="text-base font-bold text-[#0F2854]">분석 파이프라인 실행 중</p>
            <p className="text-xs text-gray-500">경과 시간: {formatElapsed(elapsed)}</p>
          </div>
        </div>

        {/* 프로그레스바 */}
        <div className="mb-6">
          <div className="flex justify-between text-xs text-gray-500 mb-1.5">
            <span>진행률</span>
            <span className="font-semibold text-[#0b49b5]">{progressPct}%</span>
          </div>
          <div className="h-2.5 bg-gray-100 rounded-full overflow-hidden">
            <div
              className="h-full bg-gradient-to-r from-[#0b49b5] to-[#4988C4] rounded-full transition-all duration-1000 ease-out"
              style={{ width: `${progressPct}%` }}
            />
          </div>
        </div>

        {/* 단계 리스트 */}
        <ul className="space-y-3">
          {PIPELINE_STAGES.map((stage, i) => {
            const isDone = i < currentStageIdx;
            const isCurrent = i === currentStageIdx;
            return (
              <li key={stage.label} className="flex items-start gap-3">
                {/* 아이콘 */}
                <div className="shrink-0 mt-0.5">
                  {isDone ? (
                    <span className="inline-flex w-5 h-5 rounded-full bg-green-100 border border-green-400 items-center justify-center">
                      <svg className="w-3 h-3 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                      </svg>
                    </span>
                  ) : isCurrent ? (
                    <span className="inline-flex w-5 h-5 rounded-full bg-amber-100 border border-amber-400 items-center justify-center">
                      <svg className="w-3 h-3 text-amber-500 animate-spin" fill="none" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4l3-3-3-3v4a8 8 0 00-8 8h4z" />
                      </svg>
                    </span>
                  ) : (
                    <span className="inline-flex w-5 h-5 rounded-full bg-gray-100 border border-gray-300 items-center justify-center">
                      <span className="w-1.5 h-1.5 rounded-full bg-gray-300" />
                    </span>
                  )}
                </div>
                {/* 텍스트 */}
                <div>
                  <p className={`text-sm font-medium leading-tight ${isDone ? "text-green-700" : isCurrent ? "text-amber-700" : "text-gray-400"}`}>
                    {stage.label}
                  </p>
                  {isCurrent && (
                    <p className="text-xs text-gray-500 mt-0.5 leading-snug">{stage.desc}</p>
                  )}
                </div>
              </li>
            );
          })}
        </ul>

        <p className="mt-5 text-center text-[11px] text-gray-400">
          AI 판정 단계는 최대 2~3분 소요될 수 있습니다. 창을 닫지 마세요.
        </p>
      </div>
    </div>
  );
}

const ZIP_MIME = "application/zip";
const ZIP_EXT = ".zip";

function isZipFile(file) {
  if (!file) return false;
  const name = (file.name || "").toLowerCase();
  const type = (file.type || "").toLowerCase();
  return name.endsWith(ZIP_EXT) || type === ZIP_MIME || type === "application/x-zip-compressed";
}

/**
 * 업로드 전용 랜딩 페이지.
 * - 화면 전체가 ZIP 드래그앤드롭 영역 (드래그 시 오버레이 표시)
 * - GitHub URL 입력 카드 / ZIP 파일 선택 카드
 */
export default function LandingPage() {
  const [githubUrl, setGithubUrl] = useState("");
  const [zipFile, setZipFile] = useState(null);
  const [designDoc, setDesignDoc] = useState(null);
  const [configDoc, setConfigDoc] = useState(null);
  const [testDoc, setTestDoc] = useState(null);
  const [loading, setLoading] = useState(false);
  const [elapsed, setElapsed] = useState(0);
  const [error, setError] = useState(null);
  const [isDragging, setIsDragging] = useState(false);
  const [dropError, setDropError] = useState(null);
  const dragCounter = useRef(0);

  // loading 중 경과 시간 카운터
  useEffect(() => {
    if (!loading) { setElapsed(0); return; }
    const timer = setInterval(() => setElapsed((s) => s + 1), 1000);
    return () => clearInterval(timer);
  }, [loading]);

  const setJob = useAnalysisStore((s) => s.setJob);
  const reset = useAnalysisStore((s) => s.reset);
  const getAnalyzeParams = useChecklistStore((s) => s.getAnalyzeParams);

  const handleZipChange = (event) => {
    const file = event.target.files?.[0];
    setZipFile(file || null);
    setDropError(null);
  };

  const handleDesignChange = (event) => {
    const file = event.target.files?.[0] || null;
    setDesignDoc(file);
  };

  const handleConfigChange = (event) => {
    const file = event.target.files?.[0] || null;
    setConfigDoc(file);
  };

  const handleTestChange = (event) => {
    const file = event.target.files?.[0] || null;
    setTestDoc(file);
  };

  const handleDragEnter = (e) => {
    e.preventDefault();
    e.stopPropagation();
    dragCounter.current += 1;
    if (e.dataTransfer?.types?.includes("Files")) setIsDragging(true);
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    e.stopPropagation();
    dragCounter.current -= 1;
    if (dragCounter.current === 0) {
      setIsDragging(false);
      setDropError(null);
    }
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    e.stopPropagation();
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    dragCounter.current = 0;
    setIsDragging(false);
    setDropError(null);
    const files = e.dataTransfer?.files;
    if (!files?.length) return;
    const file = files[0];
    if (!isZipFile(file)) {
      setDropError("ZIP 파일(.zip)만 업로드할 수 있습니다.");
      return;
    }
    setZipFile(file);
  };

  const handleAnalyzeWithZip = async () => {
    if (!zipFile) {
      setError("ZIP 파일을 선택해 주세요.");
      return;
    }
    setLoading(true);
    setError(null);
    setDropError(null);
    reset();
    try {
      const { algorithm, mode } = getAnalyzeParams();
      const res = await createAnalyzeJob({
        file: zipFile,
        designDoc,
        configDoc,
        testDoc,
        algorithm,
        mode: mode || undefined,
      });
      if (res?.job_id) {
        setJob(res.job_id, {
          sourceType: "zip",
          label: zipFile.name,
          fileCount: res?.preprocess?.file_count,
        });
      } else {
        setError("job_id가 응답에 없습니다.");
      }
    } catch (e) {
      setError(e?.message || "분석 요청 중 오류가 발생했습니다.");
    } finally {
      setLoading(false);
    }
  };

  const handleAnalyzeWithGithub = async () => {
    if (!githubUrl.trim()) {
      setError("GitHub URL을 입력해 주세요.");
      return;
    }
    setLoading(true);
    setError(null);
    reset();
    try {
      const trimmed = githubUrl.trim();
      const { algorithm, mode } = getAnalyzeParams();
      const res = await createAnalyzeJob({
        source: trimmed,
        algorithm,
        mode: mode || undefined,
      });
      if (res?.job_id) {
        // owner/repo 형태만 깔끔하게 표시
        const label = trimmed.startsWith("http")
          ? trimmed.replace(/^https?:\/\/github\.com\//, "")
          : trimmed;
        setJob(res.job_id, {
          sourceType: "github",
          label,
          fileCount: res?.preprocess?.file_count,
        });
      } else {
        setError("job_id가 응답에 없습니다.");
      }
    } catch (e) {
      // 현재 백엔드는 ZIP 파일이 없으면 400을 반환하므로, GitHub 기능은 이후에 연동 예정.
      setError(
        e?.message ||
          "GitHub URL 기반 분석은 아직 백엔드에서 완전히 지원되지 않습니다. ZIP 파일 업로드를 사용해 주세요."
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      className="min-h-screen bg-[#EEEEEE] text-[#111827] font-[Pretendard] relative"
      onDragEnter={handleDragEnter}
      onDragLeave={handleDragLeave}
      onDragOver={handleDragOver}
      onDrop={handleDrop}
    >
      {/* 분석 중 파이프라인 오버레이 */}
      {loading && <LoadingOverlay elapsed={elapsed} />}

      {/* 드래그 중 전역 오버레이 — 반응형 */}
      {isDragging && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center p-4 md:p-8 lg:p-12 transition-opacity duration-150"
          aria-hidden="true"
        >
          <div className="absolute inset-0 bg-[#0F2854]/80 backdrop-blur-sm" />
          <div className="relative w-full max-w-xl rounded-2xl border-2 border-dashed border-[#e7746f] bg-white/95 shadow-2xl p-6 md:p-10 text-center">
            <div className="text-4xl md:text-5xl lg:text-6xl mb-4 md:mb-6 text-[#0b49b5]">
              📦
            </div>
            <p className="text-lg md:text-xl lg:text-2xl font-semibold text-[#0F2854] mb-2">
              ZIP 파일을 여기에 놓으세요
            </p>
            <p className="text-sm md:text-base text-[#6B7280]">
              .zip 파일만 업로드할 수 있습니다
            </p>
          </div>
        </div>
      )}

      <header className="px-4 sm:px-6 md:px-8 py-4 flex items-center justify-between">
        <div className="text-base md:text-lg font-semibold text-[#0F2854]">KCMVP Pre-Validator</div>
      </header>

      <main className="px-4 md:px-10 lg:px-16 py-6 md:py-10 flex flex-col items-center">
        <section className="max-w-3xl text-center mb-6 md:mb-8">
          <h1 className="text-2xl sm:text-3xl md:text-4xl font-bold text-[#0F2854] mb-3">
            암호 모듈 정적 분석 도구
          </h1>
          <p className="text-sm md:text-base text-[#6B7280]">
            GitHub 링크나 ZIP 파일을 업로드하면 KCMVP 룰로 소스를 분석하고, 위반 위치와 설명을
            IDE 형태로 보여줍니다.
          </p>
        </section>

        <ChecklistForm />

        {(error || dropError) && (
          <div className="mb-4 max-w-xl w-full rounded-xl border-2 border-red-200 bg-red-50 p-4">
            <div className="flex items-start gap-2">
              <span className="text-red-500 text-base shrink-0 mt-0.5">⚠</span>
              <div className="flex-1 min-w-0">
                <p className="font-bold text-[13px] text-red-700 mb-1">업로드 실패</p>
                <p className="text-[12px] text-red-600 leading-relaxed">{error || dropError}</p>
                <p className="text-[11px] text-red-400 mt-2">
                  ZIP 파일 형식, 크기, 네트워크 상태를 확인하고 다시 시도해 주세요.
                </p>
              </div>
            </div>
            <button
              type="button"
              className="mt-3 px-3 py-1.5 text-[12px] font-medium bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors"
              onClick={() => { setError(null); }}
            >
              닫기
            </button>
          </div>
        )}

        <section className="grid gap-4 sm:gap-6 md:grid-cols-2 max-w-4xl w-full">
          {/* GitHub 카드 */}
          <div className="group rounded-xl bg-white border border-[#E5E7EB] shadow-sm p-4 sm:p-6 flex flex-col justify-between transition-colors hover:border-[#0b49b5] hover:shadow-md">
            <div>
              <h2 className="text-lg font-semibold text-[#0F2854] mb-2">GitHub 레포 분석</h2>
              <p className="text-sm text-[#6B7280] mb-4">
                공개 레포지토리 URL을 붙여넣고 분석을 시작합니다. (현재는 ZIP 우선 지원)
              </p>
              <input
                type="url"
                value={githubUrl}
                onChange={(e) => setGithubUrl(e.target.value)}
                placeholder="https://github.com/user/repo"
                className="w-full rounded-md border border-[#D1D5DB] px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-[#4988C4] focus:border-transparent"
              />
            </div>
            <button
              type="button"
              onClick={handleAnalyzeWithGithub}
              disabled={loading}
              className="mt-4 inline-flex items-center justify-center rounded-md bg-[#0b49b5] text-white text-sm font-medium px-4 py-2 shadow-sm hover:bg-[#0a3d96] disabled:opacity-60 disabled:cursor-not-allowed transition-colors relative"
            >
              {loading ? "분석 중..." : "GitHub 링크로 분석"}
              <span className="absolute inset-x-0 -bottom-1 h-0.5 bg-[#e7746f]" />
            </button>
          </div>

          {/* ZIP 카드 */}
          <div className="group rounded-xl bg-white border border-dashed border-[#CBD5E1] shadow-sm p-4 sm:p-6 flex flex-col justify-between transition-all hover:border-[#4988C4] hover:bg-[#F9FAFB]">
            <div className="flex-1 flex flex-col gap-3">
              <p className="text-sm text-[#6B7280]">
                아래 한 줄에서 코드 ZIP과 3종 문서 PDF(설계서 / 형상관리 / 시험서)를 함께 업로드하세요.
              </p>
              <div className="flex flex-col gap-2 text-xs">
                <div className="flex flex-wrap gap-2">
                  <label className="flex-1 min-w-[140px] inline-flex items-center justify-between rounded-md border border-[#0b49b5] text-[#0b49b5] px-2 py-1 cursor-pointer bg-white">
                    <span className="mr-2">코드 ZIP</span>
                    <input type="file" accept=".zip" onChange={handleZipChange} className="hidden" />
                  </label>
                  <label className="flex-1 min-w-[140px] inline-flex items-center justify-between rounded-md border border-[#0b49b5] text-[#0b49b5] px-2 py-1 cursor-pointer bg-white">
                    <span className="mr-2">설계서 PDF</span>
                    <input type="file" accept=".pdf" onChange={handleDesignChange} className="hidden" />
                  </label>
                  <label className="flex-1 min-w-[160px] inline-flex items-center justify-between rounded-md border border-[#0b49b5] text-[#0b49b5] px-2 py-1 cursor-pointer bg-white">
                    <span className="mr-2">형상관리 PDF</span>
                    <input type="file" accept=".pdf" onChange={handleConfigChange} className="hidden" />
                  </label>
                  <label className="flex-1 min-w-[140px] inline-flex items-center justify-between rounded-md border border-[#0b49b5] text-[#0b49b5] px-2 py-1 cursor-pointer bg-white">
                    <span className="mr-2">시험서 PDF</span>
                    <input type="file" accept=".pdf" onChange={handleTestChange} className="hidden" />
                  </label>
                </div>
                <div className="space-y-1 text-[11px] text-[#4B5563]">
                  {zipFile && <p>코드 ZIP: {zipFile.name}</p>}
                  {designDoc && <p>설계서: {designDoc.name}</p>}
                  {configDoc && <p>형상관리: {configDoc.name}</p>}
                  {testDoc && <p>시험서: {testDoc.name}</p>}
                </div>
                <p className="mt-1 text-[11px] text-[#9CA3AF]">
                  ZIP(코드) 1개 + PDF(문서) 3개까지 업로드할 수 있습니다. 문서는 텍스트 기반 PDF를 권장합니다.
                </p>
              </div>
            </div>
            <button
              type="button"
              onClick={handleAnalyzeWithZip}
              disabled={loading}
              className="mt-4 inline-flex items-center justify-center rounded-md bg-[#0b49b5] text-white text-sm font-medium px-4 py-2 shadow-sm hover:bg-[#0a3d96] disabled:opacity-60 disabled:cursor-not-allowed transition-colors relative"
            >
              {loading ? "분석 중..." : "ZIP 파일로 분석"}
              <span className="absolute inset-x-0 -bottom-1 h-0.5 bg-[#e7746f]" />
            </button>
          </div>
        </section>
      </main>
    </div>
  );
}

