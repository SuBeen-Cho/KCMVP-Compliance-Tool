import { useAnalysisStore } from "../stores/analysisStore";

// 파이프라인 단계 정의
const PIPELINE_STEPS = [
  { label: "파일 업로드" },
  { label: "전처리" },
  { label: "L1 규칙 검사" },
  { label: "L2 AI 판정" },
  { label: "문서 검사" },
  { label: "보고서 생성" },
];

function PipelineProgress({ progress, currentStep }) {
  const stepIndex = Math.min(
    Math.floor(((progress || 0) / 100) * PIPELINE_STEPS.length),
    PIPELINE_STEPS.length - 1
  );
  const stepLabel = PIPELINE_STEPS[stepIndex]?.label || "처리 중";

  return (
    <div className="flex items-center gap-3">
      <span className="text-[#0b49b5] font-semibold text-[11px] shrink-0">
        분석 진행 중... ({stepIndex + 1}/{PIPELINE_STEPS.length} 단계)
      </span>
      <span className="text-gray-500 text-[11px] shrink-0">⏳ {stepLabel}</span>
      <div className="flex items-center gap-1.5">
        <div className="w-20 h-1.5 bg-gray-200 rounded-full overflow-hidden">
          <div
            className="h-full bg-[#0b49b5] rounded-full transition-all duration-500"
            style={{ width: `${progress || 0}%` }}
          />
        </div>
        <span className="text-[10px] text-gray-400">{progress || 0}%</span>
      </div>
    </div>
  );
}

/**
 * JobInfoBar: 분석 화면 상단에 현재 분석 중인 ZIP/GitHub, 파일 수, 위반 요약을 한 줄로 표시.
 */
export default function JobInfoBar() {
  const { jobMeta, status, progress, currentStep, report } = useAnalysisStore((s) => ({
    jobMeta: s.jobMeta,
    status: s.status,
    progress: s.progress,
    currentStep: s.currentStep,
    report: s.report,
  }));

  if (!jobMeta && !report) return null;

  const sourceType = jobMeta?.sourceType;
  const label = jobMeta?.label;
  const summary = report?.summary || jobMeta?.summary;
  const fileCount =
    jobMeta?.fileCount ?? (Array.isArray(report?.files) ? report.files.length : undefined);

  const leftLabel =
    sourceType === "github"
      ? label ? `GitHub: ${label}` : "GitHub 레포 분석"
      : label ? `ZIP: ${label}` : "ZIP 분석";

  const isRunning = status === "pending" || status === "running";

  return (
    <div className="w-full border-b border-gray-200 bg-gray-50 px-4 py-1.5 text-[11px] text-gray-700 flex items-center justify-between gap-3">
      {/* 왼쪽: 분석 소스 라벨 + 파일 수 */}
      <div className="flex items-center gap-2 min-w-0 shrink-0">
        <span className="inline-flex items-center rounded-full bg-white border border-gray-300 px-2 py-0.5 text-[10px] text-[#0b49b5] font-medium">
          {leftLabel}
        </span>
        {typeof fileCount === "number" && (
          <span className="text-gray-500 text-[10px]">파일 {fileCount}개</span>
        )}
      </div>

      {/* 가운데: 진행 상태 */}
      <div className="flex-1 flex items-center justify-center">
        {isRunning ? (
          <PipelineProgress progress={progress} currentStep={currentStep} />
        ) : status === "failed" ? (
          <span className="text-red-600 font-semibold text-[11px]">❌ 분석 실패 — 파일을 확인하세요</span>
        ) : null}
      </div>

      {/* 오른쪽: 위반 요약 + 상태 dot */}
      <div className="flex items-center gap-2 text-[10px] text-gray-500 shrink-0">
        {summary && !isRunning && (
          <span className="hidden sm:inline">
            위반 {summary.total ?? 0}건 (H {summary.high ?? 0} · M {summary.medium ?? 0} · L {summary.low ?? 0})
          </span>
        )}
        <span className="inline-flex items-center gap-1">
          <span
            className={[
              "w-1.5 h-1.5 rounded-full",
              status === "completed" ? "bg-green-500"
              : status === "failed"  ? "bg-red-500"
              : isRunning            ? "bg-[#0b49b5] animate-pulse"
              : "bg-gray-400",
            ].join(" ")}
          />
          <span>
            {status === "completed" ? "완료"
            : status === "failed"   ? "실패"
            : isRunning             ? "분석 중"
            : "대기"}
          </span>
        </span>
      </div>
    </div>
  );
}
