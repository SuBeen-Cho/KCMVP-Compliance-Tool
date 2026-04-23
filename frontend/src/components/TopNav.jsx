import { useAnalysisStore } from "../stores/analysisStore";

/**
 * TopNav: 로고 + 새 분석 버튼
 */
export default function TopNav() {
  const reset = useAnalysisStore((s) => s.reset);

  return (
    <header className="h-12 flex items-center px-5 gap-4 bg-[#0b49b5] shadow-md">
      {/* 로고 */}
      <div className="flex items-center gap-2">
        <span className="text-white text-base font-bold tracking-wide">KCMVP</span>
        <span className="text-blue-200 text-[13px] font-normal">사전 적합성 점검</span>
      </div>

      {/* 새 분석 버튼 */}
      {reset && (
        <button
          type="button"
          onClick={reset}
          className="ml-auto px-3 py-1.5 rounded-md text-[12px] font-medium bg-white/10 text-white border border-white/20 hover:bg-white/20 transition-colors"
        >
          + 새 분석
        </button>
      )}
    </header>
  );
}
