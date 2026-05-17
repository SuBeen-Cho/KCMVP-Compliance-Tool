import { useAnalysisStore } from "../stores/analysisStore";

/**
 * FileTree: 좌측 파일 트리 (IDE 스타일).
 * - 위반 있는 파일: 굵은 글씨 + 우측 컬러 chip
 * - 위반 없는 파일: 약화된 텍스트
 * - 선택된 파일: 좌측 컬러바 + 배경 하이라이트
 */
export default function FileTree() {
  const fileList = useAnalysisStore((s) => s.fileList);
  const selectedFilePath = useAnalysisStore((s) => s.selectedFilePath);
  const setSelectedFilePath = useAnalysisStore((s) => s.setSelectedFilePath);
  const setFocusedLine = useAnalysisStore((s) => s.setFocusedLine);
  const violationsByFile = useAnalysisStore((s) => s.violationsByFile || {});

  return (
    <div className="p-2">
      <div className="text-[10px] text-gray-400 uppercase tracking-wider font-semibold mb-2 px-2">
        파일 트리
      </div>
      {fileList.length === 0 ? (
        <ul className="text-sm text-gray-700 space-y-0.5">
          <li className="italic text-gray-400 px-2 text-xs">분석 후 파일 목록 표시</li>
        </ul>
      ) : (
        <ul className="text-[12px] space-y-px">
          {fileList.map((path) => {
            const isSelected = selectedFilePath === path;
            const violations = violationsByFile[path] || [];
            const hasViolations = violations.length > 0;

            const confirmed = hasViolations
              ? violations.filter(
                  (v) =>
                    v.confidence === "확정" ||
                    (v.l2_confirmed && !v.confidence) ||
                    (!v.confidence && !v.needs_ai_review)
                ).length
              : 0;
            const hasConfirmed = confirmed > 0;

            return (
              <li key={path}>
                <button
                  type="button"
                  onClick={() => {
                    setSelectedFilePath(path);
                    setFocusedLine(null);
                  }}
                  className={[
                    "w-full text-left px-2 py-1.5 rounded-md flex items-center gap-1.5 transition-colors",
                    isSelected
                      ? "bg-blue-50 border-l-2 border-l-blue-500 text-[#0F2854] font-semibold"
                      : hasViolations
                      ? "hover:bg-gray-50 text-gray-800 font-medium"
                      : "hover:bg-gray-50 text-gray-400",
                  ].join(" ")}
                >
                  <span className={`truncate flex-1 ${isSelected ? "ml-0" : ""}`}>
                    {path}
                  </span>
                  {hasViolations && (
                    <span
                      className={[
                        "inline-flex items-center justify-center min-w-[20px] h-[18px] px-1.5 rounded-full text-[10px] font-bold shrink-0",
                        hasConfirmed
                          ? "bg-red-500 text-white"
                          : "bg-amber-100 text-amber-700 border border-amber-200",
                      ].join(" ")}
                    >
                      {violations.length}
                    </span>
                  )}
                </button>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
