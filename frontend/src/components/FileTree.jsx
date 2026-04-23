import { useAnalysisStore } from "../stores/analysisStore";

/**
 * FileTree: 좌측 파일 트리. 분석 결과의 파일 목록을 표시하고 선택 상태를 전역 스토어에 반영.
 */
export default function FileTree() {
  const fileList = useAnalysisStore((s) => s.fileList);
  const selectedFilePath = useAnalysisStore((s) => s.selectedFilePath);
  const setSelectedFilePath = useAnalysisStore((s) => s.setSelectedFilePath);
  const setFocusedLine = useAnalysisStore((s) => s.setFocusedLine);
  const violationsByFile = useAnalysisStore((s) => s.violationsByFile || {});

  return (
    <div className="p-2">
      <div className="text-xs text-gray-500 uppercase tracking-wide mb-2">파일 트리</div>
      {fileList.length === 0 ? (
        <ul className="text-sm text-gray-700 space-y-0.5">
          <li className="italic text-gray-400">분석 후 또는 업로드 후 파일 목록 표시</li>
        </ul>
      ) : (
        <ul className="text-sm text-gray-700 space-y-0.5">
          {fileList.map((path) => {
            const isSelected = selectedFilePath === path;
            const violations = violationsByFile[path] || [];
            const hasViolations = violations.length > 0;
            return (
              <li key={path}>
                <button
                  type="button"
                  onClick={() => {
                    setSelectedFilePath(path);
                    setFocusedLine(null);
                  }}
                  className={[
                    "w-full text-left px-2 py-1 rounded flex items-center gap-1.5",
                    isSelected
                      ? "bg-[#BDE8F5] text-[#0F2854] font-medium"
                      : hasViolations
                      ? "hover:bg-red-50 text-red-600"
                      : "hover:bg-gray-100 text-gray-700",
                  ].join(" ")}
                >
                  <span className="truncate flex-1">{path}</span>
                  {hasViolations && (() => {
                    const confirmed = violations.filter(
                      (v) => v.confidence === "확정" || (v.l2_confirmed && !v.confidence) || (!v.confidence && !v.needs_ai_review)
                    ).length;
                    return confirmed > 0 ? (
                      <span className="inline-flex items-center justify-center min-w-[18px] h-[18px] px-1 rounded-full bg-red-100 border border-red-200 text-[10px] font-bold text-red-700 shrink-0">
                        {violations.length}
                      </span>
                    ) : (
                      <span className="inline-flex items-center justify-center min-w-[18px] h-[18px] px-1 rounded-full bg-amber-50 border border-amber-200 text-[10px] font-bold text-amber-600 shrink-0">
                        {violations.length}
                      </span>
                    );
                  })()}
                </button>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
