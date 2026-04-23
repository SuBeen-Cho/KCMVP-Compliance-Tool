import { useEffect } from "react";
import { useAnalysisStore } from "../stores/analysisStore";

/**
 * DocTree: 좌측 문서 트리.
 * - docType(설계서/design, 형상관리/scm, 시험서/test)에 해당하는 문서 파일 목록을 표시하고
 *   선택된 문서 경로를 전역 스토어에 반영한다.
 */
export default function DocTree({ docType }) {
  const report = useAnalysisStore((s) => s.report);
  const docSections = useAnalysisStore((s) => s.docSections || []);
  const selectedDocPath = useAnalysisStore((s) => s.selectedDocPath);
  const setSelectedDocPath = useAnalysisStore((s) => s.setSelectedDocPath);

  const docsByType = report?.docs || {};
  const fileList = docType && Array.isArray(docsByType[docType]) ? docsByType[docType] : [];

  // 문서 탭 진입 시 첫 번째 문서를 자동 선택
  useEffect(() => {
    if (!docType) return;
    if (selectedDocPath) return;
    if (!fileList.length) return;
    setSelectedDocPath(fileList[0]);
  }, [docType, fileList, selectedDocPath, setSelectedDocPath]);

  const titleFor = (path) => {
    // 섹션이 쪼개진 경우(file: "docs/design/xxx.pdf#sec_1" 등)에도
    // 원본 PDF 경로(path)로 트리에서 제목을 보여주기 위해 prefix 매칭 사용
    const sec =
      docSections.find((s) => s.file === path) ||
      docSections.find((s) => (s.file || "").startsWith(path + "#"));
    return sec?.title || path;
  };

  const sectionsForDoc = (path) =>
    docSections.filter((s) => {
      const f = s.file || "";
      return f.startsWith(path + "#");
    });

  return (
    <div className="p-2">
      <div className="text-xs text-gray-500 uppercase tracking-wide mb-2">
        {docType === "design"
          ? "설계서"
          : docType === "scm"
          ? "형상관리 문서"
          : docType === "test"
          ? "시험서"
          : "문서"}
        트리
      </div>
      {fileList.length === 0 ? (
        <ul className="text-sm text-gray-700 space-y-0.5">
          <li className="italic text-gray-400">해당 유형의 문서가 업로드되지 않았습니다.</li>
        </ul>
      ) : (
        <ul className="text-sm text-gray-700 space-y-0.5">
          {fileList.map((path) => {
            const isSelectedRoot =
              selectedDocPath === path ||
              (selectedDocPath || "").startsWith(path + "#");
            const childSections = sectionsForDoc(path);
            return (
              <li key={path}>
                <button
                  type="button"
                  onClick={() =>
                    setSelectedDocPath(
                      childSections[0]?.file || path
                    )
                  }
                  className={[
                    "w-full text-left px-2 py-1 rounded flex items-center gap-1.5",
                    isSelectedRoot
                      ? "bg-[#BDE8F5] text-[#0F2854] font-medium"
                      : "hover:bg-gray-100 text-gray-700",
                  ].join(" ")}
                >
                  <span className="inline-block w-1.5 h-1.5 rounded-full bg-[#0b49b5]" />
                  <span className="truncate">{titleFor(path)}</span>
                </button>
                {childSections.length > 0 && (
                  <ul className="mt-0.5 ml-4 space-y-0.5">
                    {childSections.map((sec) => {
                      const secSelected = selectedDocPath === sec.file;
                      return (
                        <li key={sec.file}>
                          <button
                            type="button"
                            onClick={() => setSelectedDocPath(sec.file)}
                            className={[
                              "w-full text-left px-2 py-0.5 rounded flex items-center gap-1.5 text-xs",
                              secSelected
                                ? "bg-[#E0F4FB] text-[#0F2854] font-medium"
                                : "hover:bg-gray-100 text-gray-700",
                            ].join(" ")}
                          >
                            <span className="inline-block w-1 h-1 rounded-full bg-[#4B8AC9]" />
                            <span className="truncate">
                              {sec.title || sec.file}
                            </span>
                          </button>
                        </li>
                      );
                    })}
                  </ul>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}

