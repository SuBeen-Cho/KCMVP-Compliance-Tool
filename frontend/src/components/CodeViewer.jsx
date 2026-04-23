import { useEffect, useMemo, useState } from "react";
import { useAnalysisStore } from "../stores/analysisStore";
import { getFile, getFileAst, getSymbolGraph } from "../api/client";

/**
 * CodeViewer: 중앙 코드 뷰.
 * - 좌측 파일 트리에서 선택된 파일의 내용을 불러와 표시
 * - 위반이 있는 줄은 옅은 붉은색 배경으로 하이라이트
 */
export default function CodeViewer() {
  const jobId = useAnalysisStore((s) => s.jobId);
  const selectedFilePath = useAnalysisStore((s) => s.selectedFilePath);
  const fileContents = useAnalysisStore((s) => s.fileContents);
  const setFileContent = useAnalysisStore((s) => s.setFileContent);
  const violationsByFile = useAnalysisStore((s) => s.violationsByFile || {});
  const focusedLine = useAnalysisStore((s) => s.focusedLine);
  const focusedPatch = useAnalysisStore((s) => s.focusedPatch);
  const [showAst, setShowAst] = useState(false);
  const [astData, setAstData] = useState(null);
  const [astLoading, setAstLoading] = useState(false);
  const [showSymbolFlow, setShowSymbolFlow] = useState(false);
  const [symbolGraphData, setSymbolGraphData] = useState(null);
  const [symbolGraphLoading, setSymbolGraphLoading] = useState(false);

  useEffect(() => {
    if (!jobId || !selectedFilePath) return;
    if (fileContents[selectedFilePath]) return;

    let canceled = false;

    const load = async () => {
      try {
        const res = await getFile(jobId, selectedFilePath);
        const content = res?.content ?? "";
        if (!canceled) {
          setFileContent(selectedFilePath, content);
        }
      } catch {
        if (!canceled) {
          setFileContent(selectedFilePath, "// 파일을 불러오는 중 오류가 발생했습니다.");
        }
      }
    };

    load();

    return () => {
      canceled = true;
    };
  }, [jobId, selectedFilePath]);

  const content =
    (selectedFilePath && fileContents[selectedFilePath]) ||
    (selectedFilePath ? "// 코드를 불러오는 중입니다..." : null);

  const lines = useMemo(
    () => (content ? content.split(/\r?\n/) : []),
    [content],
  );

  const fileViolations = useMemo(
    () => violationsByFile[selectedFilePath] || [],
    [violationsByFile, selectedFilePath],
  );

  const lineViolations = useMemo(() => {
    const map = {};
    for (const v of fileViolations) {
      if (!v || typeof v.line !== "number") continue;
      const start = v.line;
      const end =
        typeof v.endLine === "number" && v.endLine >= start ? v.endLine : start;
      for (let ln = start; ln <= end; ln += 1) {
        if (!map[ln]) map[ln] = [];
        map[ln].push({ ...v, isStart: ln === start });
      }
    }
    return map;
  }, [fileViolations]);

  // 선택된 파일/라인이 바뀌면 해당 줄을 화면 중앙 근처로 스크롤
  useEffect(() => {
    if (!selectedFilePath || !focusedLine) return;
    if (!lines.length || focusedLine < 1 || focusedLine > lines.length) return;
    const el = document.getElementById(`code-line-${focusedLine}`);
    if (!el) return;
    el.scrollIntoView({ block: "center", behavior: "smooth" });
  }, [selectedFilePath, focusedLine, lines.length]);

  useEffect(() => {
    if (!showSymbolFlow || !jobId) {
      setSymbolGraphData(null);
      return;
    }
    let canceled = false;
    setSymbolGraphLoading(true);
    getSymbolGraph(jobId)
      .then((res) => {
        if (!canceled) setSymbolGraphData(res ?? null);
      })
      .catch(() => {
        if (!canceled) setSymbolGraphData(null);
      })
      .finally(() => {
        if (!canceled) setSymbolGraphLoading(false);
      });
    return () => { canceled = true; };
  }, [showSymbolFlow, jobId]);

  const callGraphList = useMemo(() => {
    const g = symbolGraphData?.call_graph;
    if (!Array.isArray(g)) return [];
    return g;
  }, [symbolGraphData]);

  useEffect(() => {
    if (!showAst || !jobId || !selectedFilePath) {
      setAstData(null);
      return;
    }
    let canceled = false;
    setAstLoading(true);
    getFileAst(jobId, selectedFilePath)
      .then((res) => {
        if (!canceled) setAstData(res?.ast ?? null);
      })
      .catch(() => {
        if (!canceled) setAstData(null);
      })
      .finally(() => {
        if (!canceled) setAstLoading(false);
      });
    return () => { canceled = true; };
  }, [showAst, jobId, selectedFilePath]);

  return (
    <div className="p-4 font-mono text-xs sm:text-sm bg-gray-50 min-h-full flex flex-col">
      <div className="text-gray-500 flex items-center justify-between gap-2 flex-wrap">
        {selectedFilePath ? (
          <span>선택된 파일: {selectedFilePath}</span>
        ) : (
          <span>파일을 선택하면 이 영역에 코드가 표시됩니다.</span>
        )}
        {selectedFilePath && jobId && (
          <>
            <button
              type="button"
              onClick={() => setShowAst((v) => !v)}
              className="text-xs px-2 py-1 rounded border border-gray-300 bg-white hover:bg-gray-50 text-gray-700"
            >
              {showAst ? "AST 숨기기" : "전체 파일 AST 보기"}
            </button>
            <button
              type="button"
              onClick={() => setShowSymbolFlow((v) => !v)}
              className="text-xs px-2 py-1 rounded border border-gray-300 bg-white hover:bg-gray-50 text-gray-700"
            >
              {showSymbolFlow ? "파일 전체 흐름 숨기기" : "파일 전체 흐름 보기"}
            </button>
          </>
        )}
      </div>
      <div className="mt-2 flex-1 overflow-auto border border-gray-200 rounded bg-white">
        {/* 파일 레벨 위반(COM-001 등)에 대한 상단 배너 */}
        {selectedFilePath &&
          fileViolations.some((v) => !v.line) && (
            <div className="px-3 py-2 border-b border-red-100 bg-red-50 text-[11px] sm:text-xs text-red-700">
              이 파일에는 파일 전체 수준의 위반(COM-001 등)이 있습니다. 잔존 정보 제거 코드가
              전혀 없거나, 가이드라인에서 요구하는 처리 로직이 누락되어 있을 수 있습니다.
            </div>
          )}
        {selectedFilePath && lines.length === 0 && (
          <div className="p-3 text-gray-400">이 파일은 비어 있거나 내용을 불러오지 못했습니다.</div>
        )}
        {lines.map((text, idx) => {
          const lineNumber = idx + 1;
          const violations = lineViolations[lineNumber] || [];
          const hasViolation = violations.length > 0;
          const hasStart = violations.some((v) => v.isStart);
          // 현재 선택된 패치가 이 줄에 해당하는지 확인
          const isPatchLine =
            focusedPatch &&
            focusedPatch.line === lineNumber &&
            (!focusedPatch.filePath || focusedPatch.filePath === selectedFilePath);
          return (
            <div key={lineNumber}>
              <div
                id={`code-line-${lineNumber}`}
                className={[
                  "flex px-2",
                  isPatchLine
                    ? "bg-red-200 border-l-2 border-red-500"
                    : hasViolation
                    ? hasStart || lineNumber === focusedLine
                      ? "bg-red-100"
                      : "bg-red-50"
                    : "",
                ].join(" ")}
              >
                <div className="w-10 pr-2 text-right text-[10px] sm:text-[11px] text-gray-400 select-none">
                  {lineNumber}
                </div>
                <pre className="flex-1 text-[11px] sm:text-[13px] text-gray-800 whitespace-pre">
                  {text || " "}
                </pre>
              </div>
              {isPatchLine && (
                <div className="mx-2 mb-1 border border-blue-200 rounded-md bg-blue-50 text-[11px]">
                  <div className="flex items-center gap-2 px-3 py-1.5 border-b border-blue-200 bg-blue-100">
                    <span className="font-semibold text-blue-800">패치 제안</span>
                    {focusedPatch.ruleId && (
                      <span className="text-blue-600">{focusedPatch.ruleId}</span>
                    )}
                  </div>
                  <pre className="px-3 py-2 whitespace-pre-wrap text-gray-700 max-h-48 overflow-auto">
                    {focusedPatch.content}
                  </pre>
                </div>
              )}
            </div>
          );
        })}
      </div>
      {showAst && selectedFilePath && (
        <div className="mt-2 border border-gray-200 rounded bg-gray-900 text-gray-100 overflow-auto max-h-64">
          <div className="px-2 py-1 text-[10px] text-gray-400 border-b border-gray-700">
            분석된 AST (파일: {selectedFilePath})
          </div>
          <pre className="p-2 text-[11px] whitespace-pre overflow-auto">
            {astLoading ? "불러오는 중..." : (astData && Object.keys(astData).length > 0 ? JSON.stringify(astData, null, 2) : "(AST 없음 또는 파싱 실패)")}
          </pre>
        </div>
      )}
      {showSymbolFlow && jobId && (
        <div className="mt-2 border border-gray-200 rounded bg-white overflow-auto max-h-80">
          <div className="px-2 py-1 text-[10px] text-gray-500 border-b border-gray-200 bg-gray-50">
            파일 전체 흐름 (호출 → 정의 연결)
          </div>
          {symbolGraphLoading ? (
            <div className="p-3 text-gray-500 text-sm">불러오는 중...</div>
          ) : callGraphList.length === 0 ? (
            <div className="p-3 text-gray-500 text-sm">호출 그래프가 비어 있습니다. (C 소스 파싱 후 생성됩니다)</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-[11px] sm:text-xs border-collapse">
                <thead>
                  <tr className="bg-gray-100 text-gray-600">
                    <th className="p-2 border-b">호출 파일</th>
                    <th className="p-2 border-b">줄</th>
                    <th className="p-2 border-b">호출 함수</th>
                    <th className="p-2 border-b">정의 파일</th>
                    <th className="p-2 border-b">정의 줄</th>
                  </tr>
                </thead>
                <tbody>
                  {callGraphList.map((edge, i) => (
                    <tr key={i} className="border-b border-gray-100 hover:bg-gray-50">
                      <td className="p-2 font-mono">{edge.caller_file ?? "—"}</td>
                      <td className="p-2 text-gray-600">{edge.caller_line ?? "—"}</td>
                      <td className="p-2 font-medium">{edge.callee_name ?? "—"}</td>
                      <td className="p-2 font-mono text-blue-700">{edge.defined_in ?? "—"}</td>
                      <td className="p-2 text-gray-600">{edge.def_line ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
