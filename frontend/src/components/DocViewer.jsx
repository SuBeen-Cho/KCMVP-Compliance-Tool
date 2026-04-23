import { useEffect, useMemo, useRef, useState, cloneElement, isValidElement } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { useAnalysisStore } from "../stores/analysisStore";

const SEV_STYLE = {
  high:   { border: "border-red-300",   bg: "bg-red-50",   text: "text-red-700",   badge: "bg-red-100 text-red-700 border-red-200",   icon: "🔴" },
  medium: { border: "border-amber-300", bg: "bg-amber-50", text: "text-amber-800", badge: "bg-amber-100 text-amber-700 border-amber-200", icon: "🟡" },
  low:    { border: "border-gray-300",  bg: "bg-gray-50",  text: "text-gray-600",  badge: "bg-gray-100 text-gray-600 border-gray-200",   icon: "⚪" },
};

function MissingViolationBanners({ violations }) {
  const [expanded, setExpanded] = useState(violations.length <= 3);
  const visible = expanded ? violations : violations.slice(0, 3);
  return (
    <div className="mb-2 space-y-1">
      {visible.map((v, i) => {
        const sev = (v.severity || "medium").toLowerCase();
        const s = SEV_STYLE[sev] || SEV_STYLE.medium;
        const isConfirmed = (v.confidence === "확정" || v.l2_confirmed) && !v.needs_ai_review;
        return (
          <div
            key={`missing-${v.rule_id}-${i}`}
            className={`flex items-start gap-2 rounded-md border ${s.border} ${s.bg} px-3 py-2 text-xs ${s.text}`}
          >
            <span className="mt-0.5 shrink-0">{s.icon}</span>
            <div className="flex-1 min-w-0">
              <span className="font-semibold">[{v.rule_id}]</span>{" "}
              <span>{v.message}</span>
              <span className="ml-1 opacity-60">— 필수 항목 누락</span>
            </div>
            <span className={`shrink-0 text-[10px] px-1.5 py-0.5 rounded border font-medium ${s.badge}`}>
              {isConfirmed ? "확정" : "후보"}
            </span>
          </div>
        );
      })}
      {violations.length > 3 && (
        <button
          type="button"
          onClick={() => setExpanded((e) => !e)}
          className="w-full text-[11px] text-gray-500 hover:text-gray-700 py-1 border border-gray-200 rounded bg-gray-50 hover:bg-gray-100 transition-colors"
        >
          {expanded ? "▲ 접기" : `▼ 나머지 ${violations.length - 3}건 더 보기`}
        </button>
      )}
    </div>
  );
}

/**
 * 텍스트에서 하이라이트 스펙에 맞는 위치를 찾아 세그먼트로 분리한다.
 * specs: Array<{ matched_text: string, rule_id: string, severity: string, isFocused: boolean }>
 * 반환: Array<{ text: string, highlighted: boolean, rule_id?: string, severity?: string, isFocused?: boolean }>
 */
function buildTextSegments(text, specs) {
  if (!text || !specs.length) return [{ text, highlighted: false }];

  const positions = [];
  for (const spec of specs) {
    if (!spec.matched_text) continue;
    let searchFrom = 0;
    let isFirstOfRule = true;
    while (searchFrom <= text.length) {
      const pos = text.indexOf(spec.matched_text, searchFrom);
      if (pos === -1) break;
      positions.push({
        start: pos,
        end: pos + spec.matched_text.length,
        rule_id: spec.rule_id,
        severity: spec.severity,
        isFocused: spec.isFocused,
        isFirstOfRule,
      });
      isFirstOfRule = false;
      searchFrom = pos + spec.matched_text.length;
    }
  }

  if (!positions.length) return [{ text, highlighted: false }];

  // 시작 위치 기준 정렬
  positions.sort((a, b) => a.start - b.start || a.end - b.end);

  // 겹치는 구간 병합
  const merged = [];
  for (const pos of positions) {
    if (!merged.length || pos.start >= merged[merged.length - 1].end) {
      merged.push({ ...pos });
    } else {
      const last = merged[merged.length - 1];
      if (pos.end > last.end) last.end = pos.end;
      if (pos.isFocused) last.isFocused = true;
    }
  }

  const segments = [];
  let cursor = 0;
  for (const m of merged) {
    if (m.start > cursor) {
      segments.push({ text: text.slice(cursor, m.start), highlighted: false });
    }
    segments.push({
      text: text.slice(m.start, m.end),
      highlighted: true,
      rule_id: m.rule_id,
      severity: m.severity,
      isFocused: m.isFocused,
      isFirstOfRule: m.isFirstOfRule,
    });
    cursor = m.end;
  }
  if (cursor < text.length) {
    segments.push({ text: text.slice(cursor), highlighted: false });
  }
  return segments;
}

/**
 * 마크다운 렌더링된 children 트리를 재귀적으로 순회하며 텍스트 노드에 하이라이트를 적용한다.
 */
function HighlightChildren({ children, highlightSpecs, focusedDocViolation }) {
  if (!highlightSpecs || !highlightSpecs.length) return <>{children}</>;

  function processChild(child, key) {
    if (typeof child === "string") {
      const segments = buildTextSegments(child, highlightSpecs);
      if (!segments.some((s) => s.highlighted)) return child;
      return segments.map((seg, i) => {
        if (!seg.highlighted) return <span key={`${key}-${i}`}>{seg.text}</span>;
        const isFocused =
          focusedDocViolation &&
          focusedDocViolation.rule_id === seg.rule_id &&
          seg.isFirstOfRule;
        const markClass = isFocused
          ? "bg-red-300 text-red-900 rounded px-0.5 outline outline-2 outline-red-500"
          : (seg.severity || "").toLowerCase() === "high"
          ? "bg-red-200 text-red-900 rounded px-0.5"
          : "bg-yellow-200 text-yellow-900 rounded px-0.5";
        return (
          <mark
            key={`${key}-${i}`}
            className={markClass}
            data-rule-id={seg.rule_id}
            {...(isFocused ? { "data-focused-violation": "true" } : {})}
          >
            {seg.text}
          </mark>
        );
      });
    }
    if (isValidElement(child)) {
      const childChildren = child.props.children;
      if (childChildren == null) return child;
      const processed = Array.isArray(childChildren)
        ? childChildren.map((c, i) => processChild(c, `${key}-${i}`))
        : processChild(childChildren, `${key}-0`);
      return cloneElement(child, { key, children: processed });
    }
    return child;
  }

  if (Array.isArray(children)) {
    return <>{children.map((child, i) => processChild(child, i))}</>;
  }
  return <>{processChild(children, 0)}</>;
}

/**
 * DocViewer: 중앙 문서 뷰어.
 * - 선택된 문서(docType + selectedDocPath)에 대한 전처리 텍스트를 보여준다.
 * - DOC 위반 위치를 빨간/노란 마크로 하이라이트하고, 클릭된 위반으로 스크롤한다.
 */
export default function DocViewer({ docType }) {
  const docSections = useAnalysisStore((s) => s.docSections || []);
  const selectedDocPath = useAnalysisStore((s) => s.selectedDocPath);
  const setSelectedDocPath = useAnalysisStore((s) => s.setSelectedDocPath);
  const report = useAnalysisStore((s) => s.report);
  const docViolationsByDocType = useAnalysisStore((s) => s.docViolationsByDocType || {});
  const focusedDocViolation = useAnalysisStore((s) => s.focusedDocViolation);

  const articleRef = useRef(null);

  const docsByType = report?.docs || {};
  const fileList = docType && Array.isArray(docsByType[docType]) ? docsByType[docType] : [];

  // 문서가 있는데 아무 것도 선택되어 있지 않으면 첫 번째 문서 자동 선택
  useEffect(() => {
    if (!docType) return;
    if (selectedDocPath) return;
    if (!fileList.length) return;
    setSelectedDocPath(fileList[0]);
  }, [docType, fileList, selectedDocPath, setSelectedDocPath]);

  const section = useMemo(() => {
    if (!selectedDocPath) return null;
    return (
      docSections.find((s) => s.file === selectedDocPath) ||
      docSections.find((s) => (s.file || "").startsWith(selectedDocPath + "#")) ||
      null
    );
  }, [docSections, selectedDocPath]);

  const displayTitle = section?.title || selectedDocPath || "문서를 선택해 주세요.";
  const rawText = section?.text;
  const tables = Array.isArray(section?.tables) ? section.tables : [];
  const markdownContent = section?.markdown_content || null;
  // markdown_content가 있으면 마크다운 렌더링 모드 사용
  const [useMarkdownMode, setUseMarkdownMode] = useState(true);

  const baseDocPath = useMemo(() => {
    if (!selectedDocPath) return null;
    return selectedDocPath.split("#")[0];
  }, [selectedDocPath]);

  // 표 셀과 완전히 동일한 라인만 제거 (본문 보존)
  const text = useMemo(() => {
    if (!rawText) return rawText;
    if (!tables.length) return rawText;
    const exactCells = new Set();

    const normalize = (s) =>
      typeof s === "string" ? s.replace(/\s+/g, " ").trim() : "";

    const addCell = (rawValue) => {
      const t = normalize(rawValue);
      if (!t) return;
      exactCells.add(t);
      const raw = typeof rawValue === "string" ? rawValue : "";
      if (raw.includes("\n")) {
        raw.split(/\r?\n/).forEach((line) => {
          const u = normalize(line);
          if (u) exactCells.add(u);
        });
      }
    };

    for (const tbl of tables) {
      (tbl.headers || []).forEach((h) => addCell(h));
      (tbl.rows || []).forEach((row) => {
        (row || []).forEach((c) => addCell(c));
      });
    }

    const lines = rawText.split(/\r?\n/);
    const filtered = lines.filter((line) => {
      const trimmed = line.trim();
      if (!trimmed) return true;
      const normLine = trimmed.replace(/\s+/g, " ");
      if (exactCells.has(normLine)) return false;
      return true;
    });

    return filtered.join("\n");
  }, [rawText, tables]);

  // 현재 doc_type에 해당하는 DOC 위반 목록
  const docTypeViolations = useMemo(() => {
    if (!docType) return [];
    const direct = docViolationsByDocType[docType] || [];
    // config_mgmt → scm 탭에서도 표시
    if (docType === "scm") {
      return [...direct, ...(docViolationsByDocType["config_mgmt"] || [])];
    }
    return direct;
  }, [docType, docViolationsByDocType]);

  // 하이라이트 스펙 생성 (matched_text가 있는 regex 위반만 하이라이트)
  const highlightSpecs = useMemo(() => {
    if (!docTypeViolations.length) return [];
    const specs = [];
    for (const v of docTypeViolations) {
      const ranges = Array.isArray(v.ranges) ? v.ranges : [];
      const isFocused =
        focusedDocViolation && focusedDocViolation.rule_id === v.rule_id;
      for (const r of ranges) {
        if (r.matched_text) {
          specs.push({
            matched_text: r.matched_text,
            rule_id: v.rule_id,
            severity: v.severity || "medium",
            isFocused: !!isFocused,
          });
        }
      }
    }
    return specs;
  }, [docTypeViolations, focusedDocViolation]);

  const textSegments = useMemo(
    () => buildTextSegments(text || "", highlightSpecs),
    [text, highlightSpecs]
  );

  // 포커스된 위반이 바뀌면 해당 마크로 스크롤
  useEffect(() => {
    if (!focusedDocViolation || !articleRef.current) return;
    const ruleId = focusedDocViolation.rule_id;
    const focused = articleRef.current.querySelector("[data-focused-violation='true']");
    const firstMatch = articleRef.current.querySelector(
      `[data-rule-id="${CSS.escape(ruleId)}"]`
    );
    const target = focused || firstMatch;
    if (target) {
      target.scrollIntoView({ behavior: "smooth", block: "center" });
    }
  }, [focusedDocViolation]);

  const docTypeLabel =
    docType === "design"
      ? "설계서"
      : docType === "scm"
      ? "형상관리 문서"
      : docType === "test"
      ? "시험서"
      : "문서";

  // 누락 패턴(missing) 위반 배너 목록 (ranges가 비어있는 것)
  const missingViolations = useMemo(
    () => docTypeViolations.filter((v) => !v.ranges || v.ranges.length === 0),
    [docTypeViolations]
  );

  const hasHighlights = textSegments.some((s) => s.highlighted);

  return (
    <div className="p-4 bg-gray-50 min-h-full flex flex-col">
      <div className="flex items-center justify-between gap-2 flex-wrap text-xs sm:text-sm text-gray-600 mb-2">
        <div className="flex flex-col gap-0.5">
          <span className="font-semibold text-[#0F2854]">
            {docTypeLabel} 뷰어
          </span>
          {selectedDocPath ? (
            <span className="text-gray-500 break-all text-[11px] sm:text-xs">
              {selectedDocPath}
            </span>
          ) : (
            <span className="text-gray-400 text-[11px] sm:text-xs">
              좌측 트리에서 문서를 선택하면 이 영역에 내용이 표시됩니다.
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          {markdownContent && (
            <button
              type="button"
              onClick={() => setUseMarkdownMode((v) => !v)}
              className={`text-[11px] px-2 py-0.5 rounded border transition-colors ${
                useMarkdownMode
                  ? "bg-blue-50 border-blue-200 text-blue-700 hover:bg-blue-100"
                  : "bg-gray-50 border-gray-200 text-gray-600 hover:bg-gray-100"
              }`}
              title="표·이미지 가독성 향상 모드 전환"
            >
              {useMarkdownMode ? "📄 마크다운 모드" : "📝 원문 모드"}
            </button>
          )}
          {docTypeViolations.length > 0 && (
            <div className="flex items-center gap-1 text-[11px] px-2 py-0.5 rounded-full bg-red-50 border border-red-200 text-red-700">
              <span className="inline-block w-1.5 h-1.5 rounded-full bg-red-500" />
              위반 {docTypeViolations.length}건
            </div>
          )}
        </div>
      </div>

      {/* 누락 패턴 위반 배너 */}
      {missingViolations.length > 0 && (
        <MissingViolationBanners violations={missingViolations} />
      )}

      <div className="flex-1 overflow-auto border border-gray-200 rounded bg-white">
        {!selectedDocPath ? (
          <div className="p-4 text-gray-400 text-sm">
            좌측에서 문서를 선택해 주세요.
          </div>
        ) : !section ? (
          <div className="p-4 text-gray-400 text-sm">
            전처리 결과에서 이 문서에 대한 정보를 찾을 수 없습니다.
          </div>
        ) : !text && tables.length === 0 && !markdownContent ? (
          <div className="p-4 text-gray-500 text-sm">
            이 PDF에서 텍스트를 추출하지 못했습니다. 스캔본(이미지 기반)일 수 있습니다.
            텍스트 기반 PDF로 다시 업로드하는 것을 권장합니다.
          </div>
        ) : (
          <article ref={articleRef} className="p-4 text-xs sm:text-sm leading-relaxed text-gray-800">
            <h2 className="text-sm sm:text-base font-semibold text-[#0F2854] mb-3">
              {displayTitle}
            </h2>

            {/* ── 마크다운 모드 (표·이미지 가독성 향상) ── */}
            {markdownContent && useMarkdownMode ? (
              <div className="prose prose-sm max-w-none doc-markdown">
                <ReactMarkdown
                  remarkPlugins={[remarkGfm]}
                  components={{
                    table: ({ node, ...props }) => (
                      <div className="overflow-x-auto my-3 border border-gray-200 rounded">
                        <table className="min-w-full border-collapse text-[11px] sm:text-xs" {...props} />
                      </div>
                    ),
                    thead: ({ node, ...props }) => (
                      <thead className="bg-gray-50" {...props} />
                    ),
                    th: ({ node, children, ...props }) => (
                      <th className="border border-gray-200 px-2 py-1 text-left font-medium text-gray-700 whitespace-nowrap" {...props}>
                        <HighlightChildren highlightSpecs={highlightSpecs} focusedDocViolation={focusedDocViolation}>
                          {children}
                        </HighlightChildren>
                      </th>
                    ),
                    td: ({ node, children, ...props }) => (
                      <td className="border border-gray-100 px-2 py-1 text-gray-800 whitespace-pre-wrap" {...props}>
                        <HighlightChildren highlightSpecs={highlightSpecs} focusedDocViolation={focusedDocViolation}>
                          {children}
                        </HighlightChildren>
                      </td>
                    ),
                    tr: ({ node, ...props }) => (
                      <tr className="odd:bg-white even:bg-gray-50" {...props} />
                    ),
                    blockquote: ({ node, ...props }) => (
                      <blockquote className="border-l-4 border-blue-200 bg-blue-50 px-3 py-2 my-2 text-blue-900 text-xs rounded-r" {...props} />
                    ),
                    h1: ({ node, ...props }) => (
                      <h1 className="text-base font-bold text-[#0F2854] mt-4 mb-1 border-b border-gray-200 pb-1" {...props} />
                    ),
                    h2: ({ node, ...props }) => (
                      <h2 className="text-sm font-semibold text-[#0F2854] mt-3 mb-1" {...props} />
                    ),
                    h3: ({ node, ...props }) => (
                      <h3 className="text-xs font-semibold text-gray-700 mt-2 mb-1" {...props} />
                    ),
                    p: ({ node, children, ...props }) => (
                      <p className="mb-2 leading-relaxed" {...props}>
                        <HighlightChildren highlightSpecs={highlightSpecs} focusedDocViolation={focusedDocViolation}>
                          {children}
                        </HighlightChildren>
                      </p>
                    ),
                    code: ({ node, inline, ...props }) =>
                      inline ? (
                        <code className="bg-gray-100 px-1 rounded font-mono text-[11px]" {...props} />
                      ) : (
                        <pre className="bg-gray-100 p-2 rounded overflow-x-auto text-[11px] font-mono my-2">
                          <code {...props} />
                        </pre>
                      ),
                  }}
                >
                  {markdownContent}
                </ReactMarkdown>
              </div>
            ) : (
              /* ── 원문 모드 (violation 인라인 하이라이트 포함) ── */
              <>
                {text && (
                  <p className="whitespace-pre-wrap mb-4">
                    {hasHighlights
                      ? textSegments.map((seg, i) => {
                          if (!seg.highlighted) return <span key={i}>{seg.text}</span>;
                          const isFocused =
                            focusedDocViolation &&
                            focusedDocViolation.rule_id === seg.rule_id &&
                            seg.isFirstOfRule;
                          const markClass =
                            isFocused
                              ? "bg-red-300 text-red-900 rounded px-0.5 outline outline-2 outline-red-500"
                              : (seg.severity || "").toLowerCase() === "high"
                              ? "bg-red-200 text-red-900 rounded px-0.5"
                              : "bg-yellow-200 text-yellow-900 rounded px-0.5";
                          return (
                            <mark
                              key={i}
                              className={markClass}
                              data-rule-id={seg.rule_id}
                              {...(isFocused ? { "data-focused-violation": "true" } : {})}
                            >
                              {seg.text}
                            </mark>
                          );
                        })
                      : text}
                  </p>
                )}
                {tables.length > 0 && (
                  <div className="space-y-4">
                    {tables.map((tbl, idx) => (
                      <div key={tbl.name || idx}>
                        <p className="text-[11px] sm:text-xs text-gray-500 mb-1">
                          표 {idx + 1}
                          {tbl.page ? ` (페이지 ${tbl.page})` : ""}
                        </p>
                        <div className="overflow-x-auto border border-gray-200 rounded bg-white">
                          <table className="min-w-full border-collapse text-[11px] sm:text-xs">
                            {Array.isArray(tbl.headers) && tbl.headers.length > 0 && (
                              <thead>
                                <tr className="bg-gray-50">
                                  {tbl.headers.map((h, i) => (
                                    <th
                                      key={i}
                                      className="border-b border-gray-200 px-2 py-1 text-left font-medium text-gray-700"
                                    >
                                      {h || "\u00A0"}
                                    </th>
                                  ))}
                                </tr>
                              </thead>
                            )}
                            <tbody>
                              {Array.isArray(tbl.rows) &&
                                tbl.rows.map((row, rIdx) => (
                                  <tr key={rIdx} className="odd:bg-white even:bg-gray-50">
                                    {row.map((cell, cIdx) => (
                                      <td
                                        key={cIdx}
                                        className="border-t border-gray-100 px-2 py-1 text-gray-800 whitespace-pre-wrap"
                                      >
                                        {cell || "\u00A0"}
                                      </td>
                                    ))}
                                  </tr>
                                ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </>
            )}
          </article>
        )}
      </div>
    </div>
  );
}
