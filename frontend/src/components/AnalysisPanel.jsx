import { useMemo, useState, useCallback } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { useAnalysisStore } from "../stores/analysisStore";

const TABS = ["summary", "violations", "patches"];

/**
 * AnalysisPanel: 우측 분석 결과 패널.
 * - 요약: 위반 개수, 심각도별 카운트
 * - 위반 목록: 파일/라인/메시지 리스트 (DOC 위반 포함)
 * - 패치: 패치 파일 목록
 */
export default function AnalysisPanel() {
  const [activeTab, setActiveTab] = useState("summary");
  const {
    status,
    report,
    patches,
    activeArtifactTab,
    countsByTab,
    severityByTab,
    setSelectedFilePath,
    setFocusedLine,
    setActiveArtifactTab,
    setFocusedDocViolation,
    setFocusedPatch,
    violationsByFile,
  } = useAnalysisStore((s) => ({
    status: s.status,
    report: s.report,
    patches: s.patches,
    activeArtifactTab: s.activeArtifactTab,
    countsByTab: s.countsByTab,
    severityByTab: s.severityByTab,
    setSelectedFilePath: s.setSelectedFilePath,
    setFocusedLine: s.setFocusedLine,
    setActiveArtifactTab: s.setActiveArtifactTab,
    setFocusedDocViolation: s.setFocusedDocViolation,
    setFocusedPatch: s.setFocusedPatch,
    violationsByFile: s.violationsByFile || {},
  }));

  const summary = report?.summary;
  const allViolations = report?.violations || [];

  const violations = useMemo(() => {
    if (!allViolations.length) return [];
    if (activeArtifactTab === "report") return allViolations;
    return allViolations.filter((v) => {
      const id = (v.rule_id || "").toUpperCase();
      const rawDocType = v.doc_type || "";
      const docType = String(rawDocType).toLowerCase().trim();
      const isDocViolation = id.startsWith("DOC-") || !!v.doc_type;
      const isTrcViolation = id.startsWith("TRC-") || !!v.trc_type;

      if (activeArtifactTab === "code") {
        // 코드 탭: 코드 위반 + 파일이 있는 TRC 위반 표시
        if (isDocViolation) return false;
        if (isTrcViolation) return !!(v.file || v.file_path);
        return true;
      }
      if (activeArtifactTab === "design") {
        return (
          (isDocViolation && (docType === "design" || docType === "")) ||
          id.startsWith("DOC-0")
        );
      }
      if (activeArtifactTab === "scm") {
        return (
          (isDocViolation &&
            (docType === "scm" || docType === "config_mgmt" || docType === "cm")) ||
          id.startsWith("DOC-2")
        );
      }
      if (activeArtifactTab === "test") {
        return (isDocViolation && docType === "test") || id.startsWith("DOC-1");
      }
      return true;
    });
  }, [allViolations, activeArtifactTab]);

  const tabButtonClass = (tab) =>
    [
      "px-2 py-1 text-sm border-b-2 transition-colors",
      activeTab === tab
        ? "border-[#0b49b5] text-[#0b49b5] font-semibold"
        : "border-transparent text-gray-500 hover:text-gray-700",
    ].join(" ");

  const statusLabel = useMemo(() => {
    if (status === "pending" || status === "running") return "분석 중...";
    if (status === "completed") return "분석 완료";
    if (status === "failed") return "분석 실패";
    return "대기 중";
  }, [status]);

  const handleSelectViolation = (violation) => {
    if (!violation) return;
    const ruleId = (violation.rule_id || "").toUpperCase();
    const isDocViolation = ruleId.startsWith("DOC-") || !!violation.doc_type;
    const isTrcViolation = ruleId.startsWith("TRC-") || !!violation.trc_type;

    if (isDocViolation) {
      const docType = violation.doc_type || "design";
      const tabTarget = docType === "config_mgmt" ? "scm" : docType;
      setActiveArtifactTab(tabTarget);
      setFocusedDocViolation(violation);
      return;
    }

    if (isTrcViolation) {
      // TRC 위반: 파일 있으면 코드 탭으로, 없으면 보고서 탭으로
      const path = violation.file || violation.file_path;
      if (path) {
        setActiveArtifactTab("code");
        setSelectedFilePath(path);
        const hasLine = typeof violation.line === "number" && violation.line > 0;
        setFocusedLine(hasLine ? violation.line : null);
      } else {
        setActiveArtifactTab("report");
      }
      return;
    }

    // 코드 위반: 파일/라인 포커스
    const path = violation.file || violation.file_path;
    if (!path) return;
    setSelectedFilePath(path);
    const hasLine = typeof violation.line === "number" && violation.line > 0;
    setFocusedLine(hasLine ? violation.line : null);
  };

  return (
    <div className="p-4 h-full flex flex-col">
      <div className="flex items-center justify-between border-b border-gray-200 pb-2 mb-2">
        <div className="flex gap-2">
          <button
            type="button"
            className={tabButtonClass("summary")}
            onClick={() => setActiveTab("summary")}
          >
            요약
          </button>
          <button
            type="button"
            className={tabButtonClass("violations")}
            onClick={() => setActiveTab("violations")}
          >
            위반 목록
          </button>
          <button
            type="button"
            className={tabButtonClass("patches")}
            onClick={() => setActiveTab("patches")}
          >
            패치
          </button>
        </div>
        <span className="text-xs text-gray-500">{statusLabel}</span>
      </div>

      <div className="flex-1 overflow-auto text-sm text-gray-700">
        {activeTab === "summary" && (
          <SummaryTab
            summary={summary}
            violations={violations}
            activeArtifactTab={activeArtifactTab}
            countsByTab={countsByTab}
            allViolations={allViolations}
          />
        )}
        {activeTab === "violations" && (
          <ViolationsTab violations={violations} onSelectViolation={handleSelectViolation} />
        )}
        {activeTab === "patches" && (
          <PatchesTab
            patches={patches}
            allViolations={allViolations}
            violationsByFile={violationsByFile}
            activeArtifactTab={activeArtifactTab}
            onSelectPatch={(patch) => {
              setFocusedPatch(patch);
              if (patch?.isDocPatch) {
                // DOC 패치: 해당 문서 탭으로 이동
                const docTab =
                  patch.docType === "scm" || patch.docType === "config_mgmt"
                    ? "scm"
                    : patch.docType === "test"
                    ? "test"
                    : "design";
                setActiveArtifactTab(docTab);
                // 해당 rule_id와 일치하는 DOC 위반 포커스
                const matched = (allViolations || []).find(
                  (v) => v.rule_id === patch.ruleId
                );
                if (matched) setFocusedDocViolation(matched);
              } else if (patch?.filePath) {
                setSelectedFilePath(patch.filePath);
                setFocusedLine(patch.line || null);
                setActiveArtifactTab("code");
              }
            }}
          />
        )}
      </div>
    </div>
  );
}

function getConfidence(v) {
  if (v.confidence) return v.confidence;
  if (v.l2_confirmed) return "확정";
  if (v.needs_ai_review) return "후보";
  return "확정";
}

function SummaryTab({ summary, violations, activeArtifactTab, countsByTab, allViolations }) {
  if (!summary) {
    return <p className="text-gray-500">아직 분석 결과가 없습니다. ZIP 파일을 업로드해 보세요.</p>;
  }
  const counts = countsByTab || {};

  // confidence 집계 (현재 탭 위반 기준, TRC 후보 제외)
  const nonTrcViolations = violations.filter(
    (v) => !((v.rule_id || "").toUpperCase().startsWith("TRC-") || v.trc_type)
  );
  const confirmed = nonTrcViolations.filter((v) => getConfidence(v) === "확정").length;
  const candidate = nonTrcViolations.length - confirmed;

  const currentTabKey =
    activeArtifactTab === "code"    ? "code"
    : activeArtifactTab === "design" ? "design"
    : activeArtifactTab === "scm"    ? "scm"
    : activeArtifactTab === "test"   ? "test"
    : "report";

  const currentLabel =
    currentTabKey === "code"     ? "코드 위반"
    : currentTabKey === "design" ? "설계서 위반"
    : currentTabKey === "scm"    ? "형상관리 위반"
    : currentTabKey === "test"   ? "시험서 위반"
    : "전체 위반";

  // 종합 판정 (TRC 후보 제외하여 판정)
  const verdict =
    confirmed > 0 ? { text: "❌ 불합격", cls: "bg-red-50 border-red-200 text-red-700" }
    : candidate > 0 ? { text: "⚠️ 검토 필요", cls: "bg-amber-50 border-amber-200 text-amber-700" }
    : { text: "✅ 통과", cls: "bg-green-50 border-green-200 text-green-700" };

  // TRC 요약 (종합 탭용)
  const trcViolations = (allViolations || []).filter(
    (v) => (v.rule_id || "").toUpperCase().startsWith("TRC-") || v.trc_type
  );
  const trcByType = {
    interface_match: trcViolations.filter((v) => v.trc_type === "interface_match"),
    error_code_match: trcViolations.filter((v) => v.trc_type === "error_code_match"),
    test_coverage: trcViolations.filter((v) => v.trc_type === "test_coverage"),
  };

  return (
    <div className="space-y-3">
      {/* 판정 배너 */}
      <div className={`rounded-md border px-3 py-2 text-sm font-semibold ${verdict.cls}`}>
        {verdict.text}
      </div>

      {/* 위반 건수 (TRC 제외) */}
      <div>
        <p className="text-[11px] text-gray-500 mb-0.5">{currentLabel} (추적성 제외)</p>
        <p className="text-2xl font-semibold text-[#0F2854]">{nonTrcViolations.length}</p>
      </div>

      {/* 확정 / 후보 카드 */}
      <div className="grid grid-cols-2 gap-2 text-xs">
        <div className="rounded-md bg-red-50 border border-red-200 px-3 py-2">
          <p className="text-[11px] text-red-600 mb-1">확정 위반</p>
          <p className="text-base font-semibold text-red-700">{confirmed}</p>
        </div>
        <div className="rounded-md bg-amber-50 border border-amber-200 px-3 py-2">
          <p className="text-[11px] text-amber-600 mb-1">위반 후보</p>
          <p className="text-base font-semibold text-amber-600">{candidate}</p>
        </div>
      </div>

      {/* 탭별 분류 (보고서/전체 탭에서만 표시) */}
      {(activeArtifactTab === "report") && (
        <div className="grid grid-cols-2 gap-2 text-xs">
          {[
            { key: "code",   label: "코드" },
            { key: "design", label: "설계서" },
            { key: "scm",    label: "형상관리" },
            { key: "test",   label: "시험서" },
          ].map(({ key, label }) => (
            <div key={key} className="rounded-md bg-gray-50 border border-gray-200 px-3 py-2">
              <p className="text-[11px] text-gray-500 mb-1">{label}</p>
              <p className="text-base font-semibold text-gray-800">{counts[key] ?? 0}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

const isTrc = (v) => (v.rule_id || "").toUpperCase().startsWith("TRC-") || !!v.trc_type;

/** severity 정렬 순서 */
const SEV_ORDER = { high: 0, medium: 1, med: 1, low: 2 };
function sevRank(v) { return SEV_ORDER[(v.severity || "medium").toLowerCase()] ?? 1; }

/** 위반이 라인 위치를 가지는지 판별 */
function hasLineLocation(v) {
  const ruleId = (v.rule_id || "").toUpperCase();
  const isDoc = ruleId.startsWith("DOC-") || !!v.doc_type;
  if (isDoc) return Array.isArray(v.ranges) && v.ranges.length > 0;
  return typeof v.line === "number" && v.line > 0;
}

/** 위치 라벨 생성 (개선됨) */
function getLocationLabel(v) {
  const ruleId = (v.rule_id || "").toUpperCase();
  const isDocViolation = ruleId.startsWith("DOC-") || !!v.doc_type;
  const isTrcViolation = ruleId.startsWith("TRC-") || !!v.trc_type;

  if (isDocViolation) {
    const dtMap = { design: "설계서", scm: "형상관리", config_mgmt: "형상관리", cm: "형상관리", test: "시험서" };
    const rangeCount = Array.isArray(v.ranges) ? v.ranges.length : 0;
    const dtKey = String(v.doc_type || "").toLowerCase().trim();
    const dt = dtMap[dtKey] || "문서";
    return rangeCount > 0
      ? { text: `${dt} · ${rangeCount}곳`, badge: null }
      : { text: dt, badge: "섹션 누락" };
  }

  if (isTrcViolation) {
    const trcTypeMap = { interface_match: "인터페이스", error_code_match: "오류코드", test_coverage: "시험커버리지" };
    const trcLabel = trcTypeMap[v.trc_type] || "추적성";
    const path = v.file || v.file_path;
    return { text: path ? `${trcLabel} · ${path.split("/").pop()}` : `${trcLabel}`, badge: path ? null : "전체" };
  }

  const path = v.file || v.file_path;
  const hasLine = typeof v.line === "number" && v.line > 0;
  const hasEndLine = typeof v.endLine === "number" && hasLine && v.endLine > v.line;
  const pt = v.pattern_type || "";

  if (hasLine) {
    const lineLabel = hasEndLine ? `${v.line}~${v.endLine}` : String(v.line);
    return { text: path ? `${path.split("/").pop()}:${lineLabel}` : `줄 ${lineLabel}`, badge: null };
  }

  // 위치 없는 위반
  const fileName = path ? path.split("/").pop() : null;
  if (pt === "missing") {
    return { text: fileName || "프로젝트 전체", badge: "코드 누락" };
  }
  return { text: fileName || "프로젝트 전체", badge: "파일 전체" };
}

/** severity 배지 렌더 */
function SeverityBadge({ severity }) {
  const sev = (severity || "medium").toLowerCase();
  if (sev === "high") return <span className="inline-block px-1 py-px rounded text-[9px] font-bold bg-red-600 text-white shrink-0">HIGH</span>;
  if (sev === "low") return <span className="inline-block px-1 py-px rounded text-[9px] font-bold bg-gray-200 text-gray-600 border border-gray-300 shrink-0">LOW</span>;
  return <span className="inline-block px-1 py-px rounded text-[9px] font-bold bg-amber-400 text-white shrink-0">MED</span>;
}

/** confidence 배지 렌더 */
function ConfidenceBadge({ v }) {
  const conf = getConfidence(v);
  const isTrcViolation = isTrc(v);
  if (isTrcViolation) return <span className="inline-block px-1 py-px rounded text-[9px] font-bold bg-purple-100 text-purple-700 border border-purple-200 shrink-0">추적성</span>;
  if (conf === "확정") {
    return (
      <span className="inline-flex items-center gap-0.5 px-1 py-px rounded text-[9px] font-bold bg-red-200 text-red-800 shrink-0"
            title={v.confidence_score != null ? `확신도: ${v.confidence_score}%` : undefined}>
        확정{v.confidence_score != null && <span className="font-normal opacity-70"> {v.confidence_score}%</span>}
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-0.5 px-1 py-px rounded text-[9px] font-bold bg-amber-100 text-amber-700 border border-amber-200 shrink-0"
          title={v.confidence_score != null ? `확신도: ${v.confidence_score}%` : undefined}>
      후보{v.confidence_score != null && <span className="font-normal opacity-70"> {v.confidence_score}%</span>}
    </span>
  );
}

/** 위반 카드 한 개 렌더 */
function ViolationCard({ v, idx, onSelectViolation, isFileLevelGroup }) {
  const key = `${v.rule_id || "rule"}-${idx}`;
  const isTrcViolation = isTrc(v);
  const loc = getLocationLabel(v);

  const sev = (v.severity || "medium").toLowerCase();
  const borderColor = isTrcViolation
    ? "border-l-purple-400"
    : sev === "high" ? "border-l-red-500" : sev === "low" ? "border-l-gray-300" : "border-l-amber-400";

  return (
    <li
      key={key}
      className={`border border-gray-200 rounded-md bg-white hover:bg-gray-50 cursor-pointer transition-colors border-l-4 ${borderColor}`}
      onClick={() => onSelectViolation && onSelectViolation(v)}
    >
      <div className="px-3 py-2">
        <div className="flex items-center gap-1.5 mb-1">
          {!isTrcViolation && <SeverityBadge severity={v.severity} />}
          <ConfidenceBadge v={v} />
          <span className="text-xs font-semibold text-[#0F2854] shrink-0">{v.rule_id || "규칙 미지정"}</span>
          <span className="text-[11px] text-gray-400 truncate ml-auto text-right flex items-center gap-1">
            {loc.text}
            {loc.badge && (
              <span className="inline-block px-1 py-px rounded text-[9px] bg-gray-100 text-gray-500 border border-gray-200 font-medium shrink-0">
                {loc.badge}
              </span>
            )}
          </span>
        </div>
        <p className={`text-[11px] text-gray-600 leading-tight ${isFileLevelGroup ? "line-clamp-3" : "line-clamp-2"}`}>
          {v.message || "(메시지 없음)"}
        </p>
        {/* 파일 전체 위반에서 파일 경로 표시 */}
        {isFileLevelGroup && (v.file || v.file_path) && (
          <p className="text-[10px] text-blue-500 mt-1">
            {v.file || v.file_path}
          </p>
        )}
      </div>
    </li>
  );
}

function ViolationsTab({ violations, onSelectViolation }) {
  const [confidenceFilter, setConfidenceFilter] = useState("all"); // "all" | "확정" | "후보"
  const [showTrc, setShowTrc] = useState(false); // TRC 위반 기본 숨김

  const trcCount = useMemo(() => violations.filter(isTrc).length, [violations]);
  const nonTrcViolations = useMemo(() => violations.filter((v) => !isTrc(v)), [violations]);

  const filtered = useMemo(() => {
    const base = showTrc ? violations : nonTrcViolations;
    if (confidenceFilter === "all") return base;
    return base.filter((v) => getConfidence(v) === confidenceFilter);
  }, [violations, nonTrcViolations, confidenceFilter, showTrc]);

  // 그룹 분리 + severity 정렬
  const { lineViolations: lineGroup, fileLevelViolations: fileLevelGroup } = useMemo(() => {
    const line = filtered.filter(hasLineLocation).sort((a, b) => sevRank(a) - sevRank(b));
    const fileLevel = filtered.filter((v) => !hasLineLocation(v)).sort((a, b) => sevRank(a) - sevRank(b));
    return { lineViolations: line, fileLevelViolations: fileLevel };
  }, [filtered]);

  if (!violations.length) {
    return <p className="text-gray-500">표시할 위반이 없습니다.</p>;
  }

  const filterBtnClass = (val) => [
    "px-2 py-0.5 rounded-full text-[11px] border transition-colors",
    confidenceFilter === val
      ? val === "확정"
        ? "bg-red-100 border-red-300 text-red-700 font-semibold"
        : val === "후보"
        ? "bg-amber-50 border-amber-300 text-amber-700 font-semibold"
        : "bg-[#0b49b5] border-[#0b49b5] text-white font-semibold"
      : "bg-white border-gray-200 text-gray-500 hover:border-gray-300",
  ].join(" ");

  const baseForCount = showTrc ? violations : nonTrcViolations;

  return (
    <div className="flex flex-col gap-2">
      {/* 필터 버튼 */}
      <div className="flex gap-1.5 flex-wrap">
        <button className={filterBtnClass("all")} onClick={() => setConfidenceFilter("all")}>
          전체 {baseForCount.length}
        </button>
        <button className={filterBtnClass("확정")} onClick={() => setConfidenceFilter("확정")}>
          확정 {baseForCount.filter((v) => getConfidence(v) === "확정").length}
        </button>
        <button className={filterBtnClass("후보")} onClick={() => setConfidenceFilter("후보")}>
          후보 {baseForCount.filter((v) => getConfidence(v) === "후보").length}
        </button>
        {/* TRC 토글 */}
        {trcCount > 0 && (
          <button
            className={[
              "px-2 py-0.5 rounded-full text-[11px] border transition-colors ml-auto",
              showTrc
                ? "bg-purple-100 border-purple-300 text-purple-700 font-medium"
                : "bg-white border-gray-200 text-gray-400 hover:border-gray-300",
            ].join(" ")}
            onClick={() => setShowTrc((v) => !v)}
            title="추적성(TRC) 위반 표시/숨김"
          >
            추적성 {showTrc ? "숨기기" : `${trcCount}건 표시`}
          </button>
        )}
      </div>

      {/* TRC 숨김 안내 */}
      {!showTrc && trcCount > 0 && (
        <p className="text-[10px] text-gray-400 px-1">
          추적성(TRC) 후보 {trcCount}건 숨겨짐 — 위 버튼으로 표시
        </p>
      )}

      {/* 라인 위반 그룹 */}
      {lineGroup.length > 0 && (
        <div>
          <div className="flex items-center gap-2 px-1 py-1.5">
            <span className="text-[10px] font-semibold text-gray-500 uppercase tracking-wide">라인 위반</span>
            <span className="text-[10px] text-gray-400">{lineGroup.length}건</span>
            <div className="flex-1 border-t border-gray-200" />
          </div>
          <ul className="space-y-1.5">
            {lineGroup.map((v, idx) => (
              <ViolationCard key={`line-${v.rule_id}-${idx}`} v={v} idx={idx} onSelectViolation={onSelectViolation} isFileLevelGroup={false} />
            ))}
          </ul>
        </div>
      )}

      {/* 파일/전체 수준 위반 그룹 */}
      {fileLevelGroup.length > 0 && (
        <div className={lineGroup.length > 0 ? "mt-2" : ""}>
          <div className="flex items-center gap-2 px-1 py-1.5">
            <span className="text-[10px] font-semibold text-gray-500 uppercase tracking-wide">파일/전체 수준 위반</span>
            <span className="text-[10px] text-gray-400">{fileLevelGroup.length}건</span>
            <div className="flex-1 border-t border-gray-200" />
          </div>
          <ul className="space-y-1.5">
            {fileLevelGroup.map((v, idx) => (
              <ViolationCard key={`file-${v.rule_id}-${idx}`} v={v} idx={idx} onSelectViolation={onSelectViolation} isFileLevelGroup={true} />
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

// DOC 패치: DOC-{rule_id}-doc_{doc_type}-{index}.md
// 코드 패치: {rule_id}-{safe_filename}-{line}.md
function parsePatchPath(patchPath) {
  const name = patchPath.replace(/\.md$/, "");

  // DOC 패치 형식 먼저 확인
  const docMatch = name.match(/^(DOC-\d+)-doc_(\w+)-(\d+)$/);
  if (docMatch) {
    return {
      ruleId: docMatch[1],
      docType: docMatch[2], // design | scm | config_mgmt | test
      isDocPatch: true,
      line: null,
      safeFile: null,
    };
  }

  // 코드 패치 형식
  const lastDash = name.lastIndexOf("-");
  if (lastDash === -1) return { ruleId: null, line: null, isDocPatch: false };
  const line = parseInt(name.slice(lastDash + 1), 10);
  const rest = name.slice(0, lastDash);
  const ruleMatch = rest.match(/^([A-Z]+-\d+)-(.+)$/);
  return {
    ruleId: ruleMatch ? ruleMatch[1] : null,
    safeFile: ruleMatch ? ruleMatch[2] : null,
    line: isNaN(line) ? null : line,
    isDocPatch: false,
    docType: null,
  };
}

const DOC_TYPE_LABEL = {
  design: "설계서",
  scm: "형상관리",
  config_mgmt: "형상관리",
  test: "시험서",
};

/** diff 코드 블록을 +/- 줄별로 색상 강조하여 렌더링 */
function DiffBlock({ code }) {
  if (!code) return null;
  const lines = code.split("\n");
  return (
    <div className="rounded bg-gray-900 text-[10px] font-mono overflow-auto max-h-48 p-2">
      {lines.map((line, i) => {
        const isAdded   = line.startsWith("+");
        const isRemoved = line.startsWith("-");
        return (
          <div
            key={i}
            className={
              isAdded   ? "text-green-400 bg-green-900/20"
              : isRemoved ? "text-red-400 bg-red-900/20"
              : "text-gray-300"
            }
          >
            {line || " "}
          </div>
        );
      })}
    </div>
  );
}

/** react-markdown 기반 패치 콘텐츠 렌더러 (마크다운 표/GFM 지원) */
function PatchContent({ content }) {
  if (!content) return null;

  return (
    <div className="patch-markdown text-[11px] text-gray-700 leading-relaxed">
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          // diff 코드블록은 DiffBlock으로 렌더, 나머지는 기본 pre
          code({ node, inline, className, children, ...props }) {
            const lang = (className || "").replace("language-", "");
            const codeStr = String(children).replace(/\n$/, "");
            if (inline) {
              return <code className="bg-gray-100 text-gray-800 px-1 rounded text-[10px] font-mono" {...props}>{children}</code>;
            }
            if (lang === "diff") {
              return <DiffBlock code={codeStr} />;
            }
            return (
              <pre className="rounded bg-gray-900 text-[10px] font-mono text-gray-200 p-2 overflow-auto max-h-48">
                <code>{codeStr}</code>
              </pre>
            );
          },
          pre({ children }) { return <>{children}</>; },
          // 테이블 스타일링
          table({ children }) {
            return (
              <div className="overflow-x-auto my-2">
                <table className="w-full text-[10px] border-collapse border border-gray-200 rounded">
                  {children}
                </table>
              </div>
            );
          },
          thead({ children }) { return <thead className="bg-gray-50 text-gray-600">{children}</thead>; },
          th({ children }) { return <th className="border border-gray-200 px-2 py-1 text-left font-medium">{children}</th>; },
          td({ children }) { return <td className="border border-gray-200 px-2 py-1">{children}</td>; },
          // 헤딩 스타일링
          h3({ children }) { return <p className="text-[11px] font-semibold text-gray-700 mb-1 mt-2">{children}</p>; },
          h2({ children }) { return <p className="text-[12px] font-bold text-gray-800 mb-1 mt-2">{children}</p>; },
          // 리스트 스타일링
          ul({ children }) { return <ul className="list-disc ml-4 space-y-0.5">{children}</ul>; },
          ol({ children }) { return <ol className="list-decimal ml-4 space-y-0.5">{children}</ol>; },
          li({ children }) { return <li className="text-[11px] text-gray-600">{children}</li>; },
          // 단락
          p({ children }) { return <p className="text-[11px] text-gray-600 mb-1 leading-relaxed">{children}</p>; },
        }}
      >
        {content}
      </ReactMarkdown>
    </div>
  );
}

function PatchesTab({ patches, allViolations, violationsByFile, activeArtifactTab, onSelectPatch }) {
  const [selectedPath, setSelectedPath] = useState(null);

  if (!patches || !patches.length) {
    return <p className="text-gray-500">등록된 패치가 없습니다.</p>;
  }

  // 현재 아티팩트 탭에 맞는 패치만 필터링
  const filtered = patches.filter((p) => {
    const { isDocPatch, docType } = parsePatchPath(p.path);
    if (activeArtifactTab === "report") return true;
    if (activeArtifactTab === "code") return !isDocPatch;
    if (activeArtifactTab === "design") return isDocPatch && (docType === "design" || !docType);
    if (activeArtifactTab === "scm") return isDocPatch && (docType === "scm" || docType === "config_mgmt");
    if (activeArtifactTab === "test") return isDocPatch && docType === "test";
    return true;
  });

  if (!filtered.length) {
    return <p className="text-gray-500">현재 탭에 해당하는 패치가 없습니다.</p>;
  }

  const handleClick = (p) => {
    const { ruleId, safeFile, line, isDocPatch, docType } = parsePatchPath(p.path);

    const newPath = selectedPath === p.path ? null : p.path;
    setSelectedPath(newPath);
    if (!newPath) return; // 토글 닫기

    if (isDocPatch) {
      const patchInfo = { path: p.path, content: p.content, ruleId, isDocPatch, docType };
      onSelectPatch && onSelectPatch(patchInfo);
      return;
    }

    // 코드 패치: allViolations에서 매칭되는 위반 찾기 (rule_id + line)
    let filePath = null;
    if (ruleId && line !== null) {
      const match = (allViolations || []).find(
        (v) => v.rule_id === ruleId && v.line === line
      );
      filePath = match?.file || match?.file_path || null;
    }
    // violationsByFile에서 safeFile로 근사 탐색
    if (!filePath && safeFile) {
      const safeNorm = safeFile.replace(/_/g, "/");
      filePath = Object.keys(violationsByFile || {}).find(
        (fp) => fp.endsWith(safeNorm) || fp.replace(/[/\\]/g, "_") === safeFile
      ) || null;
    }
    const patchInfo = { path: p.path, content: p.content, ruleId, line, filePath, isDocPatch: false };
    onSelectPatch && onSelectPatch(patchInfo);
  };

  return (
    <ul className="space-y-2">
      {filtered.map((p) => {
        const isSelected = selectedPath === p.path;
        const { ruleId, line, isDocPatch, docType } = parsePatchPath(p.path);
        const docLabel = DOC_TYPE_LABEL[docType] || "문서";

        return (
          <li
            key={p.path}
            className={[
              "border rounded-md text-xs cursor-pointer transition-colors",
              isSelected
                ? "border-[#0b49b5] bg-blue-50"
                : "border-gray-200 bg-white hover:bg-gray-50",
            ].join(" ")}
          >
            {/* 헤더 (항상 표시) */}
            <div
              className="px-3 py-2 flex items-center gap-2"
              onClick={() => handleClick(p)}
            >
              {isDocPatch && (
                <span className="inline-block px-1 py-px rounded text-[9px] font-bold bg-blue-100 text-blue-700 border border-blue-200 shrink-0">
                  {docLabel}
                </span>
              )}
              {ruleId && (
                <span className="font-semibold text-[#0F2854]">{ruleId}</span>
              )}
              {!isDocPatch && line !== null && (
                <span className="text-[11px] text-gray-400">줄 {line}</span>
              )}
              <span className="ml-auto text-[10px] text-gray-400">
                {isSelected ? "▲ 접기" : "▼ 펼치기"}
              </span>
            </div>

            {/* 펼쳐진 패치 내용 */}
            {isSelected && (
              <div className="px-3 pb-3 border-t border-gray-100 pt-2 space-y-1">
                <p className="text-[10px] text-gray-400 truncate mb-1">{p.path}</p>
                <PatchContent content={p.content} />
                <button
                  className="mt-1 text-[10px] text-[#0b49b5] hover:underline"
                  onClick={() => {
                    const { ruleId: rid, line: ln, isDocPatch: idp, docType: dt, safeFile: sf } = parsePatchPath(p.path);
                    let filePath = null;
                    if (rid && ln !== null) {
                      const match = (allViolations || []).find(v => v.rule_id === rid && v.line === ln);
                      filePath = match?.file || match?.file_path || null;
                    }
                    onSelectPatch && onSelectPatch({ path: p.path, content: p.content, ruleId: rid, line: ln, filePath, isDocPatch: idp, docType: dt });
                  }}
                >
                  {isDocPatch ? "문서에서 보기 →" : "코드에서 보기 →"}
                </button>
              </div>
            )}
          </li>
        );
      })}
    </ul>
  );
}
