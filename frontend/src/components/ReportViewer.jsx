import { useMemo, useState } from "react";
import { useAnalysisStore } from "../stores/analysisStore";

// ── 간단 마크다운 → JSX 렌더러 ─────────────────────────────────────────
function renderMd(text) {
  if (!text) return null;
  const lines = text.split("\n");
  const elements = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (/^### /.test(line)) {
      elements.push(<p key={i} className="font-semibold text-[13px] text-blue-800 mt-3 mb-1">{inlineMd(line.slice(4))}</p>);
    } else if (/^## /.test(line)) {
      elements.push(<p key={i} className="font-semibold text-[14px] text-blue-900 mt-3 mb-1">{inlineMd(line.slice(3))}</p>);
    } else if (/^# /.test(line)) {
      elements.push(<p key={i} className="font-bold text-[15px] text-blue-900 mt-2 mb-1">{inlineMd(line.slice(2))}</p>);
    } else if (/^[-*] /.test(line)) {
      elements.push(<li key={i} className="ml-4 list-disc text-[13px] text-gray-700 leading-relaxed">{inlineMd(line.slice(2))}</li>);
    } else if (/^\d+\. /.test(line)) {
      elements.push(<li key={i} className="ml-4 list-decimal text-[13px] text-gray-700 leading-relaxed">{inlineMd(line.replace(/^\d+\. /, ""))}</li>);
    } else if (line.trim() === "") {
      elements.push(<div key={i} className="h-2" />);
    } else {
      elements.push(<p key={i} className="text-[13px] text-gray-700 leading-relaxed">{inlineMd(line)}</p>);
    }
    i++;
  }
  return elements;
}

function inlineMd(text) {
  // **bold**, *italic*, `code` 처리
  const parts = text.split(/(\*\*[^*]+\*\*|\*[^*]+\*|`[^`]+`)/g);
  return parts.map((part, i) => {
    if (/^\*\*(.+)\*\*$/.test(part)) return <strong key={i}>{part.slice(2, -2)}</strong>;
    if (/^\*(.+)\*$/.test(part))   return <em key={i}>{part.slice(1, -1)}</em>;
    if (/^`(.+)`$/.test(part))     return <code key={i} className="bg-blue-100 text-blue-800 px-1 rounded text-[11px] font-mono">{part.slice(1, -1)}</code>;
    return part;
  });
}

// ── 심각도별 스타일 ────────────────────────────────────────────────────
function getSeverityStyle(severity, confidence) {
  const isCandidate = confidence !== "확정";
  const opac = isCandidate ? "opacity-80" : "";
  switch ((severity || "medium").toLowerCase()) {
    case "high":
      return {
        card:  `border-l-4 border-red-500 bg-red-50 ${opac}`,
        badge: "bg-red-100 text-red-700 border border-red-300",
        label: "HIGH",
      };
    case "low":
      return {
        card:  `border-l-4 border-gray-300 bg-white ${opac}`,
        badge: "bg-gray-100 text-gray-600 border border-gray-300",
        label: "LOW",
      };
    default:
      return {
        card:  `border-l-4 border-amber-400 bg-amber-50 ${opac}`,
        badge: "bg-amber-100 text-amber-700 border border-amber-300",
        label: "MED",
      };
  }
}

function ViolationCard({ v, onClick }) {
  const conf   = getConfidence(v);
  const style  = getSeverityStyle(v.severity, conf);
  const isDoc  = (v.rule_id || "").toUpperCase().startsWith("DOC-") || !!v.doc_type;
  const lineNo =
    typeof v.line === "number" && v.line > 0 ? `L${v.line}`
    : isDoc ? "문서 전체"
    : v.pattern_type === "missing" ? "항목 부재"
    : "파일 전체";

  return (
    <div
      className={`rounded-lg border border-gray-200 overflow-hidden cursor-pointer hover:shadow-md transition-shadow ${style.card}`}
      onClick={onClick}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => e.key === "Enter" && onClick?.()}
    >
      {/* 카드 헤더 */}
      <div className="flex items-center justify-between px-3 py-2 gap-2">
        <div className="flex items-center gap-1.5 min-w-0 flex-wrap">
          <span className="font-mono font-bold text-[12px] text-[#0b49b5] shrink-0">
            {v.rule_id}
          </span>
          <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold shrink-0 ${style.badge}`}>
            {style.label}
          </span>
          <ConfidenceBadge
            confidence={conf}
            score={v.confidence_score}
            insufficientCtx={v.insufficient_context}
          />
        </div>
        <span className="font-mono text-[10px] text-gray-400 shrink-0">{lineNo}</span>
      </div>

      {/* 카드 본문 */}
      <div className="px-3 pb-2 space-y-1">
        <p className="text-[12px] text-gray-800 leading-relaxed">{v.message}</p>
        {v.rag_evidence && (
          <p className="text-[11px] text-blue-700 bg-blue-50 rounded px-2 py-1 leading-relaxed border border-blue-100">
            📖 {v.rag_evidence}
          </p>
        )}
        {v.l2_reason && (
          <p className="text-[11px] text-gray-500 italic leading-relaxed">
            AI: {v.l2_reason}
          </p>
        )}
      </div>
    </div>
  );
}

// ── 카테고리 매핑 ─────────────────────────────────────────────────────
const MODE_PREFIXES = new Set(["CBC", "GCM", "CTR", "CCM", "CFB", "OFB", "CMAC", "ECB"]);
const ALGO_PREFIXES = new Set(["LEA", "ARIA", "SEED", "HIGHT"]);

const CATEGORY_ORDER = ["common", "algorithm", "mode", "cm", "test", "doc", "trc", "etc"];
const CATEGORY_META = {
  common:    { label: "공통 보안",       abbr: "COM" },
  algorithm: { label: "알고리즘 구현",   abbr: "ALG" },
  mode:      { label: "운영 모드",       abbr: "MODE" },
  cm:        { label: "형상관리",         abbr: "CM" },
  test:      { label: "시험 요구사항",   abbr: "TEST" },
  doc:       { label: "문서 요구사항",   abbr: "DOC" },
  trc:       { label: "추적성",           abbr: "TRC" },
  etc:       { label: "기타",             abbr: "ETC" },
};

function getCategory(ruleId) {
  const prefix = (ruleId || "").split("-")[0].toUpperCase();
  if (prefix === "COM") return "common";
  if (ALGO_PREFIXES.has(prefix)) return "algorithm";
  if (MODE_PREFIXES.has(prefix)) return "mode";
  if (prefix === "CM") return "cm";
  if (prefix === "TEST") return "test";
  if (prefix === "DOC" || prefix === "DESIGN" || prefix === "CONFIG") return "doc";
  if (prefix === "TRC") return "trc";
  return "etc";
}

function getConfidence(v) {
  if (v.confidence) return v.confidence;
  if (v.l2_confirmed) return "확정";
  if (v.needs_ai_review) return "후보";
  return "확정";
}

function Verdict({ confirmed, review = 0, candidate }) {
  if (confirmed > 0) return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium bg-red-100 text-red-700 border border-red-200">
      ❌ 불합격
    </span>
  );
  if (review > 0) return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium bg-blue-50 text-blue-700 border border-blue-200">
      ⚠️ 검토 권고
    </span>
  );
  if (candidate > 0) return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium bg-amber-50 text-amber-700 border border-amber-200">
      ⚠️ 검토 필요
    </span>
  );
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium bg-green-50 text-green-700 border border-green-200">
      ✅ 통과
    </span>
  );
}

function ConfidenceBadge({ confidence, score, insufficientCtx }) {
  const scoreText = (score !== undefined && score !== null) ? ` ${score}%` : "";
  if (confidence === "확정") return (
    <span className="inline-flex items-center gap-0.5 px-2 py-0.5 rounded-full text-[10px] font-bold bg-red-100 text-red-700 border border-red-200"
          title={score !== undefined ? `확신도: ${score}%` : undefined}>
      확정{scoreText && <span className="font-normal opacity-75">{scoreText}</span>}
    </span>
  );
  if (insufficientCtx) return (
    <span className="inline-flex items-center gap-0.5 px-2 py-0.5 rounded-full text-[10px] font-medium bg-gray-100 text-gray-500 border border-gray-300"
          title="AI 판정 시 코드 절삭이 불충분하여 재검토 필요">
      ? 증거부족
    </span>
  );
  if (confidence === "검토권고") return (
    <span className="inline-flex items-center gap-0.5 px-2 py-0.5 rounded-full text-[10px] font-bold bg-blue-50 text-blue-700 border border-blue-200"
          title={score !== undefined ? `확신도: ${score}% (제출물 맥락 검토 필요)` : "정책상 검토 권고"}>
      검토권고{scoreText && <span className="font-normal opacity-75">{scoreText}</span>}
    </span>
  );
  return (
    <span className="inline-flex items-center gap-0.5 px-2 py-0.5 rounded-full text-[10px] font-bold bg-amber-50 text-amber-600 border border-amber-200"
          title={score !== undefined ? `확신도: ${score}% (L2 미검토 또는 낮은 확신도)` : "L1 탐지, L2 미검토"}>
      △ 후보{scoreText && <span className="font-normal opacity-75">{scoreText}</span>}
    </span>
  );
}

// DOC 위반: doc_type으로 그룹 레이블 반환
const DOC_TYPE_LABEL = {
  design: "상세설계서",
  scm: "형상관리 문서",
  config_mgmt: "형상관리 문서",
  test: "시험서",
};

function groupViolations(violations) {
  // DOC/TRC 위반은 doc_type 기반, 코드 위반은 file 기반으로 그룹
  const byGroup = {};
  for (const v of violations) {
    const isDoc = (v.rule_id || "").toUpperCase().startsWith("DOC-") || !!v.doc_type;
    let key;
    if (isDoc) {
      const dt = v.doc_type || "design";
      key = `[문서] ${DOC_TYPE_LABEL[dt] || dt}`;
    } else {
      key = v.file || "(파일 미확인)";
    }
    if (!byGroup[key]) byGroup[key] = [];
    byGroup[key].push(v);
  }
  return byGroup;
}

function CollapsibleSection({ title, badge, defaultOpen = true, children }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="rounded-lg border border-gray-200 overflow-hidden">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="w-full flex items-center justify-between px-3 py-2 bg-gray-50 hover:bg-gray-100 transition-colors text-left"
      >
        <div className="flex items-center gap-2">
          <span className="text-[10px] text-gray-400 select-none">{open ? "▼" : "▶"}</span>
          <span className="font-mono text-[11px] text-[#0F2854] font-medium">{title}</span>
          {badge && <span className="text-[10px] text-gray-400 truncate max-w-[200px]">{badge}</span>}
        </div>
      </button>
      {open && children}
    </div>
  );
}

export default function ReportViewer() {
  const report     = useAnalysisStore((s) => s.report);
  const jobId      = useAnalysisStore((s) => s.jobId);
  const jobMeta    = useAnalysisStore((s) => s.jobMeta);
  const aiSummary  = useAnalysisStore((s) => s.aiSummary);
  const setSelectedFilePath  = useAnalysisStore((s) => s.setSelectedFilePath);
  const setFocusedLine       = useAnalysisStore((s) => s.setFocusedLine);
  const setActiveArtifactTab = useAnalysisStore((s) => s.setActiveArtifactTab);
  const setFocusedDocViolation = useAnalysisStore((s) => s.setFocusedDocViolation);

  const violations = report?.violations || [];
  const summary    = report?.summary || {};
  const meta       = report?.meta || {};

  // 카테고리별 분류
  const catData = useMemo(() => {
    const data = Object.fromEntries(
      CATEGORY_ORDER.map((c) => [c, { confirmed: [], review: [], candidate: [] }])
    );
    for (const v of violations) {
      const cat    = getCategory(v.rule_id || "");
      const conf = getConfidence(v);
      const bucket = conf === "확정" ? "confirmed" : conf === "검토권고" ? "review" : "candidate";
      data[cat][bucket].push(v);
    }
    return data;
  }, [violations]);

  const isTrc = (v) => (v.rule_id || "").toUpperCase().startsWith("TRC-") || !!v.trc_type;
  const nonTrcViolations = violations.filter((v) => !isTrc(v));
  const trcViolations    = violations.filter(isTrc);

  const totalConfirmed = nonTrcViolations.filter((v) => getConfidence(v) === "확정").length;
  const totalReview    = nonTrcViolations.filter((v) => getConfidence(v) === "검토권고").length;
  const totalCandidate = nonTrcViolations.filter((v) => getConfidence(v) === "후보").length;
  const trcCount       = trcViolations.length;

  function handleViolationClick(v) {
    const ruleId = (v.rule_id || "").toUpperCase();
    const isDoc  = ruleId.startsWith("DOC-") || !!v.doc_type;
    if (isDoc) {
      const docType = v.doc_type || "design";
      setActiveArtifactTab(docType === "config_mgmt" ? "scm" : docType);
      setFocusedDocViolation(v);
    } else {
      const path = v.file || v.file_path;
      if (path) {
        setSelectedFilePath(path);
        setFocusedLine(typeof v.line === "number" && v.line > 0 ? v.line : null);
        setActiveArtifactTab("code");
      }
    }
  }

  if (!report) {
    return (
      <div className="flex items-center justify-center h-full text-sm text-gray-400">
        분석 완료 후 보고서가 표시됩니다.
      </div>
    );
  }

  const overallVerdict = totalConfirmed > 0 ? "❌ 불합격" : totalReview > 0 ? "⚠️ 검토 권고" : totalCandidate > 0 ? "⚠️ 검토 필요" : "✅ 통과";
  // TRC는 판정에 포함하지 않음 — 별도 참고 정보로 표시

  const handlePrint = () => window.print();

  return (
    <div className="h-full overflow-auto bg-white text-sm" id="report-printable">
      {/* ── 헤더 ── */}
      <div className="sticky top-0 z-10 bg-white border-b border-gray-200 px-6 py-3 flex items-center justify-between shadow-sm print:static print:shadow-none">
        <div>
          <h2 className="text-sm font-semibold text-[#0F2854]">KCMVP 사전 적합성 분석 보고서</h2>
          <p className="text-[11px] text-gray-500 mt-0.5">
            {meta.algorithm && `대상: ${meta.algorithm}`}
            {meta.mode && ` · 모드: ${meta.mode}`}
            {meta.date && ` · ${meta.date}`}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className={[
            "px-3 py-1.5 rounded-lg text-sm font-semibold border",
            totalConfirmed > 0
              ? "bg-red-50 text-red-700 border-red-200"
              : totalReview > 0
              ? "bg-blue-50 text-blue-700 border-blue-200"
              : totalCandidate > 0
              ? "bg-amber-50 text-amber-700 border-amber-200"
              : "bg-green-50 text-green-700 border-green-200",
          ].join(" ")}>
            {overallVerdict}
          </div>
          {jobId && (
            <a
              href={`/api/analyze/${jobId}/report.pdf`}
              target="_blank"
              rel="noopener noreferrer"
              className="print:hidden px-3 py-1.5 rounded-lg text-xs border border-blue-200 bg-blue-50 text-blue-700 hover:bg-blue-100 flex items-center gap-1"
              title="PDF 보고서 다운로드"
            >
              ⬇ PDF 다운로드
            </a>
          )}
          <button
            type="button"
            onClick={handlePrint}
            className="print:hidden px-3 py-1.5 rounded-lg text-xs border border-gray-200 bg-white text-gray-600 hover:bg-gray-50 flex items-center gap-1"
          >
            🖨️ 인쇄
          </button>
        </div>
      </div>

      <div className="px-6 py-4 space-y-6">
        {/* ── 종합 판정 테이블 ── */}
        <section>
          <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-3">
            종합 판정
          </h3>

          {/* 상단 확정/후보 요약 카드 */}
          <div className="grid grid-cols-4 gap-3 mb-4">
            <div className="rounded-xl border-2 border-red-200 bg-red-50 px-4 py-4 text-center shadow-sm">
              <p className="text-[11px] font-medium text-red-500 mb-1 uppercase tracking-wide">확정 위반</p>
              <p className="text-3xl font-black text-red-700">{totalConfirmed}</p>
              {summary.confirmed_high > 0 && (
                <p className="text-[10px] text-red-400 mt-1">HIGH {summary.confirmed_high}건 포함</p>
              )}
            </div>
            <div className="rounded-xl border-2 border-amber-200 bg-amber-50 px-4 py-4 text-center shadow-sm">
              <p className="text-[11px] font-medium text-amber-500 mb-1 uppercase tracking-wide">검토 권고</p>
              <p className="text-3xl font-black text-amber-600">{totalReview}</p>
              <p className="text-[10px] text-amber-400 mt-1">제출물 맥락 확인</p>
            </div>
            <div className="rounded-xl border-2 border-gray-200 bg-gray-50 px-4 py-4 text-center shadow-sm">
              <p className="text-[11px] font-medium text-amber-500 mb-1 uppercase tracking-wide">위반 후보</p>
              <p className="text-3xl font-black text-gray-700">{totalCandidate}</p>
              <p className="text-[10px] text-amber-400 mt-1">L2 재검토 필요</p>
            </div>
            <div className="rounded-xl border-2 border-gray-200 bg-gray-50 px-4 py-4 text-center shadow-sm">
              <p className="text-[11px] font-medium text-gray-400 mb-1 uppercase tracking-wide">전체</p>
              <p className="text-3xl font-black text-gray-700">{nonTrcViolations.length}</p>
              <p className="text-[10px] text-gray-400 mt-1">TRC 제외</p>
            </div>
          </div>
          {/* TRC 참고 정보 */}
          {trcCount > 0 && (
            <div className="mb-4 flex items-center gap-2 px-3 py-2 rounded-lg bg-purple-50 border border-purple-200 text-[11px] text-purple-700">
              <span className="text-purple-500">🔗</span>
              <span>추적성(TRC) 항목 <strong>{trcCount}건</strong> 별도 검토 필요 — 위 판정에는 포함되지 않음</span>
            </div>
          )}

          {/* 카테고리별 판정 테이블 */}
          <div className="overflow-hidden rounded-lg border border-gray-200">
            <table className="w-full text-xs">
              <thead>
                <tr className="bg-gray-50 text-gray-500 uppercase text-[10px]">
                  <th className="text-left px-3 py-2 font-medium">카테고리</th>
                  <th className="text-center px-3 py-2 font-medium w-20">확정</th>
                  <th className="text-center px-3 py-2 font-medium w-20">권고</th>
                  <th className="text-center px-3 py-2 font-medium w-20">후보</th>
                  <th className="text-center px-3 py-2 font-medium w-28">판정</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {CATEGORY_ORDER.map((cat) => {
                  const c = catData[cat].confirmed.length;
                  const r = catData[cat].review.length;
                  const k = catData[cat].candidate.length;
                  if (c === 0 && r === 0 && k === 0) return null;
                  const { label, abbr } = CATEGORY_META[cat];
                  return (
                    <tr key={cat} className={["transition-colors", c > 0 ? "bg-red-50 hover:bg-red-100" : r > 0 ? "bg-blue-50 hover:bg-blue-100" : k > 0 ? "bg-amber-50 hover:bg-amber-100" : "hover:bg-gray-50"].join(" ")}>
                      <td className="px-3 py-2 font-medium text-gray-800">
                        {label} <span className="text-gray-400">({abbr})</span>
                      </td>
                      <td className="px-3 py-2 text-center">
                        {c > 0
                          ? <span className="font-bold text-red-600">{c}건</span>
                          : <span className="text-gray-400">0건</span>
                        }
                      </td>
                      <td className="px-3 py-2 text-center text-blue-600">{r}건</td>
                      <td className="px-3 py-2 text-center text-gray-500">{k}건</td>
                      <td className="px-3 py-2 text-center">
                        <Verdict confirmed={c} review={r} candidate={k} />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>

        {/* ── AI 종합 평가 ── */}
        {aiSummary && (
          <section className="rounded-xl border border-blue-200 bg-blue-50 p-5 shadow-sm">
            <div className="flex items-center gap-2 mb-3">
              <span className="text-blue-500 text-base">🤖</span>
              <h3 className="text-sm font-bold text-blue-800 tracking-wide">AI 종합 평가</h3>
            </div>
            <div className="leading-relaxed space-y-1">
              {renderMd(aiSummary)}
            </div>
          </section>
        )}

        {/* ── 카테고리별 상세 ── */}
        {CATEGORY_ORDER.map((cat) => {
          const c_list = catData[cat].confirmed;
          const r_list = catData[cat].review;
          const k_list = catData[cat].candidate;
          const all    = [...c_list, ...r_list, ...k_list];
          if (!all.length) return null;

          const { label, abbr } = CATEGORY_META[cat];
          const byGroup = groupViolations(all);

          return (
            <section key={cat}>
              <div className="flex items-center justify-between mb-3 pb-2 border-b border-gray-100">
                <div className="flex items-center gap-2">
                  <h3 className="text-[13px] font-bold text-gray-800">{label}</h3>
                  <span className="text-[11px] text-gray-400 font-normal">({abbr})</span>
                  <span className="px-2 py-0.5 rounded-full bg-gray-100 text-[10px] text-gray-500 font-medium">
                    {all.length}건
                  </span>
                </div>
                <Verdict confirmed={c_list.length} review={r_list.length} candidate={k_list.length} />
              </div>

              <div className="space-y-2">
                {Object.entries(byGroup).sort(([a], [b]) => a.localeCompare(b)).map(([groupKey, groupVs]) => {
                  const isDocGroup = groupKey.startsWith("[문서]");
                  const fname = isDocGroup
                    ? groupKey
                    : (groupKey.includes("/") ? groupKey.split("/").pop() : groupKey);
                  const badge = isDocGroup ? null : groupKey;
                  return (
                    <CollapsibleSection
                      key={groupKey}
                      title={fname}
                      badge={badge !== fname ? badge : null}
                      defaultOpen={all.length <= 30}
                    >
                      <div className="p-2 space-y-2">
                        {groupVs
                          .sort((a, b) => (a.line || 0) - (b.line || 0))
                          .map((v, idx) => (
                            <ViolationCard
                              key={`${v.rule_id}-${idx}`}
                              v={v}
                              onClick={() => handleViolationClick(v)}
                            />
                          ))}
                      </div>
                    </CollapsibleSection>
                  );
                })}
              </div>
            </section>
          );
        })}

        {/* ── 수정 필요 파일 요약 ── */}
        {totalConfirmed > 0 && (() => {
          const fileStats = {};
          for (const v of nonTrcViolations) {
            if (getConfidence(v) !== "확정") continue;
            const fp = (v.file || "(알 수 없음)").split("/").pop();
            if (!fileStats[fp]) fileStats[fp] = { count: 0, rules: [] };
            fileStats[fp].count += 1;
            if (v.rule_id && !fileStats[fp].rules.includes(v.rule_id)) {
              fileStats[fp].rules.push(v.rule_id);
            }
          }
          const sorted = Object.entries(fileStats).sort(([, a], [, b]) => b.count - a.count);
          return (
            <section>
              <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-3">
                수정 필요 파일 (확정 위반 기준)
              </h3>
              <div className="overflow-hidden rounded-lg border border-gray-200">
                <table className="w-full text-[11px]">
                  <thead>
                    <tr className="bg-gray-50 text-gray-500 uppercase text-[10px]">
                      <th className="text-left px-3 py-2 font-medium">파일</th>
                      <th className="text-center px-3 py-2 font-medium w-16">확정</th>
                      <th className="text-left px-3 py-2 font-medium">대표 규칙</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-100">
                    {sorted.map(([fname, stats]) => (
                      <tr key={fname} className="hover:bg-gray-50">
                        <td className="px-3 py-2 font-mono font-medium text-[#0F2854]">{fname}</td>
                        <td className="px-3 py-2 text-center font-bold text-red-600">{stats.count}건</td>
                        <td className="px-3 py-2 text-gray-600">
                          {stats.rules.slice(0, 3).join(", ")}
                          {stats.rules.length > 3 && ` 외 ${stats.rules.length - 3}건`}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          );
        })()}
      </div>
    </div>
  );
}
