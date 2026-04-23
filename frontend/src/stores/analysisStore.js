import { create } from "zustand";

/**
 * 분석 job 상태: jobId, status, progress, report, patches.
 * 폴링 또는 WebSocket으로 갱신.
 */
export const useAnalysisStore = create((set) => ({
  jobId: null,
  status: "idle", // idle | pending | running | completed | failed
  progress: 0,
  currentStep: null,
  report: null,
  aiSummary: null,
  patches: [],
  fileList: [],
  fileContents: {},
  selectedFilePath: null,
  violationsByFile: {},
  jobMeta: null,
  focusedLine: null,
  activeArtifactTab: "report", // report | code | design | scm | test
  docSections: [],
  selectedDocPath: null,
  // DOC 위반: doc_type별로 분류된 문서 위반 목록
  docViolationsByDocType: {}, // { design: [...], scm: [...], test: [...] }
  // 현재 포커스된 DOC 위반 (클릭 시 DocViewer에서 스크롤/하이라이트)
  focusedDocViolation: null,
  // 현재 포커스된 패치 (PatchesTab 클릭 시 CodeViewer에 인라인 패치 패널 표시)
  focusedPatch: null, // { path, content, ruleId, line }
  // 탭별 위반 건수 요약 (code/design/scm/test/combined)
  countsByTab: { code: 0, design: 0, scm: 0, test: 0, combined: 0 },
  // 탭별 심각도 카운트 (high/medium/low)
  severityByTab: {
    code: { high: 0, medium: 0, low: 0 },
    design: { high: 0, medium: 0, low: 0 },
    scm: { high: 0, medium: 0, low: 0 },
    test: { high: 0, medium: 0, low: 0 },
    combined: { high: 0, medium: 0, low: 0 },
  },

  setJob: (jobId, jobMeta) => set({ jobId, status: "pending", progress: 0, jobMeta: jobMeta || null }),
  setStatus: (status, progress, currentStep) =>
    set({ status, progress: progress ?? 0, currentStep }),
  setJobMeta: (meta) =>
    set((state) => ({
      jobMeta: { ...(state.jobMeta || {}), ...(meta || {}) },
    })),
  setReport: (report) =>
    set((state) => {
      const violations = report?.violations || [];
      const fileSet = new Set();
      const violationsByFile = {};
      // 1) 전처리에서 넘어온 전체 파일 목록 우선 사용
      if (Array.isArray(report?.files)) {
        for (const path of report.files) {
          if (typeof path === "string" && path.length > 0) {
            fileSet.add(path);
          }
        }
      }
      // 2) 위반 목록에 포함된 파일 경로도 추가 (줄 번호가 없는 파일 레벨 위반도 포함)
      // 3) DOC 위반(path:null)은 docViolationsByDocType으로 분류
      const docViolationsByDocType = {};
      const countsByTab = { code: 0, design: 0, scm: 0, test: 0, trc: 0, combined: 0 };
      const severityByTab = {
        code: { high: 0, medium: 0, low: 0 },
        design: { high: 0, medium: 0, low: 0 },
        scm: { high: 0, medium: 0, low: 0 },
        test: { high: 0, medium: 0, low: 0 },
        combined: { high: 0, medium: 0, low: 0 },
      };

      const isTrcViolation = (v) =>
        (v.rule_id || "").toUpperCase().startsWith("TRC-") || v.trc_type;

      const normalizeDocType = (dtRaw) => {
        const dt = String(dtRaw || "").toLowerCase().trim();
        if (!dt) return "";
        if (dt === "config_mgmt") return "scm";
        if (dt === "cm") return "scm";
        return dt; // design | scm | test | ...
      };

      const normalizeSeverity = (sevRaw) => {
        const s = String(sevRaw || "").toLowerCase().trim();
        if (s === "high" || s === "medium" || s === "low") return s;
        if (s === "warning") return "medium";
        return "low";
      };

      const bumpSeverity = (tab, sev) => {
        if (!severityByTab[tab]) return;
        if (!severityByTab[tab][sev] && severityByTab[tab][sev] !== 0) return;
        severityByTab[tab][sev] += 1;
      };

      for (const v of violations) {
        if (!v) continue;
        const ruleId = (v.rule_id || "").toUpperCase();
        const sev = normalizeSeverity(v.severity);

        // TRC 위반: TRC-로 시작하거나 trc_type 필드가 있는 경우
        if (isTrcViolation(v)) {
          countsByTab.trc += 1;
          // 파일이 있는 경우 violationsByFile에도 추가 (코드 탭에서 표시)
          const path = v.file || v.file_path;
          if (path) {
            fileSet.add(path);
            countsByTab.code += 1;
            if (!violationsByFile[path]) violationsByFile[path] = [];
            const hasLine = typeof v.line === "number" && v.line > 0;
            violationsByFile[path].push({
              line: hasLine ? v.line : null,
              endLine: hasLine ? v.line : null,
              severity: normalizeSeverity(v.severity),
              rule_id: v.rule_id,
              message: v.message,
              scope: hasLine ? "line" : "file",
              confidence: v.confidence || "후보",
            });
          }
          continue;
        }

        // DOC 위반: rule_id가 DOC-로 시작하거나 doc_type 필드가 있는 경우
        if (ruleId.startsWith("DOC-") || v.doc_type) {
          const dtNorm = normalizeDocType(v.doc_type) || "design";
          if (!docViolationsByDocType[dtNorm]) {
            docViolationsByDocType[dtNorm] = [];
          }
          docViolationsByDocType[dtNorm].push(v);
          if (dtNorm === "design") {
            countsByTab.design += 1;
            bumpSeverity("design", sev);
          } else if (dtNorm === "scm") {
            countsByTab.scm += 1;
            bumpSeverity("scm", sev);
          } else if (dtNorm === "test") {
            countsByTab.test += 1;
            bumpSeverity("test", sev);
          }
          continue;
        }
        const path = v.file || v.file_path;
        if (!path) continue;
        fileSet.add(path);
        countsByTab.code += 1;
        bumpSeverity("code", sev);
        const hasLine = typeof v.line === "number" && v.line > 0;
        const line = hasLine ? v.line : null;
        const severity = (v.severity || "low").toLowerCase();
        const hasEndLine =
          typeof v.end_line === "number" && hasLine && v.end_line >= v.line;
        const endLine = hasEndLine ? v.end_line : line;
        if (!violationsByFile[path]) {
          violationsByFile[path] = [];
        }
        violationsByFile[path].push({
          line,
          endLine,
          severity,
          rule_id: v.rule_id,
          message: v.message,
          scope: v.scope || (hasLine ? "line" : "file"),
        });
      }
      const summary = report?.summary || null;
      // trc는 code와 별도 집계이므로 combined에는 순수 trc (파일 없는) 건수만 추가
      // 파일 있는 TRC는 이미 code에 카운트됨
      countsByTab.combined =
        countsByTab.code + countsByTab.design + countsByTab.scm + countsByTab.test;
      severityByTab.combined = {
        high:
          (severityByTab.code.high || 0) +
          (severityByTab.design.high || 0) +
          (severityByTab.scm.high || 0) +
          (severityByTab.test.high || 0),
        medium:
          (severityByTab.code.medium || 0) +
          (severityByTab.design.medium || 0) +
          (severityByTab.scm.medium || 0) +
          (severityByTab.test.medium || 0),
        low:
          (severityByTab.code.low || 0) +
          (severityByTab.design.low || 0) +
          (severityByTab.scm.low || 0) +
          (severityByTab.test.low || 0),
      };
      return {
        report,
        aiSummary: report?.ai_summary || null,
        status: "completed",
        fileList: Array.from(fileSet),
        violationsByFile,
        docViolationsByDocType,
        countsByTab,
        severityByTab,
        jobMeta: {
          ...(state.jobMeta || {}),
          summary,
          fileCount:
            (state.jobMeta && state.jobMeta.fileCount) ||
            (Array.isArray(report?.files) ? report.files.length : undefined),
        },
      };
    }),
  setPatches: (patches) => set({ patches }),
  setFileList: (fileList) => set({ fileList }),
  setSelectedFilePath: (selectedFilePath) => set({ selectedFilePath }),
  setFocusedLine: (focusedLine) => set({ focusedLine }),
  setFileContent: (path, content) =>
    set((state) => ({
      fileContents: {
        ...state.fileContents,
        [path]: content,
      },
    })),
  setDocSections: (sections) =>
    set({
      docSections: Array.isArray(sections) ? sections : [],
    }),
  setSelectedDocPath: (selectedDocPath) => set({ selectedDocPath }),
  setActiveArtifactTab: (tab) => set({ activeArtifactTab: tab || "report" }),
  setFocusedDocViolation: (violation) => set({ focusedDocViolation: violation }),
  setFocusedPatch: (patch) => set({ focusedPatch: patch }),
  reset: () =>
    set({
      jobId: null,
      status: "idle",
      progress: 0,
      currentStep: null,
      report: null,
      aiSummary: null,
      patches: [],
      fileList: [],
      fileContents: {},
      selectedFilePath: null,
      violationsByFile: {},
      jobMeta: null,
      focusedLine: null,
      activeArtifactTab: "report",
      docSections: [],
      selectedDocPath: null,
      docViolationsByDocType: {},
      focusedDocViolation: null,
      focusedPatch: null,
      countsByTab: { code: 0, design: 0, scm: 0, test: 0, trc: 0, combined: 0 },
      severityByTab: {
        code: { high: 0, medium: 0, low: 0 },
        design: { high: 0, medium: 0, low: 0 },
        scm: { high: 0, medium: 0, low: 0 },
        test: { high: 0, medium: 0, low: 0 },
        combined: { high: 0, medium: 0, low: 0 },
      },
    }),
}));
