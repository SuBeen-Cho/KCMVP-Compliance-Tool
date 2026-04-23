import { create } from "zustand";

/**
 * 초기 체크리스트 상태 (암호 모듈 시험 신청서 형식).
 * - 보안수준 1, 소프트웨어, 블록암호, LEA: 고정(수정 불가)
 * - 운영모드: 단일 선택만 가능 (라디오), 분석 시 algorithm/mode 로 API에 전달
 */
export const OPERATING_MODES = [
  { value: "ECB", label: "ECB" },
  { value: "CBC", label: "CBC" },
  { value: "CTR", label: "CTR" },
  { value: "OFB", label: "OFB" },
  { value: "CFB", label: "CFB" },
  { value: "CCM", label: "CCM" },
  { value: "GCM", label: "GCM" },
  { value: "CMAC", label: "CMAC" },
];

export const useChecklistStore = create((set) => ({
  /** 운영모드 단일 선택 (null = 선택 안 함, 모드 룰 미적용) */
  selectedMode: "CBC",

  setSelectedMode: (mode) => set({ selectedMode: mode }),

  /** 분석 API에 넘길 값: algorithm 고정 LEA, mode는 선택값(없으면 null) */
  getAnalyzeParams: () => {
    const state = useChecklistStore.getState();
    return {
      algorithm: "LEA",
      mode: state.selectedMode || undefined,
    };
  },
}));
