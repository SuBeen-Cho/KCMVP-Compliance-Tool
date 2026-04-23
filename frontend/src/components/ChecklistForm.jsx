import { useChecklistStore, OPERATING_MODES } from "../stores/checklistStore";

/**
 * 암호 모듈 시험 신청서 형식의 초기 체크리스트.
 * - 보안수준 1, 제품구분 소프트웨어, 암호알고리즘 블록암호, 암호 선택 LEA: 고정(수정 불가)
 * - 운영모드: 단일 선택(라디오)
 */
export default function ChecklistForm() {
  const selectedMode = useChecklistStore((s) => s.selectedMode);
  const setSelectedMode = useChecklistStore((s) => s.setSelectedMode);

  return (
    <section className="w-full max-w-4xl mb-8">
      <h2 className="text-lg font-semibold text-[#0F2854] mb-3">분석 설정 (암호 모듈 시험 신청서 기준)</h2>
      <div className="rounded-xl border border-[#E5E7EB] bg-white shadow-sm overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="bg-[#F9FAFB] border-b border-[#E5E7EB]">
              <th className="text-left py-3 px-4 font-medium text-[#374151] w-36">구분</th>
              <th className="text-left py-3 px-4 font-medium text-[#374151]">선택</th>
            </tr>
          </thead>
          <tbody className="text-[#111827]">
            {/* 보안수준: 1 고정 */}
            <tr className="border-b border-[#E5E7EB]">
              <td className="py-3 px-4 align-top">보안수준</td>
              <td className="py-3 px-4 flex flex-wrap gap-4">
                {["보안수준 1", "보안수준 2", "보안수준 3", "보안수준 4"].map((label, i) => (
                  <label key={label} className="flex items-center gap-2 cursor-not-allowed opacity-90">
                    <input
                      type="radio"
                      name="securityLevel"
                      checked={i === 0}
                      disabled
                      readOnly
                      className="rounded-full border-[#0b49b5] text-[#0b49b5]"
                    />
                    <span className={i === 0 ? "font-medium" : "text-[#9CA3AF]"}>{label}</span>
                  </label>
                ))}
              </td>
            </tr>
            {/* 제품구분: 소프트웨어 고정 */}
            <tr className="border-b border-[#E5E7EB]">
              <td className="py-3 px-4 align-top">제품구분</td>
              <td className="py-3 px-4 flex flex-wrap gap-4">
                {["하드웨어", "소프트웨어", "펌웨어", "기타"].map((label, i) => (
                  <label key={label} className="flex items-center gap-2 cursor-not-allowed opacity-90">
                    <input
                      type="radio"
                      name="productType"
                      checked={label === "소프트웨어"}
                      disabled
                      readOnly
                      className="rounded-full border-[#0b49b5] text-[#0b49b5]"
                    />
                    <span className={label === "소프트웨어" ? "font-medium" : "text-[#9CA3AF]"}>{label}</span>
                  </label>
                ))}
              </td>
            </tr>
            {/* 암호알고리즘: 블록암호 고정 */}
            <tr className="border-b border-[#E5E7EB]">
              <td className="py-3 px-4 align-top">암호알고리즘</td>
              <td className="py-3 px-4 flex flex-wrap gap-3">
                {["블록암호", "해시", "메시지 인증코드", "난수발생기", "공개키 암호", "전자서명", "키 설정", "키 유도", "기타"].map((label) => (
                  <label key={label} className="flex items-center gap-2 cursor-not-allowed opacity-90">
                    <input
                      type="radio"
                      name="cryptoAlgo"
                      checked={label === "블록암호"}
                      disabled
                      readOnly
                      className="rounded-full border-[#0b49b5] text-[#0b49b5]"
                    />
                    <span className={label === "블록암호" ? "font-medium" : "text-[#9CA3AF]"}>{label}</span>
                  </label>
                ))}
              </td>
            </tr>
            {/* 암호 선택: LEA 고정 */}
            <tr className="border-b border-[#E5E7EB]">
              <td className="py-3 px-4 align-top">암호 선택</td>
              <td className="py-3 px-4 flex flex-wrap gap-4">
                {["LEA", "ARIA", "AES"].map((label) => (
                  <label key={label} className="flex items-center gap-2 cursor-not-allowed opacity-90">
                    <input
                      type="radio"
                      name="cipher"
                      checked={label === "LEA"}
                      disabled
                      readOnly
                      className="rounded-full border-[#0b49b5] text-[#0b49b5]"
                    />
                    <span className={label === "LEA" ? "font-medium" : "text-[#9CA3AF]"}>{label}</span>
                  </label>
                ))}
              </td>
            </tr>
            {/* 운영모드: 단일 선택 (수정 가능) */}
            <tr className="border-b border-[#E5E7EB] bg-[#FAFBFC]">
              <td className="py-3 px-4 align-top font-medium">운영모드</td>
              <td className="py-3 px-4 flex flex-wrap gap-4">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="radio"
                    name="operatingMode"
                    checked={selectedMode === null || selectedMode === ""}
                    onChange={() => setSelectedMode("")}
                    className="rounded-full border-[#0b49b5] text-[#0b49b5]"
                  />
                  <span className="text-[#6B7280]">선택 안 함</span>
                </label>
                {OPERATING_MODES.map(({ value, label }) => (
                  <label key={value} className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="radio"
                      name="operatingMode"
                      checked={selectedMode === value}
                      onChange={() => setSelectedMode(value)}
                      className="rounded-full border-[#0b49b5] text-[#0b49b5]"
                    />
                    <span>{label}</span>
                  </label>
                ))}
              </td>
            </tr>
          </tbody>
        </table>
        <p className="text-xs text-[#6B7280] px-4 py-2 bg-[#F9FAFB] border-t border-[#E5E7EB]">
          운영모드를 선택하면 해당 모드 룰만 적용됩니다. 선택 안 함 시 모드별 룰은 적용되지 않습니다.
        </p>
      </div>
    </section>
  );
}
