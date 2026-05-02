"""
ReportService: 최종 보고서·패치 조합 및 저장.
- 위반 목록 + L3 근거 + 패치 링크 → JSON 보고서 + 마크다운 파일.
"""
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional
from collections import defaultdict
from datetime import date


# ──────────────────────────────────────────────────────────────────────
# 카테고리 매핑
# ──────────────────────────────────────────────────────────────────────

_CATEGORY_ORDER = ["common", "algorithm", "mode", "cm", "test", "doc", "trc", "etc"]

_CATEGORY_META: Dict[str, Dict[str, str]] = {
    "common":    {"label": "공통 보안",     "abbr": "COM"},
    "algorithm": {"label": "알고리즘 구현", "abbr": "ALG"},
    "mode":      {"label": "운영 모드",     "abbr": "MODE"},
    "cm":        {"label": "형상관리",       "abbr": "CM"},
    "test":      {"label": "시험 요구사항", "abbr": "TEST"},
    "doc":       {"label": "문서 요구사항", "abbr": "DOC"},
    "trc":       {"label": "추적성",         "abbr": "TRC"},
    "etc":       {"label": "기타",           "abbr": "ETC"},
}

_MODE_PREFIXES = {"CBC", "GCM", "CTR", "CCM", "CFB", "OFB", "CMAC", "ECB"}
_ALGO_PREFIXES = {"LEA", "SEED", "HIGHT"}
_DOC_PREFIXES  = {"DOC", "DESIGN", "CONFIG", "KEYBIZ"}


def _get_category(rule_id: str) -> str:
    prefix = rule_id.split("-")[0].upper()
    if prefix == "COM":
        return "common"
    if prefix in _ALGO_PREFIXES:
        return "algorithm"
    if prefix in _MODE_PREFIXES:
        return "mode"
    if prefix == "CM":
        return "cm"
    if prefix == "TEST":
        return "test"
    if prefix in _DOC_PREFIXES or prefix == "DOC":
        return "doc"
    if prefix == "TRC":
        return "trc"
    return "etc"


# ──────────────────────────────────────────────────────────────────────
# 신뢰도 헬퍼
# ──────────────────────────────────────────────────────────────────────

def _confidence(v: Dict[str, Any]) -> str:
    """위반 딕셔너리에서 confidence 값 추출.

    - confidence 필드가 있으면 그대로 사용
    - l3_confirmed=True  → "확정" (L3 검증 통과)
    - needs_ai_review=True → "후보"
    - pattern_type=missing  → "검토권고" (동등 구현/별도 래퍼/시험 아티팩트 가능성 검토 필요)
    - 나머지 regex/semantic/ast without L3 → "후보" (L1 단독 판정, 미검토)
    """
    if "confidence" in v:
        return v["confidence"]
    if v.get("l3_confirmed"):
        return "확정"
    pt = (v.get("pattern_type") or "").lower()
    if pt == "missing":
        return "검토권고"
    if v.get("needs_ai_review"):
        return "후보"
    return "후보"       # regex/semantic/ast 는 L3 미검토 상태 → 후보


# ──────────────────────────────────────────────────────────────────────
# post_process_violations
# ──────────────────────────────────────────────────────────────────────

def post_process_violations(
    l1: List[Dict[str, Any]],
    l3: List[Dict[str, Any]],
    l3_rejected_keys: Optional[set] = None,
) -> List[Dict[str, Any]]:
    """
    L1 + L3 원시 결과를 받아 최종 위반 리스트로 통합.

    - L1 결과를 (file, line, rule_id) 기준으로 dedup
    - l3_rejected_keys에 있는 항목은 L3가 오탐으로 판정 → 제거
    - L3 확인 결과가 매칭되면 병합 후 confidence → "확정"
    - 매칭 안 된 L3 항목은 독립 위반으로 유지
    """
    # ── L1 dedup ──
    seen_l1: set = set()
    deduped_l1: List[Dict[str, Any]] = []
    for v in l1:
        key = (
            (v.get("file") or "").strip(),
            v.get("line"),
            (v.get("rule_id") or "").strip(),
        )
        if key in seen_l1:
            continue
        seen_l1.add(key)
        deduped_l1.append(dict(v))

    # ── L3 오탐 제거: L3가 is_real_issue=False 로 판정한 L1 항목 제거 ──
    if l3_rejected_keys:
        before = len(deduped_l1)
        deduped_l1 = [
            v for v in deduped_l1
            if (
                (v.get("file") or "").strip(),
                (v.get("rule_id") or "").strip(),
                v.get("line"),
            ) not in l3_rejected_keys
        ]
        removed = before - len(deduped_l1)
        if removed:
            print(f"[Report] L3 오탐 제거 후처리: {removed}건 삭제 (L3 rejected)")

    # ── L3 인덱스 ──
    def _original_rule_id(rid: str) -> str:
        return rid[3:] if rid.startswith("L3-") else rid

    l3_index: Dict[Tuple, Dict[str, Any]] = {}
    for v in l3:
        file_ = (v.get("file") or "").strip()
        original = _original_rule_id((v.get("rule_id") or "").strip())
        key = (file_, original, v.get("line"))
        l3_index[key] = v

    # ── L1에 L3 병합 ──
    matched_l3_keys: set = set()
    result: List[Dict[str, Any]] = []
    for v in deduped_l1:
        file_ = (v.get("file") or "").strip()
        rid   = (v.get("rule_id") or "").strip()
        key   = (file_, rid, v.get("line"))
        l3_match = l3_index.get(key)
        if l3_match:
            merged = dict(v)
            merged["source"]       = "L1+L3"
            merged["l3_confirmed"] = True
            merged["l3_message"]   = l3_match.get("message", "")
            merged["suggestion"]   = l3_match.get("suggestion", v.get("suggestion", ""))
            merged["confidence"]   = l3_match.get("confidence", "확정")
            if "confidence_score" in l3_match:
                merged["confidence_score"] = l3_match.get("confidence_score")
            if "l3_is_real_issue" in l3_match:
                merged["l3_is_real_issue"] = l3_match.get("l3_is_real_issue")
            result.append(merged)
            matched_l3_keys.add(key)
        else:
            if (
                (v.get("pattern_type") or "").lower() == "missing"
                and not v.get("l3_confirmed")
                and v.get("confidence") == "확정"
            ):
                # 과거 L1 missing 결과는 confidence="확정"으로 생성된 경우가 있다.
                # 실제 제출물형 코드에서는 L3 확인 전까지 검토 권고로 낮춰 보고한다.
                v["confidence"] = "검토권고"
            if "confidence" not in v:
                v["confidence"] = _confidence(v)
            result.append(v)

    # ── 매칭 안 된 L3 항목 ──
    for v in l3:
        file_ = (v.get("file") or "").strip()
        original = _original_rule_id((v.get("rule_id") or "").strip())
        key = (file_, original, v.get("line"))
        if key not in matched_l3_keys:
            item = dict(v)
            if "confidence" not in item:
                item["confidence"] = _confidence(item)
            result.append(item)

    return result


# ──────────────────────────────────────────────────────────────────────
# build_summary
# ──────────────────────────────────────────────────────────────────────

def build_summary(violations: List[Dict[str, Any]]) -> Dict[str, Any]:
    """confidence × severity 교차 집계."""
    confirmed = sum(1 for v in violations if _confidence(v) == "확정")
    review = sum(1 for v in violations if _confidence(v) == "검토권고")
    candidate = len(violations) - confirmed

    # severity 전체 집계
    sev: Dict[str, int] = {"high": 0, "medium": 0, "low": 0}
    # confirmed 중 severity 교차 집계
    confirmed_sev: Dict[str, int] = {"high": 0, "medium": 0, "low": 0}
    for v in violations:
        s = (v.get("severity") or "low").lower()
        if s not in sev:
            s = "low"
        sev[s] += 1
        if _confidence(v) == "확정":
            confirmed_sev[s] += 1

    return {
        "total":           len(violations),
        "confirmed":       confirmed,
        "review":          review,
        "candidate":       candidate,
        # 전체 severity (하위 호환)
        "high":            sev["high"],
        "medium":          sev["medium"],
        "low":             sev["low"],
        # 확정 위반만의 severity — 진짜 위험도 파악용
        "confirmed_high":  confirmed_sev["high"],
        "confirmed_medium":confirmed_sev["medium"],
        "confirmed_low":   confirmed_sev["low"],
    }


# ──────────────────────────────────────────────────────────────────────
# write_report_json
# ──────────────────────────────────────────────────────────────────────

def write_report_json(job_root: Path, report: Dict[str, Any]) -> Path:
    out = job_root / "report.json"
    import json
    with open(out, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    return out


# ──────────────────────────────────────────────────────────────────────
# write_report_markdown  (방향 B 기반 혼합형)
# ──────────────────────────────────────────────────────────────────────

def write_report_markdown(job_root: Path, report: Dict[str, Any]) -> Path:
    """
    카테고리(규정) 중심 보고서 + 각 카테고리 내 파일별 그룹.

    판정 기준:
      확정 위반 ≥ 1건  →  ❌ 불합격
      검토권고/후보만   →  ⚠️  검토 필요
      0건              →  ✅ 통과
    """
    violations = report.get("violations", [])
    summary    = report.get("summary", {})
    meta       = report.get("meta", {})
    ai_summary = report.get("ai_summary")

    algo        = meta.get("algorithm") or "-"
    mode        = meta.get("mode") or "-"
    today       = meta.get("date") or str(date.today())
    total_files = meta.get("file_count") or "-"

    # ── 카테고리별 분류 ──
    cat_data: Dict[str, Dict[str, list]] = {
        cat: {"confirmed": [], "review": [], "candidate": []}
        for cat in _CATEGORY_ORDER
    }
    for v in violations:
        cat    = _get_category(v.get("rule_id", ""))
        conf   = _confidence(v)
        bucket = "confirmed" if conf == "확정" else ("review" if conf == "검토권고" else "candidate")
        cat_data[cat][bucket].append(v)

    def _verdict(c: int, r: int, k: int) -> str:
        if c:   return "❌ 불합격"
        if r:   return "⚠️  검토 권고"
        if k:   return "⚠️  검토 필요"
        return "✅ 통과"

    lines: List[str] = []

    # ━━ 헤더 ━━
    lines += [
        "# KCMVP 사전 적합성 분석 보고서",
        "",
        f"**분석 대상**: {algo} | **운영 모드**: {mode}  ",
        f"**분석 일시**: {today}  ",
        f"**소스 파일**: {total_files}개",
        "",
        "---",
        "",
    ]

    # ━━ 종합 판정 테이블 ━━
    total_confirmed = summary.get("confirmed", 0)
    total_review = summary.get("review", 0)
    total_candidate = summary.get("candidate", 0)
    total_low_candidate = max(0, total_candidate - total_review)
    overall = _verdict(total_confirmed, total_review, total_low_candidate)

    lines += [
        "## 종합 판정",
        "",
        "| 카테고리 | 확정 위반 | 검토 권고 | 낮은 신뢰도 후보 | 판정 |",
        "|----------|:---------:|:---------:|:---------------:|:----:|",
    ]
    for cat in _CATEGORY_ORDER:
        c_n = len(cat_data[cat]["confirmed"])
        r_n = len(cat_data[cat]["review"])
        k_n = len(cat_data[cat]["candidate"])
        if c_n == 0 and r_n == 0 and k_n == 0:
            continue
        label   = _CATEGORY_META[cat]["label"]
        abbr    = _CATEGORY_META[cat]["abbr"]
        verdict = _verdict(c_n, r_n, k_n)
        c_str   = f"**{c_n}건**" if c_n else f"{c_n}건"
        lines.append(f"| {label} ({abbr}) | {c_str} | {r_n}건 | {k_n}건 | {verdict} |")

    lines += [
        f"| **합계** | **{total_confirmed}건** | **{total_review}건** | **{total_low_candidate}건** | **{overall}** |",
        "",
        "---",
        "",
    ]

    # ━━ AI 종합 평가 ━━
    if ai_summary:
        lines += [
            "## AI 종합 평가",
            "",
            ai_summary,
            "",
            "---",
            "",
        ]

    # ━━ 카테고리별 상세 ━━
    section_num = 1
    for cat in _CATEGORY_ORDER:
        c_list = cat_data[cat]["confirmed"]
        r_list = cat_data[cat]["review"]
        k_list = cat_data[cat]["candidate"]
        all_v  = c_list + r_list + k_list
        if not all_v:
            continue

        label   = _CATEGORY_META[cat]["label"]
        abbr    = _CATEGORY_META[cat]["abbr"]
        verdict = _verdict(len(c_list), len(r_list), len(k_list))

        lines += [
            f"## {section_num}. {label} ({abbr})  {verdict}",
            "",
        ]
        section_num += 1

        # 파일별 그룹
        by_file: Dict[str, list] = defaultdict(list)
        for v in all_v:
            by_file[v.get("file") or "(알 수 없음)"].append(v)

        for file_path, file_violations in sorted(by_file.items()):
            fname = file_path.split("/")[-1] if "/" in file_path else file_path
            lines += [
                f"#### `{fname}`",
                "",
                "| 규칙 | 판정 | 위치 | 설명 |",
                "|------|:----:|------|------|",
            ]
            for v in sorted(file_violations, key=lambda x: (x.get("line") or 0)):
                rule_id    = v.get("rule_id", "")
                conf       = _confidence(v)
                conf_badge = "**확정**" if conf == "확정" else conf
                line_no    = v.get("line")
                pt_v       = (v.get("pattern_type") or "").lower()
                if line_no:
                    loc = f"{line_no}번 줄"
                elif pt_v == "missing":
                    loc = "항목 부재"
                else:
                    loc = "파일 수준"
                msg        = v.get("message", "")
                lines.append(f"| {rule_id} | {conf_badge} | {loc} | {msg} |")
            lines.append("")

    # ━━ 수정 필요 파일 요약 ━━
    if total_confirmed:
        lines += [
            "---",
            "",
            "## 수정 필요 파일 (확정 위반 기준)",
            "",
            "| 파일 | 확정 위반 | 위반 후보 | 대표 규칙 |",
            "|------|:---------:|:---------:|----------|",
        ]
        file_stats: Dict[str, Dict] = defaultdict(
            lambda: {"confirmed": 0, "candidate": 0, "rules": []}
        )
        for v in violations:
            fname = (v.get("file") or "(알 수 없음)").split("/")[-1]
            if _confidence(v) == "확정":
                file_stats[fname]["confirmed"] += 1
                rid = v.get("rule_id", "")
                if rid and rid not in file_stats[fname]["rules"]:
                    file_stats[fname]["rules"].append(rid)
            else:
                file_stats[fname]["candidate"] += 1

        for fname, stats in sorted(
            file_stats.items(), key=lambda x: -x[1]["confirmed"]
        ):
            if stats["confirmed"] == 0:
                continue
            top = ", ".join(stats["rules"][:3])
            if len(stats["rules"]) > 3:
                top += f" 외 {len(stats['rules']) - 3}건"
            lines.append(
                f"| `{fname}` | {stats['confirmed']}건 | {stats['candidate']}건 | {top} |"
            )

        lines += [
            "",
            "> 세부 수정 방법: `patches/` 폴더 참조",
            "",
        ]

    out = job_root / "report.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    return out


# ──────────────────────────────────────────────────────────────────────
# write_report_pdf  (Phase 3 — PyMuPDF 기반 PDF 보고서)
# ──────────────────────────────────────────────────────────────────────

_SEV_KR = {"high": "높음", "medium": "중간", "low": "낮음"}

# ── 한글 폰트 탐지 ──────────────────────────────────────────────────
import os as _os, sys as _sys

def _find_cjk_font() -> Optional[str]:
    """시스템에서 CJK(한글 포함) 폰트 경로 탐색."""
    candidates = []
    if _sys.platform == "darwin":  # macOS
        candidates = [
            "/Library/Fonts/AppleGothic.ttf",
            "/System/Library/Fonts/AppleSDGothicNeo.ttc",
            "/System/Library/Fonts/Supplemental/AppleGothic.ttf",
        ]
    candidates += [  # Linux 공통
        "/usr/share/fonts/truetype/nanum/NanumGothic.ttf",
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/google-noto-cjk/NotoSansCJK-Regular.ttc",
    ]
    for p in candidates:
        if _os.path.isfile(p):
            return p
    return None

_CJK_FONT_PATH: Optional[str] = _find_cjk_font()


def write_report_pdf(job_root: Path, report_obj: Dict[str, Any]) -> Path:
    """
    violations + summary + meta → A4 PDF 보고서 생성.

    PyMuPDF(fitz)를 사용하며, 패키지가 없으면 ImportError를 그대로 전파.
    한글 폰트가 시스템에 없으면 ASCII 라벨로 Fallback.
    생성된 PDF는 job_root/report.pdf 에 저장됩니다.
    """
    import fitz  # PyMuPDF

    violations = report_obj.get("violations", [])
    summary    = report_obj.get("summary", {})
    meta       = report_obj.get("meta", {})
    ai_summary = report_obj.get("ai_summary") or ""

    # ── 색상 팔레트 ──────────────────────────────────────────────────
    C_BLACK  = (0.08, 0.08, 0.08)
    C_GRAY   = (0.45, 0.45, 0.45)
    C_BLUE   = (0.13, 0.34, 0.65)
    C_RED    = (0.75, 0.10, 0.10)
    C_AMBER  = (0.70, 0.40, 0.00)
    C_GREEN  = (0.05, 0.50, 0.20)
    C_LIGHT  = (0.95, 0.95, 0.97)  # 헤더 배경

    PAGE_W, PAGE_H = 595, 842  # A4 pt
    MARGIN_L, MARGIN_R = 48, 48
    MARGIN_T, MARGIN_B = 60, 48
    BODY_W = PAGE_W - MARGIN_L - MARGIN_R

    # ── CJK 폰트 로드 ──────────────────────────────────────────────
    _ko_font = None
    if _CJK_FONT_PATH:
        try:
            _ko_font = fitz.Font(fontfile=_CJK_FONT_PATH)
        except Exception as _fe:
            print(f"[PDF] CJK 폰트 로드 실패: {_fe}")

    doc = fitz.open()

    def new_page():
        return doc.new_page(width=PAGE_W, height=PAGE_H)

    def _text(page, x, y, text, size=10, color=C_BLACK, bold=False):
        """텍스트 삽입. CJK 폰트 있으면 TextWriter 사용, 없으면 Helvetica(ASCII only)."""
        if not text:
            return
        if _ko_font:
            tw = fitz.TextWriter(page.rect, color=color)
            try:
                tw.append((x, y), text, font=_ko_font, fontsize=size)
                tw.write_text(page)
                return
            except Exception:
                pass  # fallback to built-in
        # ASCII fallback
        safe = text.encode("ascii", errors="replace").decode("ascii")
        font = "Helvetica" if not bold else "Helvetica-Bold"
        page.insert_text((x, y), safe, fontname=font, fontsize=size, color=color)

    def _rect_fill(page, rect, color):
        page.draw_rect(fitz.Rect(rect), color=None, fill=color, width=0)

    def _hrule(page, y, color=C_LIGHT):
        page.draw_line((MARGIN_L, y), (PAGE_W - MARGIN_R, y), color=color, width=0.8)

    # ── 표지 + 요약 ──────────────────────────────────────────────────
    page = new_page()
    y = MARGIN_T

    # 헤더 배경
    _rect_fill(page, (0, 0, PAGE_W, 80), C_BLUE)
    _text(page, MARGIN_L, 32, "KCMVP 사전 검증 보고서", size=18, color=(1, 1, 1), bold=True)
    _text(page, MARGIN_L, 55, "Korea Cryptographic Module Validation Program",
          size=9, color=(0.8, 0.9, 1.0))

    y = 96
    algo = meta.get("algorithm") or "미지정"
    mode = meta.get("mode") or "미지정"
    dt   = meta.get("date") or str(date.today())
    fc   = meta.get("file_count") or 0
    _text(page, MARGIN_L, y, f"생성일: {dt}   알고리즘: {algo}   운영모드: {mode}   파일 수: {fc}",
          size=9, color=C_GRAY)
    y += 20
    _hrule(page, y)
    y += 14

    # 판정 결과
    confirmed  = summary.get("confirmed", 0)
    review     = summary.get("review", 0)
    candidate  = summary.get("candidate", 0)
    low_candidate = max(0, candidate - review)
    high       = summary.get("confirmed_high", 0) or summary.get("high", 0)
    medium     = summary.get("confirmed_medium", 0) or summary.get("medium", 0)
    low        = summary.get("confirmed_low", 0) or summary.get("low", 0)

    if confirmed > 0:
        verdict_txt, verdict_color = "불합격 (FAIL)", C_RED
    elif review > 0:
        verdict_txt, verdict_color = "검토 권고 (REVIEW)", C_BLUE
    elif candidate > 0:
        verdict_txt, verdict_color = "검토 필요 (REVIEW)", C_AMBER
    else:
        verdict_txt, verdict_color = "통과 (PASS)", C_GREEN

    _text(page, MARGIN_L, y, "종합 판정", size=12, bold=True, color=C_BLUE)
    y += 16
    _rect_fill(page, (MARGIN_L, y, MARGIN_L + 200, y + 22), (*verdict_color, 0.12))
    page.draw_rect(fitz.Rect(MARGIN_L, y, MARGIN_L + 200, y + 22),
                   color=verdict_color, width=0.8)
    _text(page, MARGIN_L + 8, y + 15, verdict_txt, size=13, color=verdict_color, bold=True)
    y += 32

    # 통계 카드
    stats = [
        ("확정 위반", confirmed, C_RED),
        ("검토 권고", review, C_BLUE),
        ("위반 후보", low_candidate, C_AMBER),
        ("HIGH",  high,   C_RED),
        ("MEDIUM", medium, C_AMBER),
        ("LOW",   low,    C_GRAY),
    ]
    card_w = (BODY_W - 8 * (len(stats) - 1)) / len(stats)
    for i, (label, val, col) in enumerate(stats):
        cx = MARGIN_L + i * (card_w + 8)
        _rect_fill(page, (cx, y, cx + card_w, y + 42), C_LIGHT)
        page.draw_rect(fitz.Rect(cx, y, cx + card_w, y + 42), color=col, width=0.8)
        _text(page, cx + card_w / 2 - 8, y + 14, str(val), size=16, color=col, bold=True)
        _text(page, cx + 4, y + 34, label, size=7, color=C_GRAY)
    y += 58

    # AI 종합 평가
    if ai_summary:
        _hrule(page, y)
        y += 12
        _text(page, MARGIN_L, y, "AI 종합 평가", size=11, bold=True, color=C_BLUE)
        y += 14
        for line_txt in ai_summary.splitlines()[:12]:
            stripped = line_txt.strip().lstrip("*#").strip()
            if not stripped:
                y += 4
                continue
            _text(page, MARGIN_L, y, stripped[:90], size=9, color=C_BLACK)
            y += 12
            if y > PAGE_H - MARGIN_B - 20:
                break
    y += 10
    _hrule(page, y)

    # ── 위반 목록 ────────────────────────────────────────────────────
    y += 18
    _text(page, MARGIN_L, y, "위반 상세 목록", size=12, bold=True, color=C_BLUE)
    y += 16

    # 테이블 헤더
    col_x = [MARGIN_L, MARGIN_L + 72, MARGIN_L + 118, MARGIN_L + 160,
              MARGIN_L + 210, MARGIN_L + 275]
    col_labels = ["규칙 ID", "심각도", "판정", "위치", "파일/문서", "설명"]

    def _draw_table_header(pg, yy):
        _rect_fill(pg, (MARGIN_L, yy - 10, PAGE_W - MARGIN_R, yy + 8), C_BLUE)
        for cx, lbl in zip(col_x, col_labels):
            _text(pg, cx + 2, yy + 4, lbl, size=8, color=(1, 1, 1), bold=True)

    _draw_table_header(page, y)
    y += 16

    row_h = 14
    for idx, v in enumerate(violations):
        if y > PAGE_H - MARGIN_B - row_h:
            _hrule(page, y)
            page = new_page()
            y = MARGIN_T
            _draw_table_header(page, y)
            y += 16

        # 줄무늬 배경
        if idx % 2 == 0:
            _rect_fill(page, (MARGIN_L, y - 9, PAGE_W - MARGIN_R, y + row_h - 9), C_LIGHT)

        rule_id = v.get("rule_id") or ""
        sev     = (v.get("severity") or "low").lower()
        sev_kr  = _SEV_KR.get(sev, sev)
        conf    = _confidence(v)
        line_no = v.get("line")
        pt      = (v.get("pattern_type") or "").lower()
        if line_no:
            loc = f"L{line_no}"
        elif pt == "missing":
            loc = "부재"
        else:
            loc = "전체"
        fname   = (v.get("file") or v.get("doc_type") or "-").split("/")[-1][:22]
        msg     = (v.get("message") or "")[:60]

        sev_color = C_RED if sev == "high" else (C_AMBER if sev == "medium" else C_GRAY)
        con_color = C_RED if conf == "확정" else C_AMBER

        _text(page, col_x[0] + 2, y, rule_id[:14], size=8, color=C_BLACK)
        _text(page, col_x[1] + 2, y, sev_kr, size=8, color=sev_color, bold=True)
        _text(page, col_x[2] + 2, y, conf, size=8, color=con_color, bold=True)
        _text(page, col_x[3] + 2, y, loc, size=8, color=C_GRAY)
        _text(page, col_x[4] + 2, y, fname, size=8, color=C_GRAY)
        _text(page, col_x[5] + 2, y, msg, size=8, color=C_BLACK)
        y += row_h

    # 푸터
    _text(page, MARGIN_L, PAGE_H - 28,
          f"KCMVP Pre-Validation Report  |  {dt}  |  Total: {len(violations)}",
          size=8, color=C_GRAY)

    pdf_path = job_root / "report.pdf"
    doc.save(str(pdf_path))
    doc.close()
    return pdf_path


# ──────────────────────────────────────────────────────────────────────
# save_patch
# ──────────────────────────────────────────────────────────────────────

def save_patch(job_root: Path, rule_id: str, file_name: str, line: int, content: str) -> Path:
    patches_dir = job_root / "patches"
    patches_dir.mkdir(parents=True, exist_ok=True)
    safe = file_name.replace("/", "_").replace("\\", "_")
    path = patches_dir / f"{rule_id}-{safe}-{line}.md"
    path.write_text(content, encoding="utf-8")
    return path
