"""
가짜 설계서 마크다운 → PDF 변환 스크립트 (reportlab 사용)
한국어 폰트: 시스템 폰트 사용
"""
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib import colors
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
import os, re

# ── 한국어 폰트 등록 ──────────────────────────────────────────────
FONT_PATHS = [
    "/System/Library/Fonts/Supplemental/AppleGothic.ttf",
    "/Library/Fonts/AppleGothic.ttf",
    "/usr/share/fonts/truetype/nanum/NanumGothic.ttf",
    "/System/Library/Fonts/AppleSDGothicNeo.ttc",
]
FONT_NAME = "Korean"
for fp in FONT_PATHS:
    if os.path.exists(fp):
        try:
            pdfmetrics.registerFont(TTFont(FONT_NAME, fp))
            print(f"폰트 등록: {fp}")
            break
        except Exception:
            continue
else:
    FONT_NAME = "Helvetica"
    print("한국어 폰트 없음 → Helvetica 사용 (한글 깨질 수 있음)")

# ── 스타일 정의 ───────────────────────────────────────────────────
def make_styles():
    styles = {}
    base = {"fontName": FONT_NAME, "leading": 16}

    styles["h1"] = ParagraphStyle("h1", fontName=FONT_NAME, fontSize=16,
                                   leading=22, spaceAfter=12, spaceBefore=16,
                                   textColor=colors.HexColor("#0F2854"), bold=True)
    styles["h2"] = ParagraphStyle("h2", fontName=FONT_NAME, fontSize=13,
                                   leading=18, spaceAfter=8, spaceBefore=14,
                                   textColor=colors.HexColor("#1a3a6e"), bold=True)
    styles["h3"] = ParagraphStyle("h3", fontName=FONT_NAME, fontSize=11,
                                   leading=16, spaceAfter=6, spaceBefore=10,
                                   textColor=colors.HexColor("#2c5f9e"), bold=True)
    styles["body"] = ParagraphStyle("body", fontName=FONT_NAME, fontSize=9,
                                     leading=15, spaceAfter=4)
    styles["bullet"] = ParagraphStyle("bullet", fontName=FONT_NAME, fontSize=9,
                                       leading=15, leftIndent=12, spaceAfter=2,
                                       bulletIndent=4)
    styles["code"] = ParagraphStyle("code", fontName="Courier", fontSize=8,
                                     leading=12, leftIndent=16, spaceAfter=4,
                                     backColor=colors.HexColor("#f5f5f5"),
                                     borderPadding=4)
    styles["note"] = ParagraphStyle("note", fontName=FONT_NAME, fontSize=9,
                                     leading=14, leftIndent=8, spaceAfter=6,
                                     textColor=colors.HexColor("#cc0000"),
                                     backColor=colors.HexColor("#fff3f3"),
                                     borderPadding=4)
    return styles

# ── 마크다운 파싱 및 PDF 빌드 ─────────────────────────────────────
def md_to_pdf(md_path: str, pdf_path: str):
    styles = make_styles()
    story = []

    with open(md_path, encoding="utf-8") as f:
        lines = f.readlines()

    i = 0
    table_rows = []
    in_table = False
    in_code = False
    code_lines = []

    def flush_table():
        nonlocal table_rows
        if not table_rows:
            return
        # 구분선 행 제거 (|---|---|)
        clean = [r for r in table_rows if not re.match(r"^\s*\|[-| :]+\|\s*$", r)]
        if not clean:
            table_rows = []
            return
        data = []
        for row in clean:
            cells = [c.strip() for c in row.strip().strip("|").split("|")]
            data.append([Paragraph(c, styles["body"]) for c in cells])
        col_count = max(len(r) for r in data)
        col_width = (A4[0] - 40*mm) / col_count
        tbl = Table(data, colWidths=[col_width]*col_count)
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#dbe4f0")),
            ("FONTNAME",   (0,0), (-1,-1), FONT_NAME),
            ("FONTSIZE",   (0,0), (-1,-1), 8),
            ("GRID",       (0,0), (-1,-1), 0.5, colors.HexColor("#bbbbbb")),
            ("VALIGN",     (0,0), (-1,-1), "TOP"),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#f7f9fd")]),
        ]))
        story.append(tbl)
        story.append(Spacer(1, 4))
        table_rows = []

    while i < len(lines):
        line = lines[i].rstrip("\n")

        # 코드 블록
        if line.startswith("```"):
            if not in_code:
                in_code = True
                code_lines = []
            else:
                in_code = False
                code_text = "\n".join(code_lines)
                # HTML 이스케이프
                code_text = code_text.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
                story.append(Paragraph(code_text.replace("\n","<br/>"), styles["code"]))
                story.append(Spacer(1, 4))
            i += 1
            continue

        if in_code:
            code_lines.append(line)
            i += 1
            continue

        # 표 행
        if line.startswith("|"):
            if not in_table:
                flush_table()
                in_table = True
                table_rows = []
            table_rows.append(line)
            i += 1
            continue
        else:
            if in_table:
                flush_table()
                in_table = False

        # 구분선
        if line.startswith("---"):
            story.append(HRFlowable(width="100%", thickness=0.5,
                                     color=colors.HexColor("#cccccc"), spaceAfter=6))
            i += 1
            continue

        # 제목
        if line.startswith("### "):
            text = line[4:].strip()
            story.append(Paragraph(text, styles["h3"]))
        elif line.startswith("## "):
            text = line[3:].strip()
            story.append(Paragraph(text, styles["h2"]))
        elif line.startswith("# "):
            text = line[2:].strip()
            story.append(Paragraph(text, styles["h1"]))
            story.append(HRFlowable(width="100%", thickness=1.5,
                                     color=colors.HexColor("#0F2854"), spaceAfter=8))

        # 불릿
        elif line.startswith("- ") or line.startswith("* "):
            text = line[2:].strip()
            text = re.sub(r"\*\*(.*?)\*\*", r"<b>\1</b>", text)
            story.append(Paragraph(f"• {text}", styles["bullet"]))

        # 의도적 위반 표시 (※ 포함)
        elif "의도적 위반" in line or line.startswith("※"):
            text = line.strip()
            text = re.sub(r"\*\*(.*?)\*\*", r"<b>\1</b>", text)
            text = text.replace("&", "&amp;").replace("<b>", "<b>").replace("</b>", "</b>")
            story.append(Paragraph(text, styles["note"]))

        # 빈 줄
        elif line.strip() == "":
            story.append(Spacer(1, 4))

        # 일반 텍스트
        else:
            text = line.strip()
            if not text:
                i += 1
                continue
            # 볼드 처리
            text = re.sub(r"\*\*(.*?)\*\*", r"<b>\1</b>", text)
            text = text.replace("`", "")
            try:
                story.append(Paragraph(text, styles["body"]))
            except Exception:
                story.append(Paragraph(text.encode("ascii","replace").decode(), styles["body"]))

        i += 1

    # 남은 표 처리
    flush_table()

    # PDF 생성
    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=A4,
        leftMargin=20*mm, rightMargin=20*mm,
        topMargin=20*mm, bottomMargin=20*mm,
    )
    doc.build(story)
    print(f"✅ PDF 생성 완료: {pdf_path}")


if __name__ == "__main__":
    base = os.path.dirname(os.path.abspath(__file__))
    md_path  = os.path.join(base, "fake_design_doc.md")
    pdf_path = os.path.join(base, "fake_design_doc.pdf")
    md_to_pdf(md_path, pdf_path)
    size_kb = os.path.getsize(pdf_path) // 1024
    print(f"   파일 크기: {size_kb} KB")
