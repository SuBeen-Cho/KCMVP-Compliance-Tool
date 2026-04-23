"""
DOC 정확도 테스트 v2 — 실제 설계서 수준 PDF 생성기
=====================================================
KCMVP 제출물 작성 안내서(2025.9.) 기준 구조를 따르는 상세 문서 생성.
- design_pass.pdf  : 55개 DOC 규칙 전부 충족 (~40p), 일부 경계 케이스 포함
- design_fail.pdf  : 핵심 규칙 의도적 누락 (~10p)
- config_pass.pdf  : 4개 CM 규칙 충족 (~8p)
- test_pass.pdf    : 5개 TEST 규칙 충족 (~10p)

2-pass 빌드로 TOC 페이지 번호 정확성 보장.
"""

import io, os, sys, zipfile
from pathlib import Path
from typing import List, Tuple

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm, mm
from reportlab.platypus import (
    BaseDocTemplate, Frame, HRFlowable, PageBreak, PageTemplate,
    Paragraph, Spacer, Table, TableStyle,
)
from reportlab.platypus.tableofcontents import TableOfContents

# ── 한국어 폰트 등록 ─────────────────────────────────────────────
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

FONT_CANDIDATES = [
    "/Library/Fonts/Arial Unicode.ttf",
    "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
    "/usr/share/fonts/truetype/nanum/NanumGothic.ttf",
]
KO_FONT = "Arial Unicode"
for fc in FONT_CANDIDATES:
    if os.path.exists(fc):
        pdfmetrics.registerFont(TTFont(KO_FONT, fc))
        break

W, H = A4

# ── 스타일 정의 ──────────────────────────────────────────────────
def _make_styles():
    base = getSampleStyleSheet()
    def S(name, parent="Normal", **kw):
        kw.setdefault("fontName", KO_FONT)
        return ParagraphStyle(name, parent=base[parent], **kw)

    return {
        "cover_title":  S("cover_title",  fontSize=22, leading=30, alignment=TA_CENTER, spaceAfter=10),
        "cover_sub":    S("cover_sub",    fontSize=14, leading=20, alignment=TA_CENTER, spaceAfter=6),
        "cover_meta":   S("cover_meta",   fontSize=11, leading=16, alignment=TA_CENTER, spaceAfter=4),
        "h1":           S("h1",           fontSize=15, leading=20, spaceBefore=16, spaceAfter=6, textColor=colors.HexColor("#1a3a6b")),
        "h2":           S("h2",           fontSize=13, leading=18, spaceBefore=12, spaceAfter=4, textColor=colors.HexColor("#2a5298")),
        "h3":           S("h3",           fontSize=11, leading=16, spaceBefore=8,  spaceAfter=3, textColor=colors.HexColor("#3a6abf")),
        "body":         S("body",         fontSize=10, leading=15, spaceAfter=4),
        "body_indent":  S("body_indent",  fontSize=10, leading=15, spaceAfter=4, leftIndent=12),
        "bullet":       S("bullet",       fontSize=10, leading=14, spaceAfter=2, leftIndent=16, bulletIndent=4),
        "table_header": S("table_header", fontSize=9,  leading=13, alignment=TA_CENTER, textColor=colors.white),
        "table_cell":   S("table_cell",   fontSize=9,  leading=13),
        "table_cell_c": S("table_cell_c", fontSize=9,  leading=13, alignment=TA_CENTER),
        "caption":      S("caption",      fontSize=8,  leading=12, alignment=TA_CENTER, textColor=colors.grey),
        "toc_h1":       S("toc_h1",       fontSize=11, leading=16, spaceAfter=2),
        "toc_h2":       S("toc_h2",       fontSize=10, leading=14, leftIndent=16, spaceAfter=1),
        "footer":       S("footer",       fontSize=8,  leading=10, alignment=TA_CENTER, textColor=colors.grey),
    }

ST = _make_styles()

# ── 테이블 공통 헬퍼 ─────────────────────────────────────────────
HDR_BG  = colors.HexColor("#1a3a6b")
ALT_BG  = colors.HexColor("#eef2f8")
GRID_C  = colors.HexColor("#b0bcd0")

def _tbl(data, col_widths, hdr_rows=1):
    """헤더 포함 테이블 생성."""
    tbl = Table(data, colWidths=col_widths, repeatRows=hdr_rows)
    n = len(data)
    style = [
        ("BACKGROUND", (0, 0), (-1, hdr_rows - 1), HDR_BG),
        ("TEXTCOLOR",  (0, 0), (-1, hdr_rows - 1), colors.white),
        ("FONTNAME",   (0, 0), (-1, -1), KO_FONT),
        ("FONTSIZE",   (0, 0), (-1, -1), 9),
        ("ALIGN",      (0, 0), (-1, -1), "LEFT"),
        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
        ("GRID",       (0, 0), (-1, -1), 0.5, GRID_C),
        ("ROWBACKGROUNDS", (0, hdr_rows), (-1, -1), [colors.white, ALT_BG]),
        ("TOPPADDING",  (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",(0, 0), (-1, -1), 6),
    ]
    tbl.setStyle(TableStyle(style))
    return tbl

def P(text, style="body"): return Paragraph(text, ST[style])
def SP(n=6):               return Spacer(1, n)
def HR():                   return HRFlowable(width="100%", thickness=0.5, color=GRID_C, spaceAfter=4)

# ── 2-pass DocTemplate ────────────────────────────────────────────
class KcmvpDoc(BaseDocTemplate):
    """TOC 자동 생성을 위한 2-pass 빌드 지원."""
    def __init__(self, path, title="", **kw):
        BaseDocTemplate.__init__(self, path, pagesize=A4,
            leftMargin=2.5*cm, rightMargin=2.5*cm,
            topMargin=2.5*cm,  bottomMargin=2.5*cm, **kw)
        self._title = title
        frame = Frame(self.leftMargin, self.bottomMargin,
                      self.width, self.height, id="main")
        tmpl = PageTemplate(id="main", frames=[frame],
                            onPage=self._draw_page)
        self.addPageTemplates([tmpl])

    def _draw_page(self, canvas, doc):
        canvas.saveState()
        # 페이지 번호 (표지 제외)
        if doc.page > 1:
            canvas.setFont(KO_FONT, 8)
            canvas.setFillColor(colors.grey)
            canvas.drawCentredString(W / 2, 1.2*cm,
                f"{self._title}  |  {doc.page - 1}")  # 표지 제외
        canvas.restoreState()

    def afterFlowable(self, flowable):
        """TOC 항목 등록 (Heading1, Heading2 스타일)."""
        if not isinstance(flowable, Paragraph):
            return
        sname = flowable.style.name
        text  = flowable.getPlainText()
        if sname == "h1":
            self.notify("TOCEntry", (0, text, self.page))
        elif sname == "h2":
            self.notify("TOCEntry", (1, text, self.page))


# ── 공통 표지 ────────────────────────────────────────────────────
def _cover(title, subtitle, version, date, doc_no) -> List:
    return [
        SP(60),
        P(title, "cover_title"),
        SP(8),
        P(subtitle, "cover_sub"),
        SP(40),
        P(f"문서 번호: {doc_no}", "cover_meta"),
        P(f"버전: {version}", "cover_meta"),
        P(f"작성일: {date}", "cover_meta"),
        P("기관명: KCMVP 테스트 연구소", "cover_meta"),
        PageBreak(),
    ]


# ══════════════════════════════════════════════════════════════════
#  design_pass.pdf  (55개 DOC 규칙 전부 충족, ~40p)
# ══════════════════════════════════════════════════════════════════
def build_design_pass(path: str):
    doc = KcmvpDoc(path, title="기본설계서")

    toc = TableOfContents()
    toc.levelStyles = [ST["toc_h1"], ST["toc_h2"]]
    toc.dotsMinLevel = 0

    story: List = []

    # ── 표지 ──────────────────────────────────────────────────────
    story += _cover(
        "LEA Crypto Library", "기본 및 상세 설계서",
        "v1.0", "2025-09-01", "KCMVP-DSG-2025-001",
    )

    # ── 목차 ──────────────────────────────────────────────────────
    story.append(P("목 차", "h1"))
    story.append(toc)
    story.append(PageBreak())

    # ── 1. 개요 ───────────────────────────────────────────────────
    story.append(P("1. 개요", "h1"))
    story.append(P("1.1 목적", "h2"))
    story.append(P(
        "본 문서는 LEA Crypto Library 암호모듈의 기본 및 상세 설계서로서, "
        "국가 암호모듈 검증 프로그램(KCMVP) KS X ISO/IEC 19790 요건에 따라 "
        "암호모듈의 구조, 인터페이스, 역할, 보안매개변수 관리 및 자가시험 방법을 기술한다.",
        "body"))
    story.append(P("1.2 적용 범위", "h2"))
    story.append(P(
        "본 설계서는 LEA Crypto Library v1.0(이하 '본 모듈')에 적용되며, "
        "소프트웨어 암호모듈로 분류된다. 적용 표준은 다음과 같다.",
        "body"))
    story.append(_tbl(
        [["표준 번호", "표준명"],
         ["KS X ISO/IEC 19790", "정보기술 - 보안기법 - 암호모듈 보안 요구사항"],
         ["KS X ISO/IEC 24759", "정보기술 - 보안기법 - 암호모듈 시험 요건"],
         ["KS X 3246:2016",     "128비트 블록암호 LEA"],
         ["TTAKKO-12.0271",     "블록암호 LEA 운영모드 표준"]],
        [5*cm, 10*cm]))
    story.append(SP())
    story.append(P("1.3 용어 정의", "h2"))
    story.append(_tbl(
        [["용어", "정의"],
         ["CSP (Critical Security Parameter)", "암호모듈 보안에 중요한 정보(키, IV 등)"],
         ["PSP (Public Security Parameter)",   "공개 가능한 보안 매개변수"],
         ["SSP (Secret Security Parameter)",   "비밀 보안 매개변수"],
         ["KAT (Known Answer Test)",            "알려진 답을 이용한 알고리즘 검증 시험"],
         ["MCT (Monte Carlo Test)",             "몬테카를로 반복 연산 기반 시험"]],
        [6*cm, 9*cm]))
    story.append(PageBreak())

    # ── 2. 암호모듈 명세 ──────────────────────────────────────────
    story.append(P("2. 암호모듈 명세", "h1"))

    story.append(P("2.1 암호모듈 유형 및 판단근거", "h2"))  # DOC-001
    story.append(P(
        "본 모듈은 <b>소프트웨어 암호모듈</b>로 분류된다. "
        "물리적 경계가 없는 순수 소프트웨어 구현으로, "
        "운영체제 위에서 동적 라이브러리(.so/.dll) 형태로 동작하며 "
        "KS X ISO/IEC 19790 4.1항 소프트웨어 암호모듈 정의를 충족한다.",
        "body"))
    story.append(SP())

    story.append(P("2.2 암호모듈 경계 및 구성요소", "h2"))  # DOC-002
    story.append(P(
        "암호모듈 경계는 <b>lea_crypto.so 단일 동적 공유 라이브러리</b>이다. "
        "모듈 경계 내부에는 암호 알고리즘 구현, 키 관리, 자가시험 루틴이 포함되며, "
        "운영체제 시스템 콜 및 외부 라이브러리는 경계 외부에 있다. "
        "구성요소는 다음과 같다.",
        "body"))
    story.append(_tbl(
        [["구성요소", "설명", "경계 내/외"],
         ["LEA 알고리즘 엔진",     "LEA-128/192/256 암복호화 및 키 스케줄", "경계 내"],
         ["운영모드 처리기",       "CBC, CTR, GCM, CCM, CMAC, ECB, OFB, CFB", "경계 내"],
         ["키 관리 모듈",          "키 생성, 저장, 제로화 관리", "경계 내"],
         ["자가시험 모듈",         "전원인가 KAT, 연속 RNG 시험, 무결성 시험", "경계 내"],
         ["엔트로피 소스 인터페이스", "OS /dev/urandom 연결 인터페이스", "경계 내"],
         ["운영체제 커널",         "프로세스 관리, 메모리 보호", "경계 외"]],
        [4.5*cm, 6.5*cm, 3*cm]))
    story.append(SP())

    story.append(P("2.3 암호모듈 명칭 및 버전 정보", "h2"))  # DOC-004
    story.append(P(
        "암호모듈 명칭은 <b>LEA Crypto Library</b>이며, 버전 정보는 <b>v1.0</b>이다. "
        "버전 정보는 lea_module_version() API를 통해 외부에 제공된다. "
        "버전 체계는 Major.Minor 형식을 따른다.",
        "body"))
    story.append(SP())

    story.append(P("2.4 검증대상 암호알고리즘 및 핵심보안매개변수(CSP) 명세", "h2"))  # DOC-003, DOC-007
    story.append(P(
        "탑재된 검증대상 암호알고리즘 목록 및 해당 알고리즘이 사용하는 "
        "핵심보안매개변수(CSP)는 다음 표와 같다. "
        "핵심보안매개변수(CSP)에는 암호키, 라운드키, IV, 난수 시드가 포함된다.",
        "body"))
    story.append(_tbl(
        [["알고리즘", "키 길이(비트)", "운영모드", "CSP 명칭", "비고"],
         ["LEA", "128",         "CBC, CTR, GCM, CCM\nCMAC, ECB, OFB, CFB", "LEA 암호키\n라운드키 (11개)", "KS X 3246"],
         ["LEA", "192",         "CBC, CTR, GCM, CCM\nCMAC, ECB, OFB, CFB", "LEA 암호키\n라운드키 (13개)", "KS X 3246"],
         ["LEA", "256",         "CBC, CTR, GCM, CCM\nCMAC, ECB, OFB, CFB", "LEA 암호키\n라운드키 (15개)", "KS X 3246"],
         ["RNG", "256",         "CTR_DRBG",               "엔트로피 시드\nRNG 상태값",    "NIST SP 800-90A"]],
        [2.5*cm, 3*cm, 4*cm, 3.5*cm, 2*cm]))
    story.append(SP())

    story.append(P("2.5 비검증대상 암호알고리즘 명세", "h2"))  # DOC-008
    story.append(P(
        "다음 알고리즘은 비검증대상이며, 검증대상 알고리즘과 <b>논리적으로 완전히 분리</b>되어 동작한다. "
        "비검증대상 암호알고리즘은 별도의 공유 라이브러리(libssl.so)에 위치하며 "
        "본 모듈 경계 외부에서 호출된다. 두 모듈 간 메모리 공간 및 키 공유는 없으며, "
        "검증대상 동작에 관련이 없고 영향을 미치지 않는다.",
        "body"))
    story.append(_tbl(
        [["알고리즘", "용도", "분리 방식"],
         ["HMAC-SHA256", "소프트웨어 무결성 검증키 보호", "모듈 경계 외부, libssl.so 사용"],
         ["SHA-256",     "해시 다이제스트 생성",          "모듈 경계 외부, libssl.so 사용"]],
        [3*cm, 5.5*cm, 6.5*cm]))
    story.append(SP())

    story.append(P("2.6 검증대상 동작모드 실행 및 천이", "h2"))  # DOC-006
    story.append(P(
        "각 동작모드는 초기화(Init) → 업데이트(Update) → 완료(Final) 3단계 API 시퀀스를 따른다. "
        "모드 간 천이는 허용되지 않으며, 단일 컨텍스트 객체는 하나의 모드에 귀속된다. "
        "모드별 상태 천이 조건은 다음과 같다.",
        "body"))
    story.append(_tbl(
        [["동작모드", "Init API",             "Update API",          "Final API"],
         ["CBC",  "lea_cbc_init()",       "lea_cbc_update()",    "lea_cbc_final()"],
         ["CTR",  "lea_ctr_init()",       "lea_ctr_update()",    "lea_ctr_final()"],
         ["GCM",  "lea_gcm_init()",       "lea_gcm_update()",    "lea_gcm_final()"],
         ["CCM",  "lea_ccm_init()",       "lea_ccm_update()",    "lea_ccm_final()"],
         ["CMAC", "lea_cmac_init()",      "lea_cmac_update()",   "lea_cmac_final()"],
         ["ECB",  "lea_ecb_init()",       "-",                   "lea_ecb_process()"]],
        [2.5*cm, 4.5*cm, 4.5*cm, 4.5*cm]))
    story.append(PageBreak())

    # ── 3. 인터페이스 명세 ────────────────────────────────────────
    story.append(P("3. 인터페이스 명세", "h1"))

    story.append(P("3.1 물리적 포트 및 논리적 인터페이스", "h2"))  # DOC-011
    story.append(P(
        "본 모듈은 소프트웨어 모듈이므로 물리적 포트는 존재하지 않는다. "
        "논리적 인터페이스는 <b>API 함수 호출</b> 방식으로 구성되며 다음과 같이 분류된다.",
        "body"))
    story.append(_tbl(
        [["논리적 인터페이스", "유형", "설명"],
         ["데이터 입력 인터페이스",   "함수 파라미터 (입력)", "평문, 암호문, 키, IV, AAD"],
         ["데이터 출력 인터페이스",   "함수 파라미터 (출력)", "암호문, 평문, 태그, MAC"],
         ["제어 입력 인터페이스",     "함수 파라미터 (입력)", "알고리즘 ID, 운영모드, 키 길이"],
         ["상태 출력 인터페이스",     "반환값",              "0(정상), -1(오류코드)"],
         ["전원 입력 인터페이스",     "프로세스 시작/종료",  "동적 라이브러리 로드/언로드"]],
        [4.5*cm, 3.5*cm, 7*cm]))
    story.append(SP())

    story.append(P("3.2 서비스별 논리적 인터페이스 상세 명세", "h2"))  # DOC-012
    story.append(P("각 서비스와 논리적 인터페이스의 대응 관계는 다음과 같다.", "body"))
    story.append(_tbl(
        [["서비스명", "API 함수", "입력 인터페이스", "출력 인터페이스"],
         ["LEA 암호화",     "lea_cbc_encrypt()", "평문, 키, IV, 길이",     "암호문, 반환값"],
         ["LEA 복호화",     "lea_cbc_decrypt()", "암호문, 키, IV, 길이",   "평문, 반환값"],
         ["GCM 인증 암호화","lea_gcm_encrypt()", "평문, 키, IV, AAD",      "암호문, 태그, 반환값"],
         ["키 생성",        "lea_keygen()",      "키 길이",                "키 버퍼, 반환값"],
         ["제로화",         "lea_zeroize()",     "컨텍스트 포인터",         "반환값"],
         ["자가시험",       "lea_selftest()",    "-",                      "반환값(0/−1)"],
         ["버전 조회",      "lea_module_version()", "-",                   "버전 문자열"]],
        [3*cm, 3.5*cm, 4.5*cm, 4*cm]))
    story.append(SP())

    story.append(P("3.3 특정 상태 시 입출력 금지 보장 메커니즘", "h2"))  # DOC-013
    story.append(P(
        "오류 상태 또는 미초기화 상태에서는 <b>데이터 출력 금지 및 제어 출력 금지</b>가 보장된다. "
        "출력 금지 메커니즘은 내부 상태 플래그(ctx->state)를 검사하여 INIT 상태가 아닌 경우 "
        "즉시 −1을 반환하고 데이터를 출력하지 않는 방식으로 구현된다. "
        "자가시험 실패 시 FIPS_ERROR 플래그가 설정되어 모든 암호 서비스 API가 −E_SELFTEST_FAIL을 반환한다.",
        "body"))
    story.append(SP())

    story.append(P("3.4 서비스 상태 표시기(Indicator) 및 오류 코드 체계", "h2"))  # DOC-010, DOC-014
    story.append(P(
        "모든 API 함수는 정수형 반환값으로 서비스 완료 상태를 표시한다. "
        "상태 출력(status indicator)은 반환값 0(정상) 또는 음수 오류코드로 구분된다.",
        "body"))
    story.append(_tbl(
        [["오류 코드",        "값",  "설명"],
         ["E_OK",            "0",   "정상 완료"],
         ["E_INIT_FAIL",     "-1",  "초기화 실패 (키 길이, 파라미터 오류)"],
         ["E_KEY_INVALID",   "-2",  "키 포인터 NULL 또는 키 길이 불일치"],
         ["E_DATA_INVALID",  "-3",  "입력 데이터 길이 0 또는 NULL"],
         ["E_AUTH_FAIL",     "-4",  "GCM/CCM 인증 태그 불일치"],
         ["E_SELFTEST_FAIL", "-5",  "자가시험 실패 (모든 서비스 차단)"],
         ["E_RNG_FAIL",      "-6",  "난수 발생기 오류"]],
        [4*cm, 2*cm, 9*cm]))
    story.append(SP())

    story.append(P("3.5 가변 길이 입력 및 데이터 형식 검증", "h2"))  # DOC-015
    story.append(P(
        "가변 길이 입력을 지원하는 모든 API는 입력 데이터 길이와 형식을 사전에 검증한다. "
        "ECB 모드는 16바이트 배수, CBC/CTR은 임의 길이(CTR: 패딩 없음), "
        "GCM/CCM은 최대 2^36 − 32 바이트를 허용한다. "
        "NULL 포인터, 0 길이, 범위 초과 입력은 E_DATA_INVALID로 거부된다.",
        "body"))
    story.append(SP())

    story.append(P("3.6 동시 운영자 지원 여부", "h2"))  # DOC-016
    story.append(P(
        "본 모듈은 <b>단일 운영자 환경</b>을 지원하며 동시 다중 운영자 접근은 지원하지 않는다. "
        "멀티스레드 환경에서는 호출자가 외부 뮤텍스로 직렬화해야 한다. "
        "단일 운영자 정책에 따라 별도의 세션 관리 메커니즘은 없다.",
        "body"))
    story.append(PageBreak())

    # ── 4. 역할, 서비스 및 인증 ──────────────────────────────────
    story.append(P("4. 역할, 서비스 및 인증", "h1"))

    story.append(P("4.1 역할 정의", "h2"))  # DOC-017
    story.append(P(
        "본 모듈은 <b>암호 관리자(Crypto Officer)</b>와 <b>일반 사용자(User)</b> "
        "두 가지 역할을 정의한다.",
        "body"))
    story.append(_tbl(
        [["역할",         "설명",                               "인증 방법"],
         ["암호 관리자\n(Crypto Officer)", "모듈 초기화, 키 로드, 자가시험 수행,\n설정 변경 권한 보유", "별도 인증 없음 (단일 운영자 환경)"],
         ["일반 사용자\n(User)",          "암호 연산 서비스(암호화/복호화/MAC 등)\n호출 권한만 보유", "별도 인증 없음 (단일 운영자 환경)"]],
        [3.5*cm, 7*cm, 4.5*cm]))
    story.append(SP())

    story.append(P("4.2 서비스별 인가된 역할 매핑", "h2"))  # DOC-018
    story.append(P("각 암호 서비스에 대한 인가된 역할(관리자/사용자)과 입출력을 매핑한다.", "body"))
    story.append(_tbl(
        [["서비스",          "API",                 "인가된 역할",  "입력", "출력"],
         ["모듈 초기화",     "lea_module_init()",   "암호 관리자",  "-",     "반환값"],
         ["키 로드",         "lea_set_key()",       "암호 관리자",  "키 버퍼, 키 길이", "반환값"],
         ["LEA 암호화",      "lea_*_encrypt()",     "사용자",       "평문, IV",   "암호문"],
         ["LEA 복호화",      "lea_*_decrypt()",     "사용자",       "암호문, IV", "평문"],
         ["버전 조회",       "lea_module_version()","사용자",       "-",          "버전"],
         ["상태 확인",       "lea_module_status()", "사용자",       "-",          "상태코드"],
         ["자가시험",        "lea_selftest()",      "암호 관리자",  "-",          "반환값"],
         ["제로화",          "lea_zeroize()",       "암호 관리자",  "컨텍스트 포인터", "반환값"]],
        [3*cm, 3.5*cm, 2.5*cm, 3*cm, 3*cm]))
    story.append(SP())

    story.append(P("4.3 버전 정보 출력 서비스", "h2"))  # DOC-019
    story.append(P(
        "lea_module_version() API를 통해 현재 모듈 버전 문자열을 반환한다. "
        "반환 형식: \"LEA Crypto Library v1.0 (Build 20250901)\". "
        "본 서비스는 인증 없이 사용자 역할로 호출 가능하다.",
        "body"))

    story.append(P("4.4 상태 표시 및 확인 서비스", "h2"))  # DOC-020
    story.append(P(
        "lea_module_status() API는 현재 모듈 상태(INIT / OPERATIONAL / ERROR / SHUTDOWN)를 "
        "정수 코드로 반환한다. 오류 상태일 경우 세부 오류 코드도 함께 반환된다.",
        "body"))

    story.append(P("4.5 동작 전 사용자 호출 방식의 자가시험", "h2"))  # DOC-021
    story.append(P(
        "암호 서비스 최초 호출 전 lea_module_init()에서 동작 전 자가시험(Power-up Self-test)이 "
        "자동 수행된다. 또한 사용자가 lea_selftest()를 명시적으로 호출하여 온디맨드 자가시험을 "
        "수행할 수 있다(사용자 호출 방식 자가시험 지원). 자가시험 실패 시 모든 서비스가 차단된다.",
        "body"))

    story.append(P("4.6 제로화 서비스", "h2"))  # DOC-022
    story.append(P(
        "lea_zeroize(ctx) API는 컨텍스트 구조체 내 모든 CSP(키, 라운드키, IV, 상태값)를 "
        "제로화(0 채움)한 후 컨텍스트를 해제한다. "
        "제로화는 memset_s() 함수를 사용하여 컴파일러 최적화에 의한 제거를 방지한다. "
        "제로화 서비스는 암호 관리자 역할로만 호출 가능하다.",
        "body"))

    story.append(P("4.7 리셋 및 전원 종료 시 이전 인증 소멸", "h2"))  # DOC-023
    story.append(P(
        "프로세스 종료(전원 종료 포함) 시 운영체제의 프로세스 메모리가 회수되어 "
        "CSP가 자동으로 소멸된다. 재기동 후에는 이전 인증 상태가 유지되지 않으며 "
        "lea_module_init()를 다시 호출해야 한다.",
        "body"))

    story.append(P("4.8 인증 데이터 보호", "h2"))  # DOC-024
    story.append(P(
        "본 모듈은 별도의 사용자 인증 데이터(PIN, 비밀번호 등)를 관리하지 않는다. "
        "단일 운영자 환경으로 인증 데이터 보호 메커니즘은 운영체제 수준의 "
        "파일 접근 권한(chmod 700)으로 대체된다.",
        "body"))

    story.append(P("4.9 운영체제 연계 역할 할당", "h2"))  # DOC-025
    story.append(P(
        "운영체제 사용자 계정과 본 모듈 역할 간 매핑은 다음과 같다. "
        "root 또는 crypto_admin 그룹 계정은 암호 관리자 역할을 암묵적으로 부여받으며, "
        "일반 계정은 사용자 역할로 제한된다. 역할 확인은 geteuid() / getgroups() API를 통해 수행된다.",
        "body"))
    story.append(P("4.10 CSP의 동작모드 간 독립적 분리", "h2"))  # DOC-009
    story.append(P(
        "각 동작모드 컨텍스트(lea_ctx_t)는 독립적인 메모리 공간에 할당되어 "
        "서비스 간 CSP 공유가 없음을 보장한다. 컨텍스트 간 포인터 참조는 허용되지 않으며 "
        "각 컨텍스트는 별도 키 슬롯을 사용한다.",
        "body"))
    story.append(PageBreak())

    # ── 5. 소프트웨어 보안 ───────────────────────────────────────
    story.append(P("5. 소프트웨어/펌웨어 보안", "h1"))

    story.append(P("5.1 소프트웨어 무결성 검증 기법 및 시험 방법", "h2"))  # DOC-026
    story.append(P(
        "본 모듈은 <b>HMAC-SHA256</b>을 이용한 소프트웨어 무결성 검증을 수행한다. "
        "전원 인가 시 lea_crypto.so의 .text 및 .rodata 섹션 전체에 대해 "
        "HMAC-SHA256 다이제스트를 계산하고 내장된 기준값과 비교한다. "
        "불일치 시 E_INTEGRITY_FAIL 오류를 발생시키고 오류 상태로 전환한다.",
        "body"))
    story.append(_tbl(
        [["검증 기법",     "알고리즘",    "검증 대상 영역",          "시험 방법"],
         ["소프트웨어 무결성 검증", "HMAC-SHA256", ".text + .rodata 섹션",
          "전원인가 자가시험 중 기준 HMAC과 비교"]],
        [4*cm, 3*cm, 4*cm, 4*cm]))
    story.append(SP())

    story.append(P("5.2 소프트웨어 무결성 검증키 분산 저장 및 보호", "h2"))  # DOC-027
    story.append(P(
        "무결성 검증에 사용되는 HMAC 키는 본 모듈 내부에 <b>분산 저장</b>된다. "
        "키의 전반부(16바이트)는 .rodata 섹션 내 상수 배열에, "
        "후반부(16바이트)는 빌드 시 별도 오브젝트 파일로 링크되어 저장된다. "
        "이 키는 외부에 노출되지 않으며 검증 루틴에서만 접근된다.",
        "body"))

    story.append(P("5.3 무결성 실패 시 오류 처리 및 임시 데이터 제로화", "h2"))  # DOC-028
    story.append(P(
        "소프트웨어 무결성 시험 실패 시 오류 상태(ERROR state)로 즉시 전환된다. "
        "전환 시 무결성 검증 과정에서 생성된 임시 HMAC 컨텍스트 및 중간값을 "
        "memset_s()로 제로화한다. 이후 모든 암호 서비스 API 호출은 E_SELFTEST_FAIL을 반환한다.",
        "body"))

    story.append(P("5.4 온디맨드 무결성 시험 API", "h2"))  # DOC-029
    story.append(P(
        "운영자 요구에 의한 무결성 시험(온디맨드)은 lea_selftest() API를 통해 제공된다. "
        "이 API 호출 시 전원인가 자가시험과 동일한 무결성 검증 절차가 수행된다.",
        "body"))

    story.append(P("5.5 소프트웨어의 안전한 배포 및 설치 전 무결성 확인", "h2"))  # DOC-030
    story.append(P(
        "배포 패키지(lea_crypto_v1.0.tar.gz)는 SHA-256 해시값과 함께 제공된다. "
        "설치자는 설치 전 제공된 해시값을 검증하여 배포 무결성을 확인해야 한다. "
        "패키지 서명에는 RSA-3072 기반 코드 서명이 적용된다.",
        "body"))
    story.append(PageBreak())

    # ── 6. 운영환경 명세 ──────────────────────────────────────────
    story.append(P("6. 운영환경 명세", "h1"))

    story.append(P("6.1 운영환경 상세 정보", "h2"))  # DOC-031
    story.append(P("본 모듈이 검증을 받는 운영환경은 다음과 같다.", "body"))
    story.append(_tbl(
        [["항목",         "값"],
         ["운영체제",     "Ubuntu 22.04 LTS (x86_64, 64비트)"],
         ["커널 버전",    "Linux 5.15.0-generic"],
         ["CPU 아키텍처", "Intel x86_64 (AMD64)"],
         ["컴파일러",     "GCC 11.4.0"],
         ["빌드 환경",    "CMake 3.22.1 + GNU Make 4.3"],
         ["런타임 라이브러리", "glibc 2.35"],
         ["OpenSSL",      "3.0.2 (무결성 검증용 HMAC-SHA256)"]],
        [5*cm, 10*cm]))
    story.append(SP())

    story.append(P("6.2 프로세스 및 가상 메모리 보호 메커니즘", "h2"))  # DOC-032
    story.append(P(
        "운영체제의 프로세스 격리 및 가상 메모리 보호 기능을 통해 "
        "<b>SSP는 독립적으로 제어</b>된다. "
        "ASLR(주소 공간 배치 무작위화), NX 비트(스택/힙 실행 방지), "
        "스택 캐너리(Stack Canary)가 활성화된 환경에서 동작한다. "
        "mprotect()를 이용해 키 저장 메모리 페이지에 쓰기 보호를 적용한다.",
        "body"))

    story.append(P("6.3 자식 프로세스의 소유권 제한", "h2"))  # DOC-033
    story.append(P(
        "본 모듈은 자식 프로세스를 직접 생성하지 않는다. "
        "호출 프로세스가 fork()를 통해 자식 프로세스를 생성하는 경우, "
        "자식 프로세스는 부모의 CSP에 접근할 수 없도록 fork() 이후 "
        "lea_zeroize()를 호출하여 CSP를 즉시 소거해야 한다(pthread_atfork 핸들러 등록 지원).",
        "body"))
    story.append(PageBreak())

    # ── 7. 중요 보안매개변수(CSP/PSP) 관리 ──────────────────────
    story.append(P("7. 중요 보안매개변수(CSP/PSP) 관리", "h1"))

    story.append(P("7.1 CSP 및 PSP의 인가되지 않은 접근 보호", "h2"))  # DOC-034
    story.append(P(
        "CSP(암호키, 라운드키, IV, 난수 시드 등)는 프로세스 내부 메모리에만 존재하며 "
        "디스크 또는 로그에 기록되지 않는다. "
        "외부 함수에 CSP 포인터를 직접 노출하지 않으며, "
        "모든 CSP 접근은 내부 API를 통해서만 허용된다.",
        "body"))
    story.append(_tbl(
        [["CSP 유형",   "생성 방법",         "저장 위치",         "소거 방법"],
         ["LEA 암호키", "lea_keygen() / 외부 입력", "lea_ctx_t.key[]",   "lea_zeroize() / memset_s()"],
         ["LEA 라운드키","키 스케줄 시 자동 생성", "lea_ctx_t.rk[]",  "lea_zeroize() / memset_s()"],
         ["IV",         "외부 입력",          "lea_ctx_t.iv[]",    "연산 완료 후 memset_s()"],
         ["RNG 시드",   "/dev/urandom 읽기",  "rng_ctx_t.seed[]",  "세션 종료 시 memset_s()"],
         ["RNG 상태값", "CTR_DRBG 내부 상태", "rng_ctx_t.state[]", "세션 종료 시 memset_s()"]],
        [2.5*cm, 4*cm, 3.5*cm, 5*cm]))
    story.append(SP())

    story.append(P("7.2 난수발생기 상태 정보 및 키생성 중간값의 CSP 간주", "h2"))  # DOC-035
    story.append(P(
        "CTR_DRBG 내부 상태(V, Key)와 키 생성 과정의 중간값은 모두 CSP로 간주한다. "
        "이 값들은 사용 후 즉시 memset_s()로 제로화되며 외부로 노출되지 않는다.",
        "body"))

    story.append(P("7.3 외부 엔트로피 잡음원의 CSP 간주 및 평가", "h2"))  # DOC-036
    story.append(P(
        "외부 엔트로피 잡음원(/dev/urandom에서 수집된 원시 엔트로피)은 CSP로 간주한다. "
        "NIST SP 800-90B 기준에 따라 엔트로피 추정치가 최소 256비트 이상임을 보장하며, "
        "수집 즉시 CTR_DRBG 시드로 투입된 후 원본 엔트로피는 제로화된다.",
        "body"))

    story.append(P("7.4 SSP 생성 및 자동화된 SSP 설정 방법", "h2"))  # DOC-037
    story.append(P(
        "SSP(Secret Security Parameter)인 LEA 암호키는 다음 방법으로 생성/설정된다. "
        "① 자동 생성: lea_keygen()이 CTR_DRBG를 통해 난수 키를 생성한다. "
        "② 키 합의: ECDH/DH 키 합의 프로토콜을 통한 자동 설정(외부 프로토콜 라이브러리 연동). "
        "③ 외부 주입: lea_set_key()를 통해 호출자가 키를 직접 제공한다.",
        "body"))

    story.append(P("7.5 SSP 주입 및 출력 형태", "h2"))  # DOC-038
    story.append(P(
        "SSP 주입은 lea_set_key(ctx, key_buf, key_len) API를 통해 바이트 배열 형태로 수행된다. "
        "SSP는 외부로 출력되지 않으며(출력 금지), 오직 내부 암호 연산에만 사용된다. "
        "내보내기(export) 기능은 제공하지 않는다.",
        "body"))

    story.append(P("7.6 SSP 저장 및 PSP 보호(변경 금지)", "h2"))  # DOC-039
    story.append(P(
        "SSP는 프로세스 메모리 내 lea_ctx_t 구조체에 저장되며 디스크에 기록되지 않는다. "
        "PSP(공개 보안매개변수: 알고리즘 ID, 키 길이)는 상수로 정의되어 "
        "프로그램 실행 중 변경이 불가능하다(.rodata 섹션 배치).",
        "body"))

    story.append(P("7.7 절차적/운영적 제로화 및 복구 불가능성 명세", "h2"))  # DOC-040
    story.append(P(
        "CSP 제로화는 lea_zeroize() API를 통한 <b>절차적 제로화</b>와 "
        "프로세스 종료 시 운영체제의 메모리 회수에 의한 <b>운영적 제로화</b> 두 가지를 지원한다. "
        "절차적 제로화는 memset_s()로 수행되어 복구 불가능하며, "
        "포렌식 복구를 방지하기 위해 메모리 해제 전 3회 덮어쓰기를 수행한다.",
        "body"))
    story.append(PageBreak())

    # ── 8. 자가시험 ───────────────────────────────────────────────
    story.append(P("8. 자가시험", "h1"))

    story.append(P("8.1 자가시험 실패 시 오류 처리 및 해제 방법", "h2"))  # DOC-041
    story.append(P(
        "자가시험 실패 시 내부 상태 플래그를 FIPS_ERROR로 설정하고 "
        "시스템 로그에 오류를 기록한다. 이후 모든 암호 서비스는 차단된다. "
        "오류 해제는 시스템 재기동 후 lea_module_init()를 재호출해야 한다.",
        "body"))

    story.append(P("8.2 자가시험 오류 시 암호 서비스 제한 및 출력 금지", "h2"))  # DOC-042
    story.append(P(
        "FIPS_ERROR 상태에서는 암호화/복호화/MAC 생성 등 모든 암호 서비스 API가 "
        "E_SELFTEST_FAIL(−5)을 반환하고 데이터를 출력하지 않는다. "
        "출력 버퍼는 변경되지 않으며, 반환값 검사를 통해 호출자가 오류를 인지해야 한다.",
        "body"))

    story.append(P("8.3 소프트웨어 무결성 시험 수행 순서", "h2"))  # DOC-043
    story.append(P(
        "전원인가 자가시험은 다음 순서로 수행된다: "
        "① 소프트웨어 무결성 기술 시험(무결성 검증 알고리즘 자체 검증) → "
        "② 소프트웨어 무결성 시험(HMAC-SHA256으로 .text/.rodata 무결성 검증) → "
        "③ KAT 시험. 이 순서를 통해 무결성 시험 도구의 신뢰성을 먼저 보장한다.",
        "body"))

    story.append(P("8.4 동작 전 핵심기능시험(KAT) 세부 수행 방법", "h2"))  # DOC-044
    story.append(P(
        "동작 전 핵심기능시험(KAT)은 전원 인가 시 자동 수행되며 내용은 다음과 같다.",
        "body"))
    story.append(_tbl(
        [["시험 항목",           "알고리즘",  "테스트벡터 출처",     "판정 기준"],
         ["LEA-128 ECB KAT",    "LEA-128",   "KS X 3246 부속서 A",  "암호화/복호화 일치"],
         ["LEA-192 ECB KAT",    "LEA-192",   "KS X 3246 부속서 A",  "암호화/복호화 일치"],
         ["LEA-256 ECB KAT",    "LEA-256",   "KS X 3246 부속서 A",  "암호화/복호화 일치"],
         ["CBC KAT",            "LEA+CBC",   "TTAKKO-12.0271",      "암호화/복호화 일치"],
         ["CTR KAT",            "LEA+CTR",   "TTAKKO-12.0271",      "암호화/복호화 일치"],
         ["GCM KAT",            "LEA+GCM",   "TTAKKO-12.0271 Part2","암호화+인증 일치"],
         ["HMAC-SHA256 KAT",   "HMAC-SHA256","NIST CAVS",           "다이제스트 일치"],
         ["RNG 건전성 시험",    "CTR_DRBG",  "NIST SP 800-90A",     "연속 중복 없음"]],
        [3.5*cm, 2.5*cm, 4*cm, 5*cm]))
    story.append(SP())

    story.append(P("8.5 엔트로피 잡음원 건전성 시험 (오류 탐지 시험)", "h2"))  # DOC-045
    story.append(P(
        "엔트로피 잡음원(/dev/urandom) 건전성 시험으로 연속 RNG 출력 반복값 탐지 시험을 수행한다. "
        "NIST SP 800-90B Section 4.4에 따른 Repetition Count Test(RCT)와 "
        "Adaptive Proportion Test(APT)를 전원인가 시 수행한다. "
        "시험 실패 시 E_RNG_FAIL을 반환하고 오류 상태로 전환한다.",
        "body"))

    story.append(P("8.6 조건부 키쌍 일치 시험", "h2"))  # DOC-046
    story.append(P(
        "키 생성 시 조건부 키쌍 일치 시험 및 키쌍 유효성 검증을 수행한다. "
        "생성된 키로 알려진 평문을 암호화한 후 복호화하여 원본과 일치하는지 확인한다. "
        "일치하지 않을 경우 해당 키는 폐기하고 E_KEY_INVALID를 반환한다.",
        "body"))

    story.append(P("8.7 주기적 자가시험", "h2"))  # DOC-047
    story.append(P(
        "주기적 자가시험은 기본적으로 비활성화되어 있으며, "
        "lea_set_periodic_selftest(interval_sec) API를 통해 활성화 가능하다. "
        "활성화 시 설정된 주기(초 단위)마다 KAT 및 무결성 시험이 반복 수행된다.",
        "body"))
    story.append(PageBreak())

    # ── 9. 유한상태모델 ───────────────────────────────────────────
    story.append(P("9. 유한상태모델", "h1"))

    story.append(P("9.1 상태 정의 및 상태천이 명세", "h2"))  # DOC-048
    story.append(P("본 모듈의 유한상태모델은 다음 상태와 천이로 구성된다.", "body"))
    story.append(_tbl(
        [["상태",           "설명",                          "진입 조건"],
         ["UNINITIALIZED",  "모듈 초기화 전 상태",           "프로세스 기동 직후"],
         ["SELFTEST",       "자가시험 수행 중",              "lea_module_init() 호출"],
         ["OPERATIONAL",    "정상 동작 상태 (서비스 가능)", "자가시험 전체 통과"],
         ["ERROR",          "오류 상태 (서비스 불가)",       "자가시험 실패 / 오류 탐지"],
         ["SHUTDOWN",       "종료 상태",                    "lea_module_destroy() 호출"]],
        [3.5*cm, 5.5*cm, 6*cm]))
    story.append(SP())
    story.append(P("상태천이표:", "body"))
    story.append(_tbl(
        [["현재 상태",    "이벤트",                  "다음 상태",    "출력/동작"],
         ["UNINITIALIZED","lea_module_init() 호출",  "SELFTEST",    "자가시험 시작"],
         ["SELFTEST",     "자가시험 통과",            "OPERATIONAL", "서비스 활성화"],
         ["SELFTEST",     "자가시험 실패",            "ERROR",       "E_SELFTEST_FAIL 반환"],
         ["OPERATIONAL",  "오류 탐지",               "ERROR",       "서비스 차단"],
         ["OPERATIONAL",  "lea_selftest() 성공",     "OPERATIONAL", "상태 유지"],
         ["OPERATIONAL",  "lea_module_destroy()",   "SHUTDOWN",    "CSP 제로화"],
         ["ERROR",        "재기동",                  "UNINITIALIZED","메모리 초기화"]],
        [3*cm, 4.5*cm, 3*cm, 4.5*cm]))
    story.append(SP())

    story.append(P("9.2 단순 오류 발생 시 복구 및 자동 천이 절차", "h2"))  # DOC-049
    story.append(P(
        "단순 오류(E_DATA_INVALID, E_KEY_INVALID 등)는 현재 연산만 실패하며 "
        "모듈 상태는 OPERATIONAL을 유지한다(자동 복구). "
        "호출자가 올바른 파라미터로 재호출하면 정상 동작한다. "
        "심각한 오류(E_SELFTEST_FAIL, E_INTEGRITY_FAIL)만 ERROR 상태로 천이한다.",
        "body"))
    story.append(PageBreak())

    # ── 10. 생명주기 보증 ─────────────────────────────────────────
    story.append(P("10. 생명주기 보증", "h1"))

    story.append(P("10.1 소프트웨어 개발환경 및 빌드 도구 상세 명세", "h2"))  # DOC-050
    story.append(_tbl(
        [["항목",           "도구/버전"],
         ["언어",           "C11 (ISO/IEC 9899:2011)"],
         ["컴파일러",       "GCC 11.4.0 (Ubuntu 22.04 기본)"],
         ["컴파일 옵션",    "-O2 -Wall -Wextra -fstack-protector-strong -D_FORTIFY_SOURCE=2"],
         ["빌드 도구",      "CMake 3.22.1 + GNU Make 4.3"],
         ["정적 분석",      "Coverity 2023.6 + cppcheck 2.10"],
         ["버전 관리",      "Git 2.34.1 + GitLab CE 16.0"],
         ["CI/CD",          "GitLab CI/CD (빌드/테스트 자동화)"],
         ["패키징",         "dpkg-deb 1.21.1 (Debian 패키지 형식)"]],
        [4*cm, 11*cm]))
    story.append(SP())

    story.append(P("10.2 기능시험 및 자동화 보안 진단(취약점 점검)", "h2"))  # DOC-051
    story.append(P(
        "기능시험은 단위시험(Unit Test), 통합시험(Integration Test)으로 구성된다. "
        "자동화 보안 진단은 정적 분석 도구(Coverity, cppcheck)와 "
        "동적 분석 도구(Valgrind, AddressSanitizer)를 사용하여 취약점을 점검한다. "
        "OWASP Top 10 기반 취약점 점검과 Fuzzing 테스트(libFuzzer)를 수행한다.",
        "body"))

    story.append(P("10.3 수명 종료 시의 안전한 소거 절차", "h2"))  # DOC-052
    story.append(P(
        "모듈 수명 종료 시 lea_module_destroy()를 호출하여 모든 CSP를 제로화한다. "
        "동적 할당 메모리는 memset_s()로 3회 덮어쓴 후 free()한다. "
        "공유 메모리(shm)가 사용된 경우 shm_unlink()로 제거하고 파일 기반 임시 키는 "
        "secure_delete()(DoD 5220.22-M 7패스)로 소거한다.",
        "body"))

    story.append(P("10.4 역할별 운영자 안내서 분리 제공", "h2"))  # DOC-053
    story.append(P(
        "관리자 안내서와 비관리자 안내서를 별도 문서로 분리하여 제공한다. "
        "관리자 안내서(KCMVP-ADM-2025-001)는 모듈 설치, 초기화, 자가시험, 키 관리, "
        "오류 복구 절차를 포함한다. "
        "비관리자 안내서(KCMVP-USR-2025-001)는 암호 서비스 API 호출 방법 및 "
        "오류 처리 지침을 포함한다.",
        "body"))
    story.append(PageBreak())

    # ── 11. 기타 공격 대응 ────────────────────────────────────────
    story.append(P("11. 기타 공격에 대한 대응", "h1"))

    story.append(P("11.1 공개키 타이밍 공격 및 키 마스킹 대응", "h2"))  # DOC-054
    story.append(P(
        "LEA 연산은 고정 시간(Constant-Time) 구현을 적용하여 타이밍 공격을 방어한다. "
        "키 비교 연산은 ct_memcmp()(Constant-Time memcmp)로 수행하며, "
        "중간 연산값에는 난수 마스킹(Random Masking)을 적용하여 "
        "전력 분석(DPA) 및 캐시 사이드채널 공격에 대응한다.",
        "body"))

    story.append(P("11.2 소프트웨어 버퍼오버플로우 구조적 방어", "h2"))  # DOC-055
    story.append(P(
        "버퍼오버플로우에 대한 구조적 방어로 다음을 적용한다: "
        "① 경계 검사: 모든 입력 길이 검증 및 배열 접근 전 범위 확인. "
        "② 컴파일러 방어: -fstack-protector-strong(스택 캐너리), "
        "-D_FORTIFY_SOURCE=2(버퍼 크기 체크). "
        "③ ASLR + NX: 운영체제 수준 메모리 보호 활성화. "
        "④ AddressSanitizer: CI 빌드 시 동적 메모리 오류 탐지.",
        "body"))
    story.append(SP(20))

    doc.multiBuild(story)
    print(f"  design_pass.pdf → {path}")


# ══════════════════════════════════════════════════════════════════
#  design_fail.pdf  (핵심 규칙 의도적 누락)
# ══════════════════════════════════════════════════════════════════
def build_design_fail(path: str):
    doc = KcmvpDoc(path, title="설계서(불완전)")
    story: List = []

    story += _cover("LEA Crypto Library (불완전본)", "기본 및 상세 설계서",
                    "v0.9 (draft)", "2025-08-01", "KCMVP-DSG-2025-DRAFT")

    story.append(P("1. 개요", "h1"))
    story.append(P("1.1 목적", "h2"))
    story.append(P("본 문서는 LEA 암호 라이브러리에 대한 설계 문서이다.", "body"))
    # DOC-001 누락: "소프트웨어 암호모듈" 언급 없음
    story.append(P("1.2 배경", "h2"))
    story.append(P("다양한 환경에서 동작하는 LEA 기반 암호 라이브러리이다.", "body"))
    story.append(PageBreak())

    story.append(P("2. 암호모듈 구성", "h1"))
    story.append(P("2.1 구성 개요", "h2"))
    # DOC-004 누락: 버전 정보 없음
    story.append(P("암호모듈은 LEA 알고리즘을 지원하는 공유 라이브러리이다.", "body"))
    story.append(P("2.2 알고리즘 개요", "h2"))
    # DOC-007 누락: 알고리즘 목록 없음 (그냥 설명)
    story.append(P("LEA 알고리즘을 기반으로 암호화를 제공한다.", "body"))
    story.append(P("2.3 키 관리", "h2"))
    # DOC-009 누락: CSP 독립적 분리 언급 없음
    story.append(P("암호키를 안전하게 관리한다.", "body"))
    story.append(P("2.4 보안 기능", "h2"))
    story.append(P("다양한 보안 기능을 제공한다.", "body"))
    story.append(PageBreak())

    story.append(P("3. 인터페이스 명세", "h1"))
    story.append(P("3.1 API 목록", "h2"))
    # DOC-010 누락: 상태 표시기 없음
    story.append(P("암호화 및 복호화 API를 제공한다.", "body"))
    story.append(P("3.2 입출력 형식", "h2"))
    story.append(P("바이트 배열 형식으로 입출력한다.", "body"))
    story.append(PageBreak())

    story.append(P("4. 역할", "h1"))
    story.append(P("4.1 사용자 정의", "h2"))
    # DOC-017 누락: "암호 관리자", "일반 사용자" 명시 없음
    story.append(P("시스템 관리자와 일반 운영자가 모듈을 사용한다.", "body"))
    # DOC-022 누락: 제로화 서비스 없음

    doc.multiBuild(story)
    print(f"  design_fail.pdf → {path}")


# ══════════════════════════════════════════════════════════════════
#  config_pass.pdf  (4개 CM 규칙 충족)
# ══════════════════════════════════════════════════════════════════
def build_config_pass(path: str):
    doc = KcmvpDoc(path, title="형상관리문서")
    story: List = []

    story += _cover("LEA Crypto Library", "형상관리 문서",
                    "v1.0", "2025-09-01", "KCMVP-SCM-2025-001")

    story.append(P("1. 형상관리 개요", "h1"))
    story.append(P("1.1 목적", "h2"))
    story.append(P("본 문서는 LEA Crypto Library의 형상관리 절차 및 방법을 정의한다.", "body"))
    story.append(P("1.2 형상관리 시스템", "h2"))  # CM-001
    story.append(P(
        "본 프로젝트는 <b>Git(GitLab CE 16.0)</b> 형상관리 시스템을 사용한다. "
        "모든 소스코드, 문서, 테스트 파일은 GitLab 저장소에서 형상관리된다. "
        "저장소 URL: gitlab.internal/kcmvp/lea-crypto",
        "body"))
    story.append(PageBreak())

    story.append(P("2. 형상항목 목록 및 유일 식별자", "h1"))  # CM-002
    story.append(P(
        "형상관리 대상 항목과 유일 식별자(버전) 부여 체계는 다음과 같다. "
        "Major.Minor.Patch 형식으로 버전을 부여한다.",
        "body"))
    story.append(_tbl(
        [["형상항목 ID", "항목명",              "현재 버전", "버전 부여 방법"],
         ["CI-001",    "소스코드 (lea_crypto/src/)",  "v1.0.0", "git tag (semver)"],
         ["CI-002",    "헤더 파일 (lea_crypto/include/)", "v1.0.0", "git tag (semver)"],
         ["CI-003",    "기본설계서",            "v1.0",   "문서 버전 필드"],
         ["CI-004",    "형상관리문서",          "v1.0",   "문서 버전 필드"],
         ["CI-005",    "시험서",               "v1.0",   "문서 버전 필드"],
         ["CI-006",    "테스트 프로그램 (tests/)", "v1.0.0", "git tag (semver)"],
         ["CI-007",    "빌드 스크립트 (CMakeLists.txt)", "v1.0.0", "git tag (semver)"]],
        [2*cm, 5.5*cm, 2.5*cm, 5*cm]))
    story.append(PageBreak())

    story.append(P("3. 형상항목 변경/삭제 절차 및 이력 추적", "h1"))  # CM-003
    story.append(P("3.1 변경 요청 및 승인", "h2"))
    story.append(P(
        "변경 요청은 GitLab Issue로 등록하며, 형상관리위원회(CCB: Configuration Control Board) "
        "승인 후 변경이 허용된다. CCB는 보안 담당자, 개발 책임자, 품질 담당자로 구성된다.",
        "body"))
    story.append(P("3.2 변경 이력 추적", "h2"))
    story.append(P(
        "모든 변경은 GitLab Merge Request(MR)를 통해 관리되며 "
        "커밋 히스토리로 변경 이력이 자동 추적된다. "
        "문서 변경은 문서 내 개정 이력 테이블에도 기록한다.",
        "body"))
    story.append(_tbl(
        [["버전", "변경일",     "변경자",    "변경 내용",           "승인자"],
         ["v1.0", "2025-09-01", "홍길동",    "최초 작성",           "김철수 (CCB)"],
         ["v0.9", "2025-08-15", "홍길동",    "GCM 모드 섹션 추가", "김철수 (CCB)"]],
        [1.5*cm, 2.5*cm, 2.5*cm, 5.5*cm, 3*cm]))
    story.append(PageBreak())

    story.append(P("4. 배포, 설치, 초기화 및 삭제(소거) 절차", "h1"))  # CM-004
    story.append(P("4.1 안전한 배포 절차", "h2"))
    story.append(P(
        "배포 패키지는 SHA-256 해시값과 RSA-3072 코드 서명이 첨부된다. "
        "수령자는 공개키로 서명을 검증하고 해시값으로 무결성을 확인한 후 설치한다.",
        "body"))
    story.append(P("4.2 설치 절차", "h2"))
    story.append(P(
        "① 패키지 수령 및 무결성 검증 → ② dpkg -i lea_crypto_1.0.0_amd64.deb 실행 → "
        "③ lea_module_init() 호출로 자가시험 수행 → ④ 정상 동작 확인.",
        "body"))
    story.append(P("4.3 삭제(소거) 절차", "h2"))
    story.append(P(
        "① lea_module_destroy()로 모든 CSP 제로화 → ② dpkg --purge lea_crypto로 완전 제거 → "
        "③ 설정 파일 및 로그 수동 삭제(shred -u 사용) → ④ 제거 완료 확인.",
        "body"))

    doc.multiBuild(story)
    print(f"  config_pass.pdf → {path}")


# ══════════════════════════════════════════════════════════════════
#  test_pass.pdf  (5개 TEST 규칙 충족)
# ══════════════════════════════════════════════════════════════════
def build_test_pass(path: str):
    doc = KcmvpDoc(path, title="시험서")
    story: List = []

    story += _cover("LEA Crypto Library", "암호알고리즘 시험서",
                    "v1.0", "2025-09-01", "KCMVP-TST-2025-001")

    story.append(P("1. 시험 개요", "h1"))
    story.append(P("1.1 시험 환경", "h2"))  # TEST-001
    story.append(_tbl(
        [["항목",      "내용"],
         ["시험환경 OS", "Ubuntu 22.04 LTS (x86_64, 64비트)"],
         ["CPU",        "Intel Core i7-12700K"],
         ["메모리",     "32GB DDR5"],
         ["컴파일러",   "GCC 11.4.0 (-O2 -Wall)"],
         ["시험 도구",  "CTest 3.22.1, 자체 시험 프레임워크"]],
        [4*cm, 11*cm]))
    story.append(SP())
    story.append(P("1.2 대상 알고리즘 목록", "h2"))  # TEST-001
    story.append(_tbl(
        [["알고리즘",  "키 길이",        "운영모드",                    "표준"],
         ["LEA",      "128/192/256비트", "ECB, CBC, CTR, GCM, CCM, CMAC, OFB, CFB", "KS X 3246"],
         ["CTR_DRBG", "256비트",         "CTR 모드 기반 난수발생기",   "NIST SP 800-90A"]],
        [2.5*cm, 3*cm, 7*cm, 2.5*cm]))
    story.append(PageBreak())

    story.append(P("2. 알고리즘 시험 결과", "h1"))
    story.append(P("2.1 테스트벡터 및 출처", "h2"))  # TEST-002
    story.append(P(
        "시험에 사용된 테스트벡터(평문, 암호문, 키)와 그 출처는 다음과 같다.",
        "body"))
    story.append(_tbl(
        [["시험",          "출처",                          "벡터 수"],
         ["LEA KAT",       "KS X 3246:2016 부속서 A",       "3 (128/192/256)"],
         ["CBC KAT",       "TTAKKO-12.0271:2013 부속서",    "6"],
         ["CTR KAT",       "TTAKKO-12.0271:2013 부속서",    "6"],
         ["GCM KAT",       "TTAKKO-12.0271 Part2:2017",     "4"],
         ["CCM KAT",       "TTAKKO-12.0271 Part2:2017",     "4"],
         ["CMAC KAT",      "TTAKKO-12.0271 Part2:2017",     "3"],
         ["MCT (KAT)",     "KCMVP 암호모듈 사전검증 시스템", "1000 반복"]],
        [3*cm, 7.5*cm, 2.5*cm]))
    story.append(SP())

    story.append(P("2.2 LEA-128 ECB 기지 답안 시험벡터 (KAT)", "h2"))
    story.append(_tbl(
        [["항목", "값 (16진수)"],
         ["평문 (PT)", "0x101112131415161718191a1b1c1d1e1f"],
         ["키  (Key)", "0x0f0e0d0c0b0a09080706050403020100"],
         ["암호문 (CT)", "0x9b9b7bea0d0d7d6c4d1a0ba47e8e2c05"],
         ["복호화 결과", "0x101112131415161718191a1b1c1d1e1f (원문 일치)"]],
        [4*cm, 11*cm]))
    story.append(SP())
    story.append(P("참조 표준: KS X 3246:2016 부속서 A, Table A.1 (LEA-128 ECB)", "caption"))
    story.append(PageBreak())

    story.append(P("3. 시험 절차 및 증빙", "h1"))
    story.append(P("3.1 알고리즘 시험 절차", "h2"))  # TEST-003
    story.append(P(
        "각 알고리즘 시험은 다음 절차에 따라 수행되었으며, "
        "결과는 화면 캡쳐 및 디버깅 메시지 출력을 통해 증빙된다.",
        "body"))
    story.append(_tbl(
        [["단계", "시험목적",            "시험단계",                    "예상 시험결과",    "실제 시험결과"],
         ["1",   "LEA-128 ECB KAT",    "KAT 벡터 암호화 후 비교",     "CT 일치",    "PASS"],
         ["2",   "LEA-192 ECB KAT",    "KAT 벡터 암호화 후 비교",     "CT 일치",    "PASS"],
         ["3",   "LEA-256 ECB KAT",    "KAT 벡터 암호화 후 비교",     "CT 일치",    "PASS"],
         ["4",   "CBC MCT",            "1000회 반복 몬테카를로 시험",  "최종 CT 일치","PASS"],
         ["5",   "CTR KAT",            "CTR 모드 KAT 벡터 시험",      "CT 일치",    "PASS"],
         ["6",   "GCM 인증 시험",      "GCM 암호화 + 태그 검증",      "CT+Tag 일치","PASS"]],
        [1*cm, 3.5*cm, 4.5*cm, 2.5*cm, 2.5*cm]))
    story.append(SP())

    story.append(P("4. 암호모듈 관리 API 시험", "h1"))  # TEST-004
    story.append(P("4.1 관리 API 동작 시험", "h2"))
    story.append(P(
        "모듈 초기화, 자가시험, 상태 조회, 버전 조회, 제로화 등 관리 API에 대한 "
        "시험을 수행하였다.",
        "body"))
    story.append(_tbl(
        [["API",                  "시험 내용",                         "결과"],
         ["lea_module_init()",    "정상 초기화 및 전원인가 자가시험",   "PASS"],
         ["lea_module_status()",  "OPERATIONAL 상태 반환 확인",         "PASS"],
         ["lea_module_version()", "버전 문자열 반환 확인",              "PASS"],
         ["lea_selftest()",       "온디맨드 자가시험 정상 동작",        "PASS"],
         ["lea_zeroize()",        "컨텍스트 제로화 후 재사용 불가 확인", "PASS"],
         ["lea_module_destroy()", "모듈 종료 및 CSP 소거 확인",         "PASS"]],
        [4.5*cm, 6.5*cm, 3*cm]))
    story.append(PageBreak())

    story.append(P("5. 오류 처리 시험 및 데이터 충돌 검사", "h1"))  # TEST-005
    story.append(P("5.1 의도적 오류 주입 시험", "h2"))
    story.append(P(
        "잘못된 키 길이, NULL 포인터, 잘못된 알고리즘 ID 등 비정상 입력에 대해 "
        "설계서에 명세된 오류코드가 정확히 반환되고, 오류 상태에서 암호 서비스 수행과 "
        "데이터 출력이 금지됨을 확인하였다.",
        "body"))
    story.append(_tbl(
        [["시험 항목",              "입력 조건",                "예상 반환값",   "실제 반환값", "결과"],
         ["잘못된 키 길이",         "key_len = 64 (유효 범위 외)", "E_KEY_INVALID(-2)", "−2",  "PASS"],
         ["NULL 키 포인터",         "key = NULL",               "E_KEY_INVALID(-2)", "−2",  "PASS"],
         ["NULL 평문 포인터",       "pt = NULL",                "E_DATA_INVALID(-3)", "−3", "PASS"],
         ["0 길이 입력",            "pt_len = 0",               "E_DATA_INVALID(-3)", "−3", "PASS"],
         ["자가시험 실패 상태",      "강제 FIPS_ERROR 설정",     "E_SELFTEST_FAIL(-5)", "−5","PASS"],
         ["GCM 태그 불일치",        "변조된 CT 복호화",          "E_AUTH_FAIL(-4)",   "−4",  "PASS"]],
        [4*cm, 4*cm, 3*cm, 2*cm, 1.5*cm]))
    story.append(SP())
    story.append(P(
        "모든 오류 케이스에서 출력 버퍼는 변경되지 않았으며(데이터 출력 금지 확인), "
        "오류 반환값만 설정되었음을 확인하였다. 캡처 로그는 별첨 A에 수록.",
        "body"))

    doc.multiBuild(story)
    print(f"  test_pass.pdf → {path}")


# ══════════════════════════════════════════════════════════════════
#  ZIP 패키징
# ══════════════════════════════════════════════════════════════════
GROUND_TRUTH = """\
# DOC 정확도 테스트 v2 Ground Truth
# 형식: 파일명(zip 내 경로) | P/N | 위반규칙(P인 경우) | 설명
#
# P = 위반 있음, N = 위반 없음 (파일 레벨 판정)
#
design/design_pass.pdf | N | - | 55개 DOC 규칙 모두 충족 (실제 설계서 수준)
design/design_fail.pdf | P | DOC-001,DOC-004,DOC-007,DOC-009,DOC-010,DOC-017,DOC-022 | 핵심 규칙 7개 의도적 누락
config_mgmt/config_pass.pdf | N | - | 4개 CM 규칙 모두 충족
test/test_pass.pdf | N | - | 5개 TEST 규칙 모두 충족
"""

VIOLATION_DETAIL = """\
# DOC 정확도 테스트 v2 — 위반 상세 (design_fail.pdf)
#
# DOC-001: "소프트웨어 암호모듈" 분류 명시 누락
# DOC-004: 모듈 명칭 및 버전 정보(v1.0 등) 명시 누락
# DOC-007: 검증대상 알고리즘 목록 테이블 누락
# DOC-009: CSP 독립적 분리 요구사항 명시 누락
# DOC-010: 서비스 상태 표시기(반환값 체계) 명시 누락
# DOC-017: "암호 관리자", "일반 사용자" 역할 정의 누락
# DOC-022: 제로화 서비스 제공 및 동작 명시 누락
#
# 경계 케이스 (L2 AI 판정 테스트용, design_pass.pdf):
# - DOC-023: "리셋/전원 종료" 키워드 없이 "프로세스 종료" + "메모리 회수" 표현 사용
# - DOC-025: "암묵적 역할 할당" 개념을 "운영체제 사용자 계정 매핑"으로 표현
# - DOC-033: "자식 프로세스 소유권 제한"을 "pthread_atfork 핸들러" 예시로 설명
"""


def build_zip(out_path: str):
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        pdfs = {
            "docs/design/design_pass.pdf":      build_design_pass,
            "docs/design/design_fail.pdf":       build_design_fail,
            "docs/config_mgmt/config_pass.pdf":  build_config_pass,
            "docs/test/test_pass.pdf":           build_test_pass,
        }
        for rel, fn in pdfs.items():
            dest = tmp / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            fn(str(dest))

        with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for rel in pdfs:
                zf.write(tmp / rel, rel)
            zf.writestr("GROUND_TRUTH.md",     GROUND_TRUTH)
            zf.writestr("VIOLATION_DETAIL.md", VIOLATION_DETAIL)

    print(f"\n✓ {out_path} 생성 완료")
    with zipfile.ZipFile(out_path) as zf:
        print("파일 목록:")
        for info in zf.infolist():
            print(f"  {info.filename}: {info.file_size/1024:.1f} KB")


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "testdata/doc_accuracy_test_v2.zip"
    print("=== DOC 정확도 테스트 v2 PDF 생성 ===\n")
    build_zip(out)
