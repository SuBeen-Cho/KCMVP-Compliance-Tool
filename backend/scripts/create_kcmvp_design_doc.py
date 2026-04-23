#!/usr/bin/env python3
"""
KCMVP 기본 및 상세설계서 PDF 생성 스크립트
==========================================

참고 문서: 암호모듈+구현+안내서_설계서.pdf (2013, 암호모듈 검증기관)
구조 기준: KS X ISO/IEC 19790, 소프트웨어 암호모듈 검증기준

생성 파일: testdata/kcmvp_lea_design_doc.pdf

의도적 위반 (Before/After 비교용):
  DOC-022 ← 제로화 API 함수명 명세 없음   (lea_zeroize 등 미등장)
  DOC-040 ← 절차적/운영적 제로화 미명세   (volatile, 절차적 제로화 미등장)
  DOC-048 ← 유한상태모델 섹션 전체 누락   (상태천이도, 상태천이표 미등장)

올바르게 포함된 섹션 (정상):
  DOC-001/002 — 암호모듈 유형 및 경계
  DOC-003     — 검증대상 알고리즘 + CSP 목록
  DOC-004     — 명칭 및 버전 정보 V1.0
  DOC-005/031 — 운영환경 (Linux 64bit)
  DOC-012     — 서비스별 인터페이스 API
  DOC-035     — 키 관리 (생성/저장/배포)

사용법:
  cd backend
  python scripts/create_kcmvp_design_doc.py
  → testdata/kcmvp_lea_design_doc.pdf 생성
"""

import os
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
OUTPUT  = BACKEND / "testdata" / "kcmvp_lea_design_doc.pdf"

# ── 폰트 등록 ─────────────────────────────────────────────────────
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, PageBreak, KeepTogether
    )
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
except ImportError:
    print("reportlab 없음. 설치: pip install reportlab")
    sys.exit(1)

_FONT_CANDIDATES = [
    "/System/Library/Fonts/Supplemental/AppleGothic.ttf",
    "/Library/Fonts/AppleGothic.ttf",
    "/usr/share/fonts/truetype/nanum/NanumGothic.ttf",
    "/System/Library/Fonts/AppleSDGothicNeo.ttc",
]
FONT_KO = "KoreanDoc"
for _fp in _FONT_CANDIDATES:
    if os.path.exists(_fp):
        try:
            pdfmetrics.registerFont(TTFont(FONT_KO, _fp))
            print(f"폰트 등록: {_fp}")
            break
        except Exception:
            continue
else:
    FONT_KO = "Helvetica"
    print("한국어 폰트 없음 → Helvetica 사용")

W, H = A4
MARGIN = 20 * mm

# ── 스타일 팩토리 ─────────────────────────────────────────────────
def S(name, **kw):
    defaults = dict(fontName=FONT_KO, leading=16, spaceAfter=4)
    defaults.update(kw)
    return ParagraphStyle(name, **defaults)

TITLE   = S("T",  fontSize=18, leading=26, spaceAfter=6,
            textColor=colors.HexColor("#0d2a6e"), alignment=1)
SUBTITLE= S("ST", fontSize=11, leading=18, spaceAfter=4,
            textColor=colors.HexColor("#3a3a3a"), alignment=1)
H1      = S("H1", fontSize=14, leading=22, spaceBefore=18, spaceAfter=8,
            textColor=colors.HexColor("#0d2a6e"), fontName=FONT_KO)
H2      = S("H2", fontSize=11, leading=18, spaceBefore=12, spaceAfter=6,
            textColor=colors.HexColor("#1a3a6e"), fontName=FONT_KO)
H3      = S("H3", fontSize=10, leading=16, spaceBefore=8,  spaceAfter=4,
            textColor=colors.HexColor("#2c5f9e"), fontName=FONT_KO)
BODY    = S("B",  fontSize=9,  leading=15, spaceAfter=4)
BULLET  = S("BL", fontSize=9,  leading=15, leftIndent=14, bulletIndent=6,
            spaceAfter=2)
INDENT  = S("IN", fontSize=9,  leading=15, leftIndent=24, spaceAfter=2)
CODE    = S("CO", fontName="Courier", fontSize=8, leading=13,
            leftIndent=16, spaceAfter=4,
            backColor=colors.HexColor("#f5f5f5"))
NOTE    = S("NO", fontSize=8.5, leading=14, leftIndent=8, spaceAfter=4,
            textColor=colors.HexColor("#8b0000"),
            backColor=colors.HexColor("#fff8f8"))
CAPTION = S("CA", fontSize=8, leading=13, spaceAfter=6,
            textColor=colors.HexColor("#555555"), alignment=1)

def P(text, style=BODY): return Paragraph(text, style)
def B(text): return Paragraph(f"• {text}", BULLET)
def SP(n=4): return Spacer(1, n)
def HR(): return HRFlowable(width="100%", thickness=0.5,
                             color=colors.HexColor("#aaaaaa"), spaceAfter=6)

# ── 표 스타일 헬퍼 ────────────────────────────────────────────────
def tbl(data, col_widths=None, header=True):
    t = Table(data, colWidths=col_widths, repeatRows=1 if header else 0)
    style = [
        ("FONTNAME",    (0, 0), (-1, -1), FONT_KO),
        ("FONTSIZE",    (0, 0), (-1, -1), 8.5),
        ("LEADING",     (0, 0), (-1, -1), 13),
        ("TOPPADDING",  (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING",(0, 0),(-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",(0, 0), (-1, -1), 6),
        ("GRID",        (0, 0), (-1, -1), 0.4, colors.HexColor("#bbbbbb")),
        ("BACKGROUND",  (0, 0), (-1, 0),  colors.HexColor("#e8eef8")),
        ("FONTNAME",    (0, 0), (-1, 0),  FONT_KO),
        ("ALIGN",       (0, 0), (-1, 0),  "CENTER"),
        ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
    ]
    t.setStyle(TableStyle(style))
    return t


# ═══════════════════════════════════════════════════════════════════
# 문서 콘텐츠 구성
# ═══════════════════════════════════════════════════════════════════
def build_story():
    story = []

    # ── 표지 ──────────────────────────────────────────────────────
    story += [
        SP(60),
        P("암호모듈 기본 및 상세 설계서", TITLE),
        SP(8),
        P("LEA 블록암호 라이브러리 v1.0", SUBTITLE),
        SP(4),
        P("(소프트웨어 암호모듈)", SUBTITLE),
        SP(40),
        tbl([
            ["항목", "내용"],
            ["문서 번호",  "KCMVP-LEA-DS-2025-001"],
            ["버전 정보",  "V1.0"],
            ["작성일",     "2025년 4월"],
            ["작성 기관",  "(주) 한국암호기술"],
            ["적용 기준",  "KS X ISO/IEC 19790, 소프트웨어 암호모듈 검증기준"],
        ], col_widths=[60*mm, 110*mm]),
        SP(30),
        HR(),
        P("본 문서는 KCMVP 사전 검증 테스트 목적으로 작성된 예시 설계서입니다.", NOTE),
        PageBreak(),
    ]

    # ── 목차 ──────────────────────────────────────────────────────
    story += [
        P("목 차", H1),
        HR(),
        SP(4),
    ]
    toc = [
        ("1장", "암호모듈 명세",                       "3"),
        ("  1.1", "암호모듈 유형 및 경계",              "3"),
        ("  1.2", "검증대상 암호알고리즘 목록",         "4"),
        ("  1.3", "핵심보안매개변수(CSP) 목록",         "5"),
        ("  1.4", "암호모듈 명칭 및 버전",              "6"),
        ("2장", "암호모듈 인터페이스",                   "7"),
        ("  2.1", "물리적 포트 및 논리적 인터페이스",   "7"),
        ("  2.2", "서비스별 API 명세",                  "8"),
        ("3장", "역할, 서비스 및 인증",                  "10"),
        ("  3.1", "운영자 역할 정의",                   "10"),
        ("  3.2", "서비스 목록 및 접근 권한",           "11"),
        ("4장", "운영환경",                              "12"),
        ("5장", "암호 키 관리",                          "13"),
        ("  5.1", "키 생성",                             "13"),
        ("  5.2", "키 저장 및 배포",                    "14"),
        ("  5.3", "키 제로화",                           "15"),  # 의도적 불완전
        ("6장", "자가시험",                              "16"),
        ("7장", "설계보증 및 형상관리",                  "18"),
    ]
    for num, title, page in toc:
        indent = 14 if num.startswith("  ") else 0
        style = S(f"toc_{num}", fontSize=9, leading=16, leftIndent=indent,
                  spaceAfter=1)
        dots = " " + "." * (52 - len(num) - len(title) - indent//4) + " "
        story.append(P(f"{num}  {title}{dots}{page}", style))
    story.append(PageBreak())

    # ── 1장: 암호모듈 명세 ────────────────────────────────────────
    story += [P("1장. 암호모듈 명세", H1), HR()]

    # 1.1 유형 및 경계 (DOC-001, DOC-002)
    story += [
        P("1.1 암호모듈 유형 및 경계", H2),
        P("본 암호모듈은 <b>소프트웨어 암호모듈</b>로 분류된다. 소프트웨어 암호모듈이란 "
          "암호경계 내에 하나 또는 그 이상의 소프트웨어 컴포넌트만으로 구성된 모듈을 의미하며, "
          "변경 가능한 운영환경에서 동작한다."),
        SP(4),
        P("암호모듈 유형 선택 근거:", H3),
        B("물리적 하드웨어 컴포넌트 없이 순수 C 라이브러리(.so, .dll) 형태로 배포"),
        B("범용 운영체제(Linux, Windows) 위에서 동작하는 변경 가능한 운영환경"),
        B("암호경계는 lea_lib.so 파일 단일 공유 라이브러리로 정의"),
        SP(4),
        P("암호경계 구성요소:", H3),
        tbl([
            ["구성요소", "파일명", "유형", "설명"],
            ["암호 코어",  "lea_core.c",    "소스코드", "LEA 블록암호 라운드 함수"],
            ["키 스케줄",  "lea_key.c",     "소스코드", "128/192/256비트 키 확장"],
            ["모드 드라이버","lea_mode.c",  "소스코드", "CBC/CTR/GCM/CCM 모드"],
            ["공개 API",   "lea.h",         "헤더",     "외부 노출 인터페이스"],
            ["타입 정의",  "lea_types.h",   "헤더",     "uint32_t 등 타입 정의"],
        ], col_widths=[35*mm, 38*mm, 22*mm, 65*mm]),
        SP(8),
    ]

    # 1.2 검증대상 암호알고리즘 (DOC-007)
    story += [
        P("1.2 검증대상 암호알고리즘 목록", H2),
        P("본 암호모듈이 구현하는 검증대상 암호알고리즘 목록은 다음과 같다."),
        SP(4),
        tbl([
            ["알고리즘", "동작모드", "키 길이(비트)", "표준 참조", "검증대상 여부"],
            ["LEA",  "CBC",  "128/192/256", "KS X 3246",  "검증대상"],
            ["LEA",  "CTR",  "128/192/256", "KS X 3246",  "검증대상"],
            ["LEA",  "GCM",  "128/192/256", "KS X 3246",  "검증대상"],
            ["LEA",  "CCM",  "128/192/256", "KS X 3246",  "검증대상"],
            ["LEA",  "ECB",  "128/192/256", "KS X 3246",  "검증대상 (테스트 전용)"],
            ["DRBG", "CTR",  "256",          "KS X 3186",  "검증대상"],
        ], col_widths=[22*mm, 22*mm, 35*mm, 32*mm, 45*mm]),
        SP(4),
        P("비검증대상 암호알고리즘: 본 암호모듈은 비검증대상 암호알고리즘을 포함하지 않는다. "
          "모든 암호 연산은 검증대상 동작모드로만 수행된다."),
        SP(8),
    ]

    # 1.3 핵심보안매개변수(CSP) (DOC-003)
    story += [
        P("1.3 핵심보안매개변수(CSP) 목록", H2),
        P("핵심보안매개변수(CSP: Critical Security Parameter)는 노출 또는 수정 시 "
          "암호모듈의 보안을 위협할 수 있는 보안 관련 정보이다."),
        SP(4),
        tbl([
            ["CSP 명칭",      "유형",    "크기",       "생성 방법",     "소멸 방법"],
            ["비밀키(MK)",    "비밀키",  "128/192/256비트", "DRBG 생성", "제로화"],
            ["라운드키(RK)",  "파생키",  "32×6×32비트",  "키 스케줄",  "제로화"],
            ["CBC IV",        "초기벡터","128비트",     "DRBG 생성",   "사용 후 제로화"],
            ["CTR 카운터",    "상태값",  "128비트",     "초기화 시 설정","제로화"],
            ["GCM 인증태그",  "인증값",  "96~128비트",  "GHASH 연산",  "출력 후 제로화"],
            ["DRBG 내부상태", "CSP",     "384비트",     "엔트로피 시드","제로화"],
        ], col_widths=[32*mm, 22*mm, 35*mm, 30*mm, 35*mm]),
        SP(4),
        P("CSP 생성·소멸 정책: 모든 CSP는 사용 완료 후 메모리에서 제거하여 "
          "이후 접근이 불가하도록 관리한다. 구체적인 제로화 방법은 5장에서 기술한다."),
        SP(8),
    ]

    # 1.4 명칭 및 버전 (DOC-004)
    story += [
        P("1.4 암호모듈 명칭 및 버전", H2),
        tbl([
            ["항목",           "내용"],
            ["암호모듈 명칭",  "LEA 블록암호 라이브러리"],
            ["버전 정보",      "V1.0 (2025.04 기준)"],
            ["라이브러리 파일","lea_lib.so (Linux), lea_lib.dll (Windows)"],
            ["버전 부여 방식", "Major.Minor (예: V1.0, V1.1, V2.0)"],
            ["식별자",         "KCMVP-LEA-2025-001"],
        ], col_widths=[50*mm, 120*mm]),
        PageBreak(),
    ]

    # ── 2장: 암호모듈 인터페이스 ─────────────────────────────────
    story += [P("2장. 암호모듈 인터페이스", H1), HR()]

    # 2.1 물리적 포트 및 논리적 인터페이스 (DOC-011)
    story += [
        P("2.1 물리적 포트 및 논리적 인터페이스", H2),
        P("본 소프트웨어 암호모듈은 물리적 포트를 갖지 않으며, 운영체제의 프로세스 "
          "API 경계를 논리적 인터페이스로 사용한다."),
        SP(4),
        tbl([
            ["논리적 인터페이스",  "방향", "설명"],
            ["데이터 입력(DI)",  "→ 모듈", "평문, 키 소재, IV, AAD 등"],
            ["데이터 출력(DO)",  "← 모듈", "암호문, 복호화 평문, 인증태그"],
            ["제어 입력(CI)",    "→ 모듈", "알고리즘 선택, 키 길이, 모드 설정"],
            ["상태 출력(SO)",    "← 모듈", "반환코드(0=성공, 음수=오류), 오류 메시지"],
        ], col_widths=[50*mm, 25*mm, 95*mm]),
        SP(8),
    ]

    # 2.2 서비스별 API (DOC-012)
    story += [
        P("2.2 서비스별 API 명세", H2),
        P("암호모듈이 제공하는 공개 API 목록과 각 API의 데이터 입출력 및 "
          "제어 입력을 명세한다."),
        SP(4),
    ]

    apis = [
        ("lea_set_key",
         "uint32_t RK[32][6] (출력), const uint8_t *mk (입력), int mk_len (제어)",
         "void (성공) / 없음",
         "키 스케줄 수행 — 비밀키 mk로부터 라운드키 RK 생성"),
        ("lea_cbc_enc",
         "uint8_t *ct (출력), const uint8_t *pt (입력), int len, "
         "const uint8_t *iv (입력), const uint32_t RK[32][6] (입력)",
         "int (0=성공, -1=오류)",
         "CBC 모드 암호화"),
        ("lea_cbc_dec",
         "uint8_t *pt (출력), const uint8_t *ct (입력), int len, "
         "const uint8_t *iv, const uint32_t RK[32][6]",
         "int (0=성공, -1=오류)",
         "CBC 모드 복호화"),
        ("lea_ctr_enc",
         "uint8_t *out (출력), const uint8_t *in (입력), int len, "
         "uint8_t *ctr (입출력), const uint32_t RK[32][6]",
         "int (0=성공, -1=오류)",
         "CTR 모드 암/복호화"),
        ("lea_gcm_enc",
         "uint8_t *ct, uint8_t *tag (출력), const uint8_t *pt (입력), "
         "int pt_len, const uint8_t *iv, const uint8_t *aad",
         "int (0=성공, -1=오류)",
         "GCM 모드 인증 암호화"),
        # lea_zeroize 계열 API는 5장에서 함수명 명세 없음 (DOC-022 위반 의도)
    ]

    for fname, params, ret, desc in apis:
        story += [
            P(f"▶ {fname}()", H3),
            tbl([
                ["항목", "내용"],
                ["파라미터", params],
                ["반환값",   ret],
                ["설명",     desc],
            ], col_widths=[28*mm, 142*mm]),
            SP(4),
        ]

    story.append(PageBreak())

    # ── 3장: 역할, 서비스 및 인증 ─────────────────────────────────
    story += [P("3장. 역할, 서비스 및 인증", H1), HR()]

    story += [
        P("3.1 운영자 역할 정의", H2),
        P("본 암호모듈은 라이브러리 형태로 제공되므로 KS X ISO/IEC 19790에 따라 "
          "사용자 역할이 관리자 역할을 겸한다."),
        SP(4),
        tbl([
            ["역할",    "설명",                           "인증 방법"],
            ["사용자",  "암호 서비스(암/복호화, 키 생성) 수행", "운영체제 프로세스 권한"],
            ["관리자",  "초기화, 자가시험, 제로화 수행",       "운영체제 프로세스 권한"],
        ], col_widths=[28*mm, 90*mm, 52*mm]),
        SP(8),

        P("3.2 서비스 목록 및 접근 권한", H2),
        tbl([
            ["서비스명",          "역할",      "CSP 접근", "설명"],
            ["초기화",            "관리자",    "RW",       "자가시험 수행 후 동작 모드 진입"],
            ["키 생성",           "사용자",    "W",        "lea_set_key() 호출"],
            ["암호화",            "사용자",    "R",        "CBC/CTR/GCM 암호화"],
            ["복호화",            "사용자",    "R",        "CBC/CTR/GCM 복호화"],
            ["제로화",            "사용자/관리자", "W",    "CSP 메모리 소거"],
            ["자가시험",          "관리자",    "R",        "KAT 수행 및 무결성 검사"],
            ["상태 조회",         "사용자",    "-",        "현재 동작 상태 반환"],
        ], col_widths=[38*mm, 28*mm, 22*mm, 82*mm]),
        PageBreak(),
    ]

    # ── 4장: 운영환경 ────────────────────────────────────────────
    story += [P("4장. 운영환경", H1), HR()]
    story += [
        P("4.1 지원 운영환경", H2),
        P("본 암호모듈은 변경 가능한 운영환경에서 동작하는 소프트웨어 암호모듈이다. "
          "지원 운영환경은 다음과 같다."),
        SP(4),
        tbl([
            ["운영체제",     "버전",            "비트", "컴파일러"],
            ["Linux (Ubuntu)", "20.04 LTS 이상", "64비트", "GCC 9.x 이상"],
            ["Linux (CentOS)", "7.x 이상",       "64비트", "GCC 4.8 이상"],
            ["Windows",      "10/11",           "64비트", "MSVC 2019 이상"],
            ["macOS",        "12.x 이상",        "64비트", "Apple Clang 13 이상"],
        ], col_widths=[45*mm, 38*mm, 25*mm, 62*mm]),
        SP(6),
        P("단일 운영자 동작모드: 암호모듈이 라이브러리 형태로 응용프로그램에 탑재되어 "
          "해당 응용프로그램이 단일 운영자 역할을 수행한다."),
        P("메모리 보호: 운영체제의 가상 메모리 분리, ASLR(Address Space Layout "
          "Randomization), DEP(Data Execution Prevention) 등의 메모리 보호 메커니즘을 "
          "활용하여 외부 프로세스로부터의 CSP 접근을 방지한다."),
        PageBreak(),
    ]

    # ── 5장: 암호 키 관리 ─────────────────────────────────────────
    story += [P("5장. 암호 키 관리", H1), HR()]

    story += [
        P("5.1 키 생성", H2),
        P("비밀키는 반드시 검증대상 DRBG(CTR-DRBG, KS X 3186 준거)를 통해 생성한다."),
        SP(4),
        tbl([
            ["키 종류",     "생성 방법",           "엔트로피 소스"],
            ["비밀키(MK)", "CTR-DRBG 출력",        "/dev/urandom, CryptGenRandom"],
            ["CBC IV",     "CTR-DRBG 출력",        "/dev/urandom, CryptGenRandom"],
            ["CTR 초기값", "CTR-DRBG 출력 또는 설정", "응용프로그램 제공 허용"],
        ], col_widths=[35*mm, 55*mm, 80*mm]),
        SP(8),

        P("5.2 키 저장 및 배포", H2),
        P("비밀키는 암호모듈 내부 메모리에만 존재하며, 외부 저장매체에 평문으로 기록되지 "
          "않는다."),
        B("키 저장: 운영 중 라운드키(RK)는 프로세스 가상 메모리 내 동적 할당 영역에 존재"),
        B("키 배포: 검증대상 키 설정 메커니즘(직접 전달) 사용, 네트워크 전송 시 암호화 필수"),
        B("키 수명: 비밀키는 응용프로그램의 세션 단위로 유효, 세션 종료 시 제거"),
        SP(8),

        P("5.3 키 제로화", H2),
        P("사용이 완료된 CSP는 재사용이 불가능하도록 즉시 제거해야 한다."),
        SP(4),
        P("제로화 대상:", H3),
        B("비밀키(MK): 라운드키 생성 완료 후 즉시 제거"),
        B("라운드키(RK): 암/복호화 완료 후 또는 세션 종료 시 제거"),
        B("IV/카운터: 사용 완료 후 제거"),
        SP(4),
        P("제로화 구현:", H3),
        P("메모리 초기화는 표준 메모리 초기화 함수를 사용하여 해당 영역을 0으로 덮어쓴다. "
          "구현 시 컴파일러 최적화에 의해 제로화 코드가 제거되지 않도록 주의하여 구현한다.",
          NOTE),
        # ← DOC-022 위반: lea_zeroize() 등 API 함수명 명세 없음
        # ← DOC-040 위반: "절차적 제로화", "운영적 제로화", "volatile" 언급 없음
        SP(4),
        P("제로화 확인: 제로화 수행 후 해당 메모리 영역이 0으로 초기화되었는지 "
          "자가시험을 통해 확인한다."),
        PageBreak(),
    ]

    # ── 6장: 자가시험 ────────────────────────────────────────────
    # DOC-048 위반: 유한상태모델 섹션 전체 없음 (상태천이도, 상태천이표 미등장)
    story += [P("6장. 자가시험", H1), HR()]

    story += [
        P("6.1 전원인가 자가시험 (Power-Up Self-Test)", H2),
        P("암호모듈은 초기화 시 다음 전원인가 자가시험을 수행한다. 자가시험 중에는 "
          "암호 서비스가 제공되지 않으며 데이터 출력이 금지된다."),
        SP(4),
        tbl([
            ["시험 항목",         "시험 방법",                    "대상 알고리즘"],
            ["LEA-CBC KAT",      "알려진 평문/암호문 비교",        "LEA-CBC"],
            ["LEA-CTR KAT",      "알려진 평문/암호문 비교",        "LEA-CTR"],
            ["LEA-GCM KAT",      "알려진 평문/인증태그 비교",      "LEA-GCM"],
            ["LEA-CCM KAT",      "알려진 평문/인증태그 비교",      "LEA-CCM"],
            ["CTR-DRBG KAT",     "알려진 출력값 비교",             "CTR-DRBG"],
            ["소프트웨어 무결성", "HMAC-SHA-256 해시 비교",         "전체 모듈"],
        ], col_widths=[45*mm, 70*mm, 55*mm]),
        SP(6),

        P("6.2 조건부 자가시험 (Conditional Self-Test)", H2),
        B("연속 난수 생성 시험: DRBG에서 연속으로 동일한 값이 출력될 경우 오류 처리"),
        B("소프트웨어 로드 시험: 외부 컴포넌트 로드 시 무결성 검증"),
        SP(6),

        P("6.3 자가시험 실패 처리", H2),
        P("자가시험 실패 시 암호모듈은 심각한 오류 상태(Error State)로 진입하며, "
          "이후 모든 암호 서비스 요청에 대해 오류 코드를 반환하고 암호 연산을 "
          "수행하지 않는다."),
        SP(4),
        tbl([
            ["오류 코드",    "의미",                      "해제 방법"],
            ["LEA_ERR_KAT", "KAT 실패 — 알고리즘 오류",  "암호모듈 재설치"],
            ["LEA_ERR_INT", "무결성 검증 실패",           "암호모듈 재설치"],
            ["LEA_ERR_RNG", "DRBG 연속 중복 출력",        "암호모듈 재시작"],
        ], col_widths=[40*mm, 75*mm, 55*mm]),
        SP(6),

        # NOTE: 유한상태모델 섹션 의도적 누락 (DOC-048 위반)
        P("※ 암호모듈의 동작 상태는 초기화 상태, 동작 상태, 오류 상태로 구분되며 "
          "각 상태 간 전이는 API 호출 및 자가시험 결과에 의해 결정된다.", NOTE),
        PageBreak(),
    ]

    # ── 7장: 설계보증 및 형상관리 ───────────────────────────────
    story += [P("7장. 설계보증 및 형상관리", H1), HR()]

    story += [
        P("7.1 형상관리", H2),
        P("본 암호모듈의 소스코드, 설계 문서, 시험서 등 모든 형상항목은 "
          "Git 형상관리 시스템으로 관리된다."),
        SP(4),
        tbl([
            ["형상항목",      "식별 방법",               "관리 도구"],
            ["소스코드",      "Git 커밋 해시",             "Git"],
            ["설계서",        "문서 버전 V1.0, V1.1 ...",  "Git + 문서 버전"],
            ["시험서",        "시험 버전 T1.0, T1.1 ...",  "Git + 문서 버전"],
            ["실행 라이브러리", "SHA-256 해시값",          "빌드 시스템"],
        ], col_widths=[40*mm, 65*mm, 65*mm]),
        SP(6),

        P("7.2 버전 부여 방법", H2),
        P("버전은 Major.Minor 형식으로 부여한다."),
        B("Major 버전: 암호알고리즘 변경, 보안 요구사항 변경 등 중요 변경 시 증가"),
        B("Minor 버전: 버그 수정, 운영환경 추가, 문서 보완 등 경미한 변경 시 증가"),
        B("각 형상항목의 변경 이력은 Git 로그로 추적하며 변경 시마다 커밋 메시지에 "
          "변경 내역을 기록한다."),
        SP(6),

        P("7.3 개발 보증", H2),
        P("본 암호모듈은 다음 설계 원칙을 준수하여 개발되었다."),
        B("최소 권한 원칙: 각 함수는 필요한 최소한의 CSP에만 접근"),
        B("방어적 프로그래밍: 입력 유효성 검증 후 연산 수행"),
        B("버퍼오버플로우 대응: 경계 검사 강화, 안전한 메모리 함수 사용"),
        SP(8),

        HR(),
        P("본 설계서는 KS X ISO/IEC 19790 및 소프트웨어 암호모듈 검증기준에 "
          "따라 작성되었습니다. 검증 신청 전 시험기관의 사전 검토를 받으시기 바랍니다.",
          NOTE),
    ]

    return story


# ══════════════════════════════════════════════════════════════════
def main() -> None:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    doc = SimpleDocTemplate(
        str(OUTPUT),
        pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=MARGIN,  bottomMargin=MARGIN,
        title="LEA 블록암호 라이브러리 기본 및 상세 설계서 v1.0",
        author="(주) 한국암호기술",
        subject="KCMVP 소프트웨어 암호모듈 설계서",
    )

    story = build_story()
    doc.build(story)

    size = OUTPUT.stat().st_size
    print(f"\n생성 완료: {OUTPUT}")
    print(f"  크기: {size:,} bytes ({size//1024} KB)")
    print()
    print("의도적 위반 포함 현황:")
    print("  DOC-022  ← 5.3절: 제로화 API 함수명(lea_zeroize 등) 명세 없음")
    print("  DOC-040  ← 5.3절: 절차적/운영적 제로화, volatile 키워드 언급 없음")
    print("  DOC-048  ← 6장:   유한상태모델(상태천이도, 상태천이표) 섹션 전체 누락")
    print()
    print("정상 포함 섹션:")
    print("  DOC-001/002  암호모듈 유형 및 경계 ✅")
    print("  DOC-003      검증대상 알고리즘 + CSP 목록 ✅")
    print("  DOC-004      명칭 및 버전 정보 V1.0 ✅")
    print("  DOC-005/031  운영환경 (Linux/Windows 64bit) ✅")
    print("  DOC-012      서비스별 API 명세 ✅")


if __name__ == "__main__":
    main()
