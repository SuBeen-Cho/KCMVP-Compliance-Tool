"""
doc_accuracy_test_v1.zip 생성

3종 문서 (설계서 2개 + 형상관리계획서 1개 + 시험계획서 1개):
  design_pass.pdf   — 주요 DOC 규칙 요건 충족 (N)
  design_fail.pdf   — 주요 DOC 규칙 요건 누락 (P: 여러 missing/semantic 위반)
  config_pass.pdf   — SCM 요건 충족 (N)
  test_pass.pdf     — 시험계획 요건 충족 (N)

Ground Truth (파일 레벨):
  design_pass.pdf   → N  (위반 없음)
  design_fail.pdf   → P  (DOC-001, DOC-004, DOC-007, DOC-009, DOC-010, DOC-017, DOC-022 위반)
  config_pass.pdf   → N
  test_pass.pdf     → N
"""
import io
import zipfile
from pathlib import Path

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak,
    )
    from reportlab.lib import colors
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False

BACKEND_ROOT = Path(__file__).parent.parent
OUT_PATH = BACKEND_ROOT / "testdata" / "doc_accuracy_test_v1.zip"

# ── 폰트 등록 ────────────────────────────────────────────────────────
FONT_NAME = "KoreanFont"
_FONT_CANDIDATES = [
    "/Library/Fonts/Arial Unicode.ttf",
    "/System/Library/AssetsV2/com_apple_MobileAsset_Font7/"
    "bad9b4bf17cf1669dde54184ba4431c22dcad27b.asset/AssetData/NanumGothic.ttc",
]


def _register_font():
    for path in _FONT_CANDIDATES:
        try:
            if path.endswith(".ttc"):
                pdfmetrics.registerFont(TTFont(FONT_NAME, path, subfontIndex=0))
            else:
                pdfmetrics.registerFont(TTFont(FONT_NAME, path))
            return True
        except Exception:
            continue
    return False


def _make_styles(has_korean_font: bool):
    base = getSampleStyleSheet()
    fn = FONT_NAME if has_korean_font else "Helvetica"
    fn_bold = FONT_NAME if has_korean_font else "Helvetica-Bold"

    styles = {
        "title": ParagraphStyle("DocTitle", fontName=fn_bold, fontSize=18,
                                spaceAfter=20, leading=24),
        "h1": ParagraphStyle("H1", fontName=fn_bold, fontSize=14,
                             spaceAfter=10, spaceBefore=16, leading=20),
        "h2": ParagraphStyle("H2", fontName=fn_bold, fontSize=12,
                             spaceAfter=8, spaceBefore=12, leading=18),
        "h3": ParagraphStyle("H3", fontName=fn_bold, fontSize=11,
                             spaceAfter=6, spaceBefore=10, leading=16),
        "body": ParagraphStyle("Body", fontName=fn, fontSize=10,
                               spaceAfter=6, leading=15),
        "toc": ParagraphStyle("TOC", fontName=fn, fontSize=10,
                              spaceAfter=4, leading=14),
    }
    return styles


def _table_style(has_font: bool = True):
    fn = FONT_NAME if has_font else "Helvetica"
    return TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#4472C4")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, -1), fn),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#EEF2FF")]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("PADDING", (0, 0), (-1, -1), 4),
    ])


# ════════════════════════════════════════════════════════════════════
# design_pass.pdf  — 모든 주요 요건 충족 (N)
# ════════════════════════════════════════════════════════════════════
def build_design_pass(has_font: bool) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            leftMargin=2.5*cm, rightMargin=2.5*cm,
                            topMargin=2.5*cm, bottomMargin=2.5*cm)
    s = _make_styles(has_font)
    story = []

    # 표지
    story += [
        Paragraph("KCMVP 암호모듈 설계서", s["title"]),
        Paragraph("버전 정보 V1.0  |  작성일: 2025-01-15", s["body"]),
        Spacer(1, 0.5*cm),
    ]

    # 목차
    story += [
        Paragraph("목 차", s["h1"]),
        Paragraph("1. 개요 ········································ 2", s["toc"]),
        Paragraph("2. 암호모듈 명세 ································ 3", s["toc"]),
        Paragraph("3. 인터페이스 명세 ····························· 5", s["toc"]),
        Paragraph("4. 역할 및 서비스 ······························ 7", s["toc"]),
        Paragraph("5. 소프트웨어 보안 ····························· 9", s["toc"]),
        Paragraph("6. 운영환경 명세 ······························ 11", s["toc"]),
        PageBreak(),
    ]

    # 1. 개요
    story += [
        Paragraph("1. 개요", s["h1"]),
        Paragraph("1.1 목적", s["h2"]),
        Paragraph(
            "본 문서는 KCMVP(국가검증 암호모듈 프로그램) 인증을 위한 암호모듈 설계서이다. "
            "암호모듈 유형 : 소프트웨어로, 순수 소프트웨어로 구현된 LEA 블록암호 라이브러리이다. "
            "하드웨어에 의존하지 않으며, 운영체제 위에서 실행되는 소프트웨어 형태로 배포된다.",
            s["body"]),
        Paragraph("1.2 적용 범위", s["h2"]),
        Paragraph(
            "본 설계서는 LEA-128/192/256 블록암호 및 CBC, CTR, GCM, CCM, CMAC 운영모드를 "
            "포함한 암호모듈 전반에 적용된다.",
            s["body"]),
        PageBreak(),
    ]

    # 2. 암호모듈 명세
    story += [
        Paragraph("2. 암호모듈 명세", s["h1"]),
        Paragraph("2.1 암호모듈 경계 및 구성요소", s["h2"]),
        Paragraph(
            "암호 경계 및 구현물 경계는 liblea.so 단일 공유 라이브러리로 정의된다. "
            "구성요소는 다음과 같다: (1) 블록암호 엔진, (2) 운영모드 처리기, "
            "(3) 자가시험 모듈, (4) 제로화(zeroize) 모듈.",
            s["body"]),
        Paragraph("2.2 검증대상 암호알고리즘 목록 및 CSP 명세", s["h2"]),
        Paragraph(
            "검증대상 암호알고리즘 목록: LEA-128, LEA-192, LEA-256 블록암호 및 "
            "CBC, CTR, GCM, CCM, CMAC 운영모드. "
            "비검증대상 암호알고리즘 목록: 본 암호모듈에는 비검증대상 암호알고리즘이 포함하지 않는다.",
            s["body"]),
        Paragraph(
            "핵심 보안매개변수(CSP): 비밀키, 라운드키, IV, 세션키가 CSP에 해당하며 "
            "CSP 생성부터 소멸까지 전 주기를 관리한다.",
            s["body"]),
    ]

    # CSP 표
    csp_data = [
        ["CSP 이름", "종류", "크기", "생성", "소멸(제로화)"],
        ["비밀키(Secret Key)", "대칭키", "128/192/256비트", "DRBG 생성", "lea_zeroize()"],
        ["라운드키(Round Key)", "파생키", "가변", "키 스케줄", "lea_zeroize()"],
        ["초기화벡터(IV)", "공개 파라미터", "128비트", "CSPRNG", "사용 후 즉시"],
        ["세션키(Session Key)", "대칭키", "256비트", "KDF 파생", "세션 종료 시"],
    ]
    csp_table = Table(csp_data, colWidths=[3.5*cm, 2.5*cm, 3*cm, 3*cm, 3*cm])
    csp_table.setStyle(_table_style(has_font))
    story += [csp_table, Spacer(1, 0.3*cm)]

    story += [
        Paragraph("2.3 동작모드·서비스 간 CSP 독립적 분리", s["h2"]),
        Paragraph(
            "동작모드 간 CSP 분리: 각 암호 서비스 호출 시 독립적인 컨텍스트 구조체를 할당하며, "
            "서비스 간 CSP 독립 관리를 보장한다. 운영모드 전환 시 이전 세션의 CSP를 "
            "lea_zeroize() 함수로 제로화한 후 새로운 컨텍스트를 초기화한다.",
            s["body"]),
        PageBreak(),
    ]

    # 3. 인터페이스 명세
    story += [
        Paragraph("3. 인터페이스 명세", s["h1"]),
        Paragraph("3.1 물리적 포트 및 논리적 인터페이스", s["h2"]),
        Paragraph(
            "물리적 포트: 소프트웨어 모듈이므로 별도 물리적 포트 없음. "
            "논리적 인터페이스: 데이터 입력(평문/암호문), 데이터 출력(암호문/평문), "
            "제어 입력(API 파라미터), 상태 출력(반환값/오류코드)으로 구성된다.",
            s["body"]),
        Paragraph("3.2 서비스별 인터페이스 상세", s["h2"]),
    ]

    iface_data = [
        ["API 명", "데이터 입력", "데이터 출력", "제어 입력", "상태 출력"],
        ["lea_encrypt()", "평문, 키", "암호문", "모드 파라미터", "반환값(0/-1)"],
        ["lea_decrypt()", "암호문, 키", "평문", "모드 파라미터", "반환값(0/-1)"],
        ["lea_zeroize()", "메모리 포인터", "-", "크기", "반환값"],
    ]
    iface_table = Table(iface_data, colWidths=[3*cm, 3*cm, 3*cm, 3*cm, 3*cm])
    iface_table.setStyle(_table_style(has_font))
    story += [iface_table, Spacer(1, 0.3*cm)]

    story += [
        Paragraph("3.3 출력 금지 메커니즘", s["h2"]),
        Paragraph(
            "자가시험, 제로화, 오류 상태에서는 데이터 출력 금지 및 제어 출력 금지를 "
            "API 내부 상태 플래그로 보장한다. 상태 확인 후 출력을 통제하는 메커니즘이 적용된다.",
            s["body"]),
        Paragraph("3.4 상태 표시기", s["h2"]),
        Paragraph(
            "모든 API는 성공(0), 실패(-1)를 반환값으로 제공한다. 상태 출력 및 오류코드는 "
            "상태값 열거형으로 정의되어 있으며, 단순한 오류와 심각한 오류를 구분한다.",
            s["body"]),
        PageBreak(),
    ]

    # 4. 역할 및 서비스
    story += [
        Paragraph("4. 역할 및 서비스", s["h1"]),
        Paragraph("4.1 역할 정의", s["h2"]),
        Paragraph(
            "본 암호모듈은 암호 관리자(Crypto Officer)와 일반 사용자(User) 두 역할을 정의한다. "
            "동시 운영자는 지원하지 않으며, 각 역할은 독립적으로 운영된다.",
            s["body"]),
        Paragraph(
            "인가된 역할: 관리자는 키 생성/소멸, 자가시험 호출 권한을 보유한다. "
            "일반 사용자는 암호화/복호화 서비스 이용 권한을 보유한다.",
            s["body"]),
        Paragraph("4.2 암호 서비스 목록", s["h2"]),
    ]

    svc_data = [
        ["서비스명", "설명", "허가 역할", "CSP 접근"],
        ["키 생성", "DRBG로 대칭키 생성", "암호 관리자", "W"],
        ["암호화", "LEA 블록암호 암호화", "일반 사용자", "R"],
        ["복호화", "LEA 블록암호 복호화", "일반 사용자", "R"],
        ["제로화", "CSP 메모리 제로화", "암호 관리자", "D"],
        ["자가시험", "동작 전 자가시험 호출", "암호 관리자", "-"],
        ["버전 출력", "버전 정보 확인", "일반 사용자", "-"],
        ["상태 확인", "모듈 상태 출력", "일반 사용자", "-"],
    ]
    svc_table = Table(svc_data, colWidths=[3*cm, 5*cm, 4*cm, 3*cm])
    svc_table.setStyle(_table_style(has_font))
    story += [svc_table, Spacer(1, 0.3*cm), PageBreak()]

    # 5. 소프트웨어 보안
    story += [
        Paragraph("5. 소프트웨어 보안", s["h1"]),
        Paragraph("5.1 무결성 기법", s["h2"]),
        Paragraph(
            "소프트웨어 무결성 기법으로 HMAC-SHA256을 사용하여 모듈 로드 시 무결성 검증을 수행한다. "
            "무결성 검증키는 분산 저장되며, 서명검증키 보호를 위한 추가 메커니즘이 적용된다.",
            s["body"]),
        Paragraph(
            "무결성 시험 실패 시: 오류 상태로 전환하며 중간 데이터 제로화 및 임시 변수 제로화를 수행한다.",
            s["body"]),
        Paragraph("5.2 자가시험", s["h2"]),
        Paragraph(
            "사용자 동작 전 자가시험: lea_selftest() API를 통해 동작 전 자가시험 호출이 가능하다. "
            "운영자 요구 무결성 시험 API로 lea_integrity_check()를 제공한다.",
            s["body"]),
        Paragraph("5.3 제로화", s["h2"]),
        Paragraph(
            "제로화 API 함수명: lea_zeroize(void *ptr, size_t len). "
            "모든 CSP(비밀키, 라운드키, IV)는 사용 후 lea_zeroize() 함수로 제로화된다.",
            s["body"]),
        Paragraph("5.4 인증 데이터 보호", s["h2"]),
        Paragraph(
            "인증 데이터 보호: 암호모듈은 자체적인 인증메커니즘을 포함하지 않으며 "
            "운영체제의 인증 메커니즘을 활용한다. "
            "인증 소멸: 이전 인증 데이터 제거 및 운영체제 종료 시 자동 소멸된다.",
            s["body"]),
        Paragraph("5.5 역할 할당", s["h2"]),
        Paragraph(
            "암묵적 역할 할당: 최초 실행 시 기본 역할(일반 사용자)이 자동 할당된다. "
            "명시적 역할 할당: lea_set_role() API를 통해 역할을 명시적으로 지정할 수 있다. "
            "운영환경 인증 방식과 연동하여 역할이 설정된다.",
            s["body"]),
        PageBreak(),
    ]

    # 6. 운영환경
    story += [
        Paragraph("6. 운영환경 명세", s["h1"]),
        Paragraph("6.1 지원 운영환경", s["h2"]),
        Paragraph(
            "소프트웨어 운영환경: Linux (Ubuntu 22.04 LTS, CentOS 8), "
            "Windows Server 2022, macOS 13 이상. "
            "컴파일러: GCC 11+, Clang 14+. 아키텍처: x86-64, ARM64.",
            s["body"]),
        Paragraph("6.2 검증대상 동작모드 실행 방법", s["h2"]),
        Paragraph(
            "검증대상 동작모드 실행: lea_init() → 운영모드 설정 → 서비스 호출 순으로 진행된다. "
            "동작모드 천이: lea_mode_switch() API를 통해 동작모드 천이 및 호출이 가능하다. "
            "자동 초기화 옵션은 설정 파일을 통해 제어한다.",
            s["body"]),
    ]

    # 7. 추가 보안 요건
    story += [
        Paragraph("7. 추가 보안 요건", s["h1"]),
        Paragraph("7.1 안전한 배포 및 설치 무결성", s["h2"]),
        Paragraph(
            "안전한 배포: liblea.so 배포 시 SHA-256 해시값을 제공하며, 설치 전 변경 여부 확인을 위해 "
            "해시값 비교를 수행한다. 검증필 확인 절차를 통해 무결성을 보장한다.",
            s["body"]),
        Paragraph("7.2 운영환경 상세 정보", s["h2"]),
        Paragraph(
            "지원 운영체제: Windows 10/11 64bit, Ubuntu 22.04 64bit, CentOS 8 64bit. "
            "운영환경 버전: 각 OS 최신 패치 버전 기준.",
            s["body"]),
        Paragraph("7.3 프로세스 및 메모리 보호", s["h2"]),
        Paragraph(
            "가상 메모리 분리: 암호모듈은 독립 프로세스 보호 메커니즘을 적용한다. "
            "ASLR(Address Space Layout Randomization)과 DEP(Data Execution Prevention)를 활성화하여 "
            "간섭 방지 및 접근 방지를 보장한다.",
            s["body"]),
        Paragraph("7.4 자식 프로세스 소유권 제한", s["h2"]),
        Paragraph(
            "암호모듈은 별도의 자식 프로세스를 생성하지 않으며, 프로세스 생성 소유권을 제한한다.",
            s["body"]),
        Paragraph("7.5 CSP/PSP 보호", s["h2"]),
        Paragraph(
            "인가되지 않은 접근 및 사용, 노출, 변경, 대체로부터 CSP 보호 및 PSP 보호를 위한 "
            "메커니즘을 제공한다.",
            s["body"]),
        Paragraph("7.6 난수발생기 및 엔트로피", s["h2"]),
        Paragraph(
            "난수발생기 상태 정보는 CSP로 간주하여 관리한다. 엔트로피 CSP, 중간값 CSP도 동등하게 보호된다. "
            "외부 잡음원 이름: OS DRBG. 최종 엔트로피 출력은 CSP로 분류한다.",
            s["body"]),
        Paragraph("7.7 SSP 관리", s["h2"]),
        Paragraph(
            "SSP 생성은 난수발생기를 통해 수행된다. 자동화된 SSP 설정으로 키 합의 및 키 전송 프로토콜을 지원한다. "
            "SSP 주입: 평문 주입 불가. SSP 출력: 암호화된 출력만 허용. 넘나드는 SSP는 없다. "
            "PSP 변경 금지: 인가되지 않은 변경을 차단한다.",
            s["body"]),
        Paragraph("7.8 제로화", s["h2"]),
        Paragraph(
            "절차적 제로화 및 운영적 제로화를 지원한다. "
            "volatile 키워드를 사용한 Zeroize 함수로 복구될 수 없는 제로화를 수행한다.",
            s["body"]),
        Paragraph("7.9 자가시험 오류 처리", s["h2"]),
        Paragraph(
            "자가시험 실패 시 오류 발생 조건을 로그에 기록하고 해제 방법으로 재시작 또는 재설치를 제공한다. "
            "오류 상태에서는 서비스 제한 및 암호연산 금지, 출력 금지를 적용한다. "
            "자가시험 오류가 해결되기 전까지 정상 동작을 중단한다.",
            s["body"]),
        Paragraph("7.10 무결성 시험 순서", s["h2"]),
        Paragraph(
            "무결성 시험 전 알고리즘 시험(KAT)을 먼저 수행한다. 무결성 기술 핵심기능시험이 선행되어야 한다. "
            "동작 전 핵심기능시험(KAT) 수행 방법: 테스트벡터를 이용한 기지 답안 비교.",
            s["body"]),
        Paragraph("7.11 건전성 시험 및 키쌍 일치 시험", s["h2"]),
        Paragraph(
            "엔트로피 잡음원 건전성 시험: 반복 횟수 테스트(Repetition Count Test)와 "
            "적응성 비율 테스트(Adaptive Proportion Test)를 수행한다. "
            "조건부 키쌍 일치 시험: 키쌍 유효성을 생성 직후 확인한다.",
            s["body"]),
        Paragraph("7.12 주기적 자가시험", s["h2"]),
        Paragraph(
            "주기적 자가시험을 제공하며 설정된 주기마다 자동으로 동작한다.",
            s["body"]),
        Paragraph("7.13 유한상태모델", s["h2"]),
        Paragraph(
            "유한상태모델, 상태천이도 및 상태천이표로 암호모듈의 상태 전이를 정의한다.",
            s["body"]),
        Paragraph("7.14 오류 복구", s["h2"]),
        Paragraph(
            "단순한 오류 발생 시 자동 천이를 통해 복구 가능하며 정상 천이 절차를 따른다.",
            s["body"]),
        Paragraph("7.15 개발환경", s["h2"]),
        Paragraph(
            "개발 환경: GCC 11, Visual Studio 2022. 컴파일러 및 컴파일 옵션, 빌드 도구 상세: cmake 3.25.",
            s["body"]),
        Paragraph("7.16 보안 진단", s["h2"]),
        Paragraph(
            "자동화 보안 진단 및 취약점 점검: 정적 분석 도구 사용. 취약한 함수 제거 적용.",
            s["body"]),
        Paragraph("7.17 수명 종료 소거", s["h2"]),
        Paragraph(
            "수명 종료 시 안전한 소거: 덮어쓰기 후 삭제 방식 적용.",
            s["body"]),
        Paragraph("7.18 운영 안내서", s["h2"]),
        Paragraph(
            "관리자 안내서와 비관리자 안내서를 분리하여 제공한다.",
            s["body"]),
        Paragraph("7.19 타이밍 공격 대응", s["h2"]),
        Paragraph(
            "시간차 공격 및 타이밍 공격 대응: constant-time 알고리즘 적용. 더미 연산 및 마스킹 분산 기법 사용.",
            s["body"]),
        Paragraph("7.20 버퍼오버플로우 방어", s["h2"]),
        Paragraph(
            "버퍼오버플로우 오류 방지: 입력값 형식검증 및 입력 인자 검사를 통해 구조적으로 방어한다.",
            s["body"]),
    ]

    doc.build(story)
    return buf.getvalue()


# ════════════════════════════════════════════════════════════════════
# design_fail.pdf  — 핵심 요건 누락 (P)
# 누락 위반: DOC-001(유형 미명시), DOC-004(버전 없음), DOC-007(알고리즘 목록 없음),
#            DOC-009(CSP 분리 없음), DOC-010(상태 표시기 없음),
#            DOC-017(관리자/사용자 역할 없음), DOC-022(제로화 API 없음)
# ════════════════════════════════════════════════════════════════════
def build_design_fail(has_font: bool) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            leftMargin=2.5*cm, rightMargin=2.5*cm,
                            topMargin=2.5*cm, bottomMargin=2.5*cm)
    s = _make_styles(has_font)
    story = []

    # 표지 — 버전 정보 없음 (DOC-004 위반)
    story += [
        Paragraph("암호모듈 설계서", s["title"]),
        Paragraph("작성일: 2025-01-15", s["body"]),
        Spacer(1, 0.5*cm),
    ]

    # 목차
    story += [
        Paragraph("목 차", s["h1"]),
        Paragraph("1. 개요 ··················· 2", s["toc"]),
        Paragraph("2. 암호모듈 구성 ··········· 3", s["toc"]),
        Paragraph("3. 인터페이스 ·············· 4", s["toc"]),
        Paragraph("4. 역할 ···················· 5", s["toc"]),
        PageBreak(),
    ]

    # 1. 개요 — 암호모듈 유형 명시 없음 (DOC-001 위반)
    story += [
        Paragraph("1. 개요", s["h1"]),
        Paragraph("1.1 목적", s["h2"]),
        Paragraph(
            "본 문서는 LEA 암호 라이브러리에 대한 설계 문서이다. "
            "암호화 기능을 제공하는 라이브러리로서 다양한 환경에서 동작한다.",
            s["body"]),
        # DOC-001 위반: '암호모듈 유형'과 '소프트웨어/하드웨어/펌웨어/하이브리드' 연관 서술 없음
        Paragraph("1.2 배경", s["h2"]),
        Paragraph(
            "국내 KCMVP 인증을 목표로 개발된 암호 라이브러리이다. "
            "블록암호 LEA 알고리즘을 기반으로 한다.",
            s["body"]),
        PageBreak(),
    ]

    # 2. 암호모듈 구성 — 알고리즘 목록 누락(DOC-007), CSP 분리 누락(DOC-009)
    story += [
        Paragraph("2. 암호모듈 구성", s["h1"]),
        Paragraph("2.1 구성 개요", s["h2"]),
        Paragraph(
            "암호모듈은 LEA 블록암호 엔진과 운영모드 처리기로 구성된다. "
            "암호 경계는 liblea.so 파일로 정의된다.",
            s["body"]),
        # DOC-007 위반: 검증대상/비검증대상 암호알고리즘 목록 없음
        Paragraph("2.2 알고리즘 개요", s["h2"]),
        Paragraph(
            "LEA 블록암호 알고리즘을 사용한다. 128비트 블록 크기를 지원한다.",
            s["body"]),
        # DOC-009 위반: 동작모드 간 CSP 독립 분리 명세 없음
        Paragraph("2.3 키 관리", s["h2"]),
        Paragraph(
            "키 생성은 DRBG를 통해 수행된다. 키 길이는 128, 192, 256비트를 지원한다.",
            s["body"]),
        # DOC-022 위반: lea_zeroize 등 제로화 API 함수명 없음
        Paragraph("2.4 보안 기능", s["h2"]),
        Paragraph(
            "암호화 및 복호화 후 키 메모리를 초기화한다. 안전한 메모리 관리를 수행한다.",
            s["body"]),
        PageBreak(),
    ]

    # 3. 인터페이스 — 상태 표시기 없음(DOC-010)
    story += [
        Paragraph("3. 인터페이스 명세", s["h1"]),
        Paragraph("3.1 API 목록", s["h2"]),
        Paragraph(
            "lea_encrypt(): 암호화 수행. lea_decrypt(): 복호화 수행. "
            "lea_init(): 초기화.",
            s["body"]),
        # DOC-010 위반: 상태 출력, 반환값, 오류코드 명세 없음
        Paragraph("3.2 입출력 형식", s["h2"]),
        Paragraph(
            "입력: 키, 평문 데이터. 출력: 암호문 데이터. "
            "모든 파라미터는 포인터 형태로 전달된다.",
            s["body"]),
        PageBreak(),
    ]

    # 4. 역할 — 관리자/사용자 구분 없음(DOC-017)
    story += [
        Paragraph("4. 역할", s["h1"]),
        Paragraph("4.1 사용자 역할", s["h2"]),
        Paragraph(
            "암호모듈을 사용하는 사용자는 라이브러리 API를 호출하여 "
            "암호화/복호화 서비스를 이용한다.",
            s["body"]),
        # DOC-017 위반: '암호 관리자'와 '일반 사용자' 구분 명세 없음
        Paragraph("4.2 접근 제어", s["h2"]),
        Paragraph(
            "라이브러리 호출자는 운영체제 수준의 접근 제어를 따른다.",
            s["body"]),
    ]

    doc.build(story)
    return buf.getvalue()


# ════════════════════════════════════════════════════════════════════
# config_pass.pdf  — 형상관리계획서 요건 충족 (N)
# ════════════════════════════════════════════════════════════════════
def build_config_pass(has_font: bool) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            leftMargin=2.5*cm, rightMargin=2.5*cm,
                            topMargin=2.5*cm, bottomMargin=2.5*cm)
    s = _make_styles(has_font)
    story = []

    story += [
        Paragraph("KCMVP 형상관리계획서", s["title"]),
        Paragraph("버전 정보 V1.0  |  작성일: 2025-01-15", s["body"]),
        Spacer(1, 0.5*cm),
    ]

    story += [
        Paragraph("목 차", s["h1"]),
        Paragraph("1. 형상관리 개요 ····················· 2", s["toc"]),
        Paragraph("2. 형상항목 목록 ····················· 3", s["toc"]),
        Paragraph("3. 변경관리 절차 ····················· 4", s["toc"]),
        PageBreak(),
    ]

    story += [
        Paragraph("1. 형상관리 개요", s["h1"]),
        Paragraph("1.1 목적", s["h2"]),
        Paragraph(
            "본 계획서는 KCMVP 인증을 위한 암호모듈의 형상관리 절차를 정의한다. "
            "형상항목의 식별, 변경관리, 감사 절차를 포함한다.",
            s["body"]),
        Paragraph("1.2 형상관리 도구", s["h2"]),
        Paragraph(
            "형상관리 도구: Git (버전 관리 시스템). 형상항목 식별자: 태그 및 커밋 해시. "
            "형상관리 절차는 GitFlow 브랜치 전략을 따른다.",
            s["body"]),
        PageBreak(),
    ]

    story += [
        Paragraph("2. 형상항목 목록", s["h1"]),
    ]

    ci_data = [
        ["형상항목 ID", "항목명", "버전", "유형", "위치"],
        ["CI-001", "소스코드 (liblea.so)", "V1.0", "소프트웨어", "src/"],
        ["CI-002", "설계서", "V1.0", "문서", "docs/design/"],
        ["CI-003", "시험계획서", "V1.0", "문서", "docs/test/"],
        ["CI-004", "형상관리계획서", "V1.0", "문서", "docs/config/"],
        ["CI-005", "빌드 스크립트", "V1.0", "도구", "build/"],
    ]
    ci_table = Table(ci_data, colWidths=[2.5*cm, 4*cm, 2*cm, 3*cm, 3.5*cm])
    ci_table.setStyle(_table_style(has_font))
    story += [ci_table, Spacer(1, 0.3*cm)]

    story += [
        Paragraph("3. 변경관리 절차", s["h1"]),
        Paragraph("3.1 변경 요청", s["h2"]),
        Paragraph(
            "변경 요청 절차: 변경 요청서 작성 → 검토 → 승인 → 적용 → 검증. "
            "모든 변경은 형상 관리 시스템에 기록되며 추적 가능하다.",
            s["body"]),
        Paragraph("3.2 형상 감사", s["h2"]),
        Paragraph(
            "정기적 형상 감사를 통해 형상항목의 완전성 및 무결성을 검증한다. "
            "감사 결과는 형상 감사 보고서로 문서화된다.",
            s["body"]),
    ]

    doc.build(story)
    return buf.getvalue()


# ════════════════════════════════════════════════════════════════════
# test_pass.pdf  — 시험계획서 요건 충족 (N)
# ════════════════════════════════════════════════════════════════════
def build_test_pass(has_font: bool) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                            leftMargin=2.5*cm, rightMargin=2.5*cm,
                            topMargin=2.5*cm, bottomMargin=2.5*cm)
    s = _make_styles(has_font)
    story = []

    story += [
        Paragraph("KCMVP 암호모듈 시험계획서", s["title"]),
        Paragraph("버전 정보 V1.0  |  작성일: 2025-01-20", s["body"]),
        Spacer(1, 0.5*cm),
    ]

    story += [
        Paragraph("목 차", s["h1"]),
        Paragraph("1. 시험 개요 ··················· 2", s["toc"]),
        Paragraph("2. 시험 항목 ··················· 3", s["toc"]),
        Paragraph("3. 기지 시험벡터 ··············· 4", s["toc"]),
        PageBreak(),
    ]

    story += [
        Paragraph("1. 시험 개요", s["h1"]),
        Paragraph("1.1 목적", s["h2"]),
        Paragraph(
            "본 시험계획서는 KCMVP 인증을 위한 암호모듈의 기능 시험 절차를 정의한다. "
            "알고리즘 정확성, 운영모드 적합성, 자가시험 동작을 포함한다.",
            s["body"]),
        Paragraph("1.2 시험 범위", s["h2"]),
        Paragraph(
            "시험 환경: Ubuntu 22.04 64bit, GCC 11. "
            "대상 알고리즘: LEA-128/192/256 블록암호, CBC/CTR/GCM/CCM/CMAC 운영모드.",
            s["body"]),
        PageBreak(),
    ]

    story += [
        Paragraph("2. 시험 항목", s["h1"]),
    ]

    test_data = [
        ["시험 ID", "시험명", "시험 유형", "판정 기준"],
        ["TC-001", "LEA-128 암호화 정확성", "KAT", "기준값 일치"],
        ["TC-002", "LEA-192 암호화 정확성", "KAT", "기준값 일치"],
        ["TC-003", "LEA-256 암호화 정확성", "KAT", "기준값 일치"],
        ["TC-004", "CBC 운영모드 시험", "MCT", "통계적 기준"],
        ["TC-005", "CTR 운영모드 시험", "MCT", "통계적 기준"],
        ["TC-006", "자가시험 동작 확인", "기능 시험", "PASS/FAIL"],
        ["TC-007", "제로화 기능 확인", "기능 시험", "메모리 초기화 확인"],
    ]
    test_table = Table(test_data, colWidths=[2*cm, 5*cm, 3*cm, 5*cm])
    test_table.setStyle(_table_style(has_font))
    story += [test_table, Spacer(1, 0.3*cm)]

    story += [
        Paragraph("3. 기지 시험벡터 (KAT)", s["h1"]),
        Paragraph("3.1 LEA-128 시험벡터", s["h2"]),
    ]

    kat_data = [
        ["항목", "값"],
        ["평문(PT)", "0x0f0e0d0c0b0a09080706050403020100"],
        ["키(KEY)", "0x0f0e0d0c0b0a09080706050403020100"],
        ["암호문(CT)", "0x9b9b7bea0d0d7d6c4d1a0ba47e8e2c05"],
    ]
    kat_table = Table(kat_data, colWidths=[4*cm, 11*cm])
    kat_table.setStyle(_table_style(has_font))
    story += [kat_table]

    story += [
        Paragraph("3.2 테스트벡터 출처 및 참조 표준", s["h2"]),
        Paragraph(
            "테스트벡터 출처: 사전검증 시스템(국보연 제공 표준 테스트벡터). "
            "참조 표준: TTAK.KO-12.0223",
            s["body"]),
        Paragraph("4. 시험 절차 및 증빙", s["h1"]),
        Paragraph("4.1 시험 절차", s["h2"]),
        Paragraph(
            "각 알고리즘 시험의 예상 시험결과와 실제 시험결과를 비교한다. "
            "화면 캡쳐 및 디버깅 메시지 로그를 증빙으로 보관한다.",
            s["body"]),
        Paragraph("4.2 관리 API 시험", s["h2"]),
        Paragraph(
            "관리 API 시험: 상태확인 시험 및 주기적 자가시험 시험을 포함한다.",
            s["body"]),
        Paragraph("4.3 오류 주입 시험", s["h2"]),
        Paragraph(
            "의도적으로 잘못된 입력을 주입하여 오류 출력 시험을 수행한다. "
            "데이터 출력 금지 및 오류코드 반환 동작을 확인한다.",
            s["body"]),
    ]

    doc.build(story)
    return buf.getvalue()


# ════════════════════════════════════════════════════════════════════
# Ground Truth 구성
# ════════════════════════════════════════════════════════════════════
GROUND_TRUTH = """\
# DOC 정확도 테스트 v1 Ground Truth
# 형식: 파일명 | P/N | 위반규칙(P인 경우) | 설명
#
# 파일 레벨 판정:
#   N = 해당 문서가 관련 DOC 규칙을 모두 충족
#   P = 해당 문서가 하나 이상의 DOC 규칙을 위반
#
design/design_pass.pdf | N | - | 주요 DOC 규칙 모두 충족
design/design_fail.pdf | P | DOC-001,DOC-004,DOC-007,DOC-009,DOC-010,DOC-017,DOC-022 | 핵심 요건 7개 누락
config_mgmt/config_pass.pdf | N | - | SCM 요건 충족
test/test_pass.pdf | N | - | 시험계획 요건 충족
"""

VIOLATION_DETAIL = """\
# 위반 상세 (design_fail.pdf)
# rule_id | pattern_type | 설명
DOC-001 | missing | 암호모듈 유형(소프트웨어/하드웨어/펌웨어/하이브리드) 명시 없음
DOC-004 | missing | 버전 정보(V숫자) 없음
DOC-007 | missing | 검증대상/비검증대상 암호알고리즘 목록 없음
DOC-009 | missing | 동작모드 간 CSP 독립 분리 명세 없음
DOC-010 | missing | 상태 표시기(반환값/오류코드) 명세 없음
DOC-017 | missing | 암호 관리자 + 일반 사용자 역할 구분 없음
DOC-022 | missing | lea_zeroize 등 제로화 API 함수명 없음
"""


def build_zip():
    if not HAS_REPORTLAB:
        print("ERROR: reportlab not installed. Run: pip install reportlab")
        return

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    has_font = _register_font()
    if not has_font:
        print("WARNING: Korean font not found. Using Helvetica (Korean text may not render).")

    design_pass_pdf  = build_design_pass(has_font)
    design_fail_pdf  = build_design_fail(has_font)
    config_pass_pdf  = build_config_pass(has_font)
    test_pass_pdf    = build_test_pass(has_font)

    with zipfile.ZipFile(OUT_PATH, "w", zipfile.ZIP_DEFLATED) as zout:
        zout.writestr("docs/design/design_pass.pdf",      design_pass_pdf)
        zout.writestr("docs/design/design_fail.pdf",      design_fail_pdf)
        zout.writestr("docs/config_mgmt/config_pass.pdf", config_pass_pdf)
        zout.writestr("docs/test/test_pass.pdf",          test_pass_pdf)
        zout.writestr("GROUND_TRUTH.md",                  GROUND_TRUTH)
        zout.writestr("VIOLATION_DETAIL.md",              VIOLATION_DETAIL)

    print(f"Created: {OUT_PATH}")
    print(f"  design_pass.pdf : N (통과 기준)")
    print(f"  design_fail.pdf : P (7개 위반 포함)")
    print(f"  config_pass.pdf : N")
    print(f"  test_pass.pdf   : N")
    print(f"Korean font: {'OK' if has_font else 'MISSING (Helvetica fallback)'}")


if __name__ == "__main__":
    build_zip()
