"""
KCMVP 가이드라인 MD 파일 + Gemini 연결 통합 테스트.

검증 항목:
  [G1]  모든 가이드라인 파일 존재 확인
  [G2]  frontmatter 필수 필드 (rule_id, title, kcmvp_ref, severity) 검증
  [G3]  LEA-API_functions.md — 26개 API 함수 모두 포함 확인
  [G4]  block-cipher-modes.md — ECB/CBC/CTR/CFB/OFB/GCM/CCM 모두 포함 확인
  [G5]  ssp-management.md — SSP 관리 표 6개 항목 포함 확인
  [G6]  kcmvp-verified-algorithms.md — 검증대상 알고리즘 목록 확인
  [G7]  TRC-traceability.md — TRC-001/002/003 모두 포함 확인
  [G8]  submission-document-guide.md — 제출 문서 주요 섹션 포함 확인
  [G9]  Gemini API 연결 상태 확인
  [G10] L2_PROVIDER 설정 확인

실행:
  cd backend
  venv/bin/python3 scripts/test_guidelines.py
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

_results: List[Dict[str, Any]] = []


def ok(name: str, detail: str = "") -> None:
    _results.append({"name": name, "pass": True})
    print(f"  [PASS] {name}" + (f" — {detail}" if detail else ""))


def fail(name: str, reason: str) -> None:
    _results.append({"name": name, "pass": False, "detail": reason})
    print(f"  [FAIL] {name} — {reason}")


def warn(name: str, reason: str) -> None:
    """통과이지만 주의가 필요한 경우."""
    _results.append({"name": name, "pass": True})
    print(f"  [WARN] {name} — {reason}")


def section(title: str) -> None:
    print(f"\n{'='*60}\n  {title}\n{'='*60}")


GUIDELINES_DIR = BACKEND / "guidelines"

EXPECTED_FILES = [
    "LEA-API_functions.md",
    "block-cipher-modes.md",
    "ssp-management.md",
    "kcmvp-verified-algorithms.md",
    "TRC-traceability.md",
    "submission-document-guide.md",
]

REQUIRED_FRONTMATTER = ["rule_id", "title", "kcmvp_ref", "severity"]


def _read(filename: str) -> str:
    return (GUIDELINES_DIR / filename).read_text(encoding="utf-8")


def _has_frontmatter_field(text: str, field: str) -> bool:
    for line in text.split("\n")[:20]:
        if line.startswith(f"{field}:"):
            return True
    return False


# ─────────────────────────────────────────────────────────────────
# G1: 파일 존재 확인
# ─────────────────────────────────────────────────────────────────
def test_files_exist() -> None:
    section("G1: 가이드라인 파일 존재 확인")
    missing = [f for f in EXPECTED_FILES if not (GUIDELINES_DIR / f).exists()]
    if missing:
        fail("G1", f"누락된 파일: {missing}")
    else:
        ok("G1", f"{len(EXPECTED_FILES)}개 파일 모두 존재")


# ─────────────────────────────────────────────────────────────────
# G2: frontmatter 필수 필드
# ─────────────────────────────────────────────────────────────────
def test_frontmatter() -> None:
    section("G2: frontmatter 필수 필드 검증")
    all_ok = True
    for filename in EXPECTED_FILES:
        path = GUIDELINES_DIR / filename
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        missing_fields = [f for f in REQUIRED_FRONTMATTER if not _has_frontmatter_field(text, f)]
        if missing_fields:
            fail("G2", f"{filename}: 누락 필드 {missing_fields}")
            all_ok = False
    if all_ok:
        ok("G2", "모든 파일에 필수 frontmatter 필드 존재")


# ─────────────────────────────────────────────────────────────────
# G3: LEA API 함수 26개 확인
# ─────────────────────────────────────────────────────────────────
LEA_FUNCTIONS = [
    "lea_set_key",
    "lea_ecb_enc", "lea_ecb_dec",
    "lea_cbc_enc", "lea_cbc_dec",
    "lea_ctr_enc", "lea_ctr_dec",
    "lea_cfb128_enc", "lea_cfb128_dec",
    "lea_ofb_enc", "lea_ofb_dec",
    "lea_online_init", "lea_online_init_ex",
    "lea_online_update", "lea_online_final",
    "lea_ccm_enc", "lea_ccm_dec",
    "lea_gcm_init", "lea_gcm_set_ctr", "lea_gcm_set_aad",
    "lea_gcm_encrypt", "lea_gcm_decrypt", "lea_gcm_final",
    "lea_cmac_init", "lea_cmac_update", "lea_cmac_final",
]


def test_lea_api() -> None:
    section("G3: LEA API 함수 26개 포함 확인")
    filename = "LEA-API_functions.md"
    if not (GUIDELINES_DIR / filename).exists():
        fail("G3", f"{filename} 파일 없음")
        return
    text = _read(filename)
    missing = [fn for fn in LEA_FUNCTIONS if fn not in text]
    if missing:
        fail("G3", f"누락 함수: {missing}")
    else:
        ok("G3", f"LEA API 26개 함수 모두 포함 (lea_set_key ~ lea_cmac_final)")


# ─────────────────────────────────────────────────────────────────
# G4: 블록암호 운영모드 7개 확인
# ─────────────────────────────────────────────────────────────────
def test_block_cipher_modes() -> None:
    section("G4: 블록암호 운영모드 ECB/CBC/CTR/CFB/OFB/GCM/CCM 포함")
    filename = "block-cipher-modes.md"
    if not (GUIDELINES_DIR / filename).exists():
        fail("G4", f"{filename} 파일 없음")
        return
    text = _read(filename)
    modes = ["ECB", "CBC", "CFB", "OFB", "CTR", "GCM", "CCM"]
    missing = [m for m in modes if m not in text]
    if missing:
        fail("G4", f"누락 운영모드: {missing}")
    else:
        ok("G4", f"7개 운영모드 모두 포함: {modes}")

    # 추가: IV 요구사항, 제로화 언급 확인
    checks = {
        "IV 요구사항": "IV",
        "제로화": "제로화",
        "GCM 호출 횟수 제한": "2³²",
        "패딩 금지(Zero-padding)": "Zero-padding",
    }
    for label, keyword in checks.items():
        if keyword in text:
            ok(f"G4-{label}", f"'{keyword}' 언급 확인")
        else:
            fail(f"G4-{label}", f"'{keyword}' 내용 없음")


# ─────────────────────────────────────────────────────────────────
# G5: SSP 관리 표 항목 확인
# ─────────────────────────────────────────────────────────────────
def test_ssp_management() -> None:
    section("G5: SSP 관리 요구사항 항목 확인")
    filename = "ssp-management.md"
    if not (GUIDELINES_DIR / filename).exists():
        fail("G5", f"{filename} 파일 없음")
        return
    text = _read(filename)
    items = ["생성", "합의/전송", "주입", "출력", "저장", "제로화"]
    missing = [i for i in items if i not in text]
    if missing:
        fail("G5", f"누락 항목: {missing}")
    else:
        ok("G5", f"SSP 관리 6개 항목 모두 포함: {items}")

    # CSP/PSP 구분 확인
    if "CSP" in text and "PSP" in text:
        ok("G5-CSP/PSP", "CSP/PSP 구분 언급 확인")
    else:
        fail("G5-CSP/PSP", "CSP 또는 PSP 내용 없음")


# ─────────────────────────────────────────────────────────────────
# G6: 검증대상 알고리즘 목록 확인
# ─────────────────────────────────────────────────────────────────
def test_verified_algorithms() -> None:
    section("G6: 검증대상 알고리즘 목록 확인")
    filename = "kcmvp-verified-algorithms.md"
    if not (GUIDELINES_DIR / filename).exists():
        fail("G6", f"{filename} 파일 없음")
        return
    text = _read(filename)
    algorithms = ["ARIA", "SEED", "LEA", "HIGHT", "SHA", "LSH", "HMAC", "CMAC", "DRBG", "KCDSA", "ECDSA"]
    missing = [a for a in algorithms if a not in text]
    if missing:
        fail("G6", f"누락 알고리즘: {missing}")
    else:
        ok("G6", f"주요 알고리즘 {len(algorithms)}개 모두 포함")

    # 비검증대상 알고리즘 섹션 확인
    if "AES" in text and "비검증대상" in text:
        ok("G6-비검증대상", "AES 등 비검증대상 알고리즘 명시 확인")
    else:
        fail("G6-비검증대상", "비검증대상 알고리즘 목록 없음")


# ─────────────────────────────────────────────────────────────────
# G7: TRC 규칙 3개 확인
# ─────────────────────────────────────────────────────────────────
def test_trc_traceability() -> None:
    section("G7: TRC 추적성 규칙 TRC-001/002/003 확인")
    filename = "TRC-traceability.md"
    if not (GUIDELINES_DIR / filename).exists():
        fail("G7", f"{filename} 파일 없음")
        return
    text = _read(filename)
    trc_rules = ["TRC-001", "TRC-002", "TRC-003"]
    missing = [r for r in trc_rules if r not in text]
    if missing:
        fail("G7", f"누락 TRC 규칙: {missing}")
    else:
        ok("G7", "TRC-001/002/003 모두 포함")

    # 각 규칙의 설명 확인
    checks = {
        "TRC-001 인터페이스 명세": "인터페이스 명세",
        "TRC-002 에러코드": "오류 코드",
        "TRC-003 커버리지": "커버리지",
        "자가시험 언급": "KAT",
    }
    for label, keyword in checks.items():
        if keyword in text:
            ok(f"G7-{label}", f"'{keyword}' 확인")
        else:
            fail(f"G7-{label}", f"'{keyword}' 내용 없음")


# ─────────────────────────────────────────────────────────────────
# G8: 제출물 작성 안내 주요 섹션 확인
# ─────────────────────────────────────────────────────────────────
def test_submission_guide() -> None:
    section("G8: 제출물 작성 안내 주요 섹션 확인")
    filename = "submission-document-guide.md"
    if not (GUIDELINES_DIR / filename).exists():
        fail("G8", f"{filename} 파일 없음")
        return
    text = _read(filename)
    sections = ["기본 및 상세설계서", "형상관리문서", "시험서", "자가시험", "KAT"]
    missing = [s for s in sections if s not in text]
    if missing:
        fail("G8", f"누락 섹션: {missing}")
    else:
        ok("G8", f"주요 섹션 {len(sections)}개 모두 포함")


# ─────────────────────────────────────────────────────────────────
# G9: Gemini 연결 상태 확인
# ─────────────────────────────────────────────────────────────────
def test_gemini_status() -> None:
    section("G9: Gemini API 연결 상태 확인")
    try:
        from app.config import settings
        from app.services.llm_service import _call_gemini_with_retry

        if not settings.GOOGLE_API_KEY:
            fail("G9", "GOOGLE_API_KEY 미설정")
            return

        ok("G9-key", f"GOOGLE_API_KEY 설정됨 (모델: {settings.GEMINI_L2_MODEL})")

        # 실제 호출 테스트 (실패해도 설정은 확인됨)
        try:
            result = _call_gemini_with_retry('"PASS"라고만 답하세요.')
            if result:
                ok("G9-call", f"Gemini 호출 성공: {result[:50].strip()}")
            else:
                warn("G9-call", "Gemini 응답이 비어 있음 (quota 소진 가능성)")
        except Exception as e:
            err_str = str(e)
            if "429" in err_str or "RESOURCE_EXHAUSTED" in err_str:
                warn("G9-call", f"Gemini 일일 quota 초과 (API 키/모델 자체는 유효) — {err_str[:80]}")
            elif "quota" in err_str.lower():
                warn("G9-call", f"Gemini quota 관련 오류: {err_str[:80]}")
            else:
                fail("G9-call", f"Gemini 호출 오류: {err_str[:100]}")

    except Exception as e:
        fail("G9", f"import 오류: {e}")


# ─────────────────────────────────────────────────────────────────
# G10: L2_PROVIDER 설정 확인
# ─────────────────────────────────────────────────────────────────
def test_l2_provider() -> None:
    section("G10: L2_PROVIDER 설정 확인")
    try:
        from app.config import settings
        provider = settings.L2_PROVIDER
        ok("G10", f"L2_PROVIDER = '{provider}'")

        if provider == "gemini":
            if settings.GOOGLE_API_KEY:
                ok("G10-gemini", "GOOGLE_API_KEY 설정됨")
            else:
                fail("G10-gemini", "L2_PROVIDER=gemini인데 GOOGLE_API_KEY 없음")
        elif provider == "local":
            ok("G10-local", f"로컬 LLM 사용 (base_url={settings.LOCAL_LLM_BASE_URL})")
        else:
            warn("G10-unknown", f"알 수 없는 provider: {provider}")
    except Exception as e:
        fail("G10", str(e))


# ─────────────────────────────────────────────────────────────────
# 결과 요약
# ─────────────────────────────────────────────────────────────────
def print_summary() -> int:
    total = len(_results)
    passed = sum(1 for r in _results if r["pass"])
    failed = total - passed
    print(f"\n{'='*60}")
    print(f"  가이드라인 + Gemini 테스트 결과: {passed}/{total} PASS")
    if failed:
        print("  실패 항목:")
        for r in _results:
            if not r["pass"]:
                print(f"    - {r['name']}: {r.get('detail', '')}")
    print(f"{'='*60}\n")
    return 1 if failed else 0


def main() -> int:
    print("KCMVP 가이드라인 + Gemini 통합 테스트 시작\n")
    for fn in [
        test_files_exist,
        test_frontmatter,
        test_lea_api,
        test_block_cipher_modes,
        test_ssp_management,
        test_verified_algorithms,
        test_trc_traceability,
        test_submission_guide,
        test_gemini_status,
        test_l2_provider,
    ]:
        try:
            fn()
        except Exception as e:
            fail(fn.__name__, str(e))

    return print_summary()


if __name__ == "__main__":
    sys.exit(main())
