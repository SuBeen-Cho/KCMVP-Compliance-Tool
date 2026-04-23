"""
TRC (Traceability) 통합 테스트.

검증 항목:
  [T1] build_code_index: 헤더 파일에서 공개 함수 선언 추출
  [T2] build_code_index: 소스 파일 AST 함수 정의 추출
  [T3] build_code_index: #define 에러 코드 추출
  [T4] TRC-001: 헤더 함수가 설계서에 없으면 위반 탐지
  [T5] TRC-001: 설계서에 언급된 헤더 함수는 위반 없음
  [T6] TRC-002: 설계서 에러 코드가 코드에 없으면 위반 탐지
  [T7] TRC-002: 설계서 에러 코드 없으면 위반 없음 (빈 반환)
  [T8] TRC-003: 시험서 미언급 함수 비율 초과 시 위반 탐지
  [T9] TRC-003: 시험서가 없으면 위반 없음 (빈 반환)
  [T10] run_traceability_checks: rules 없으면 빈 리스트 반환
  [T11] 실제 job 파이프라인: preprocess_result + doc_preprocess → TRC 검사 (오류 없음)

실행:
  cd backend
  venv/bin/python3 scripts/test_trc.py
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


def section(title: str) -> None:
    print(f"\n{'='*60}\n  {title}\n{'='*60}")


# ─────────────────────────────────────────────────────────────────
# T1~T3: build_code_index
# ─────────────────────────────────────────────────────────────────
def test_build_code_index() -> None:
    section("T1~T3: build_code_index")

    from app.services.traceability_service import build_code_index

    preprocess = {
        "files": [
            {
                "path": "include/lea.h",
                "lines": [
                    "/* LEA 공개 API */",
                    "void lea_key_setup(LeaKeyCtx *key, const unsigned char *mk, unsigned int mk_len);",
                    "void lea_encrypt(unsigned char *ct, const unsigned char *pt, const LeaKeyCtx *key);",
                    "void lea_decrypt(unsigned char *pt, const unsigned char *ct, const LeaKeyCtx *key);",
                    "int lea_get_version(void);",
                ],
                "ast": {"functions": [], "file_calls": []},
            },
            {
                "path": "src/lea_core.c",
                "lines": [
                    "#define LEA_ERROR_INVALID_KEY  -1",
                    "#define LEA_ERROR_BAD_PARAM    -2",
                    "void lea_key_setup(LeaKeyCtx *key, ...) { }",
                ],
                "ast": {
                    "functions": [
                        {"name": "lea_key_setup", "line": 3, "end_line": 3, "calls": []},
                    ],
                    "file_calls": [],
                },
            },
        ]
    }

    idx = build_code_index(preprocess)

    # T1: 헤더 함수 추출
    hf = idx.get("header_funcs", {})
    found = [k for k in hf if "lea" in k]
    if found:
        ok("T1", f"헤더 함수 추출: {sorted(found)}")
    else:
        fail("T1", f"헤더 함수 미추출 — 전체 keys: {list(hf.keys())[:10]}")

    # T2: 소스 함수 추출
    sf = idx.get("source_funcs", {})
    if "lea_key_setup" in sf:
        ok("T2", f"소스 함수 추출: lea_key_setup @ {sf['lea_key_setup']['file']}")
    else:
        fail("T2", f"lea_key_setup 미추출 — 전체 keys: {list(sf.keys())}")

    # T3: 에러 코드 추출
    ec = idx.get("error_codes", {})
    if "LEA_ERROR_INVALID_KEY" in ec and "LEA_ERROR_BAD_PARAM" in ec:
        ok("T3", f"에러 코드 추출: {list(ec.keys())}")
    else:
        fail("T3", f"에러 코드 미추출 — 전체: {list(ec.keys())}")


# ─────────────────────────────────────────────────────────────────
# T4~T5: TRC-001
# ─────────────────────────────────────────────────────────────────
def test_trc001() -> None:
    section("T4~T5: TRC-001 인터페이스 명세 일치성")

    from app.services.traceability_service import _check_trc001

    code_index = {
        "header_funcs": {
            "lea_encrypt": {"file": "include/lea.h", "line": 2, "signature": "void lea_encrypt(...);", "name": "lea_encrypt"},
            "lea_decrypt": {"file": "include/lea.h", "line": 3, "signature": "void lea_decrypt(...);", "name": "lea_decrypt"},
            "lea_key_setup": {"file": "include/lea.h", "line": 4, "signature": "void lea_key_setup(...);", "name": "lea_key_setup"},
        }
    }
    rule = {"id": "TRC-001", "type": "interface_match", "severity": "high"}

    # T4: 설계서에 없는 함수 → 위반
    design_no_mention = [{"text": "본 설계서는 LEA 암호 모듈의 구조를 설명합니다.", "tables": []}]
    viols = _check_trc001(design_no_mention, code_index, rule)
    if len(viols) >= 2:
        ok("T4", f"설계서 미언급 헤더 함수 위반 탐지: {len(viols)}건")
    else:
        fail("T4", f"위반 건수 부족: {len(viols)}건 (기대 ≥2)")

    # T5: 설계서에 함수명 언급 → 해당 함수 위반 없음
    design_with_mention = [{
        "text": "lea_encrypt() 함수는 128비트 블록을 암호화합니다. lea_key_setup()으로 키를 초기화합니다.",
        "tables": [],
    }]
    viols2 = _check_trc001(design_with_mention, code_index, rule)
    # lea_encrypt, lea_key_setup은 언급됨 → lea_decrypt만 위반 (또는 0건)
    mentioned_in_viols = {v["func_name"] for v in viols2}
    if "lea_encrypt" not in mentioned_in_viols and "lea_key_setup" not in mentioned_in_viols:
        ok("T5", f"설계서 언급 함수는 위반 없음 — 미언급: {mentioned_in_viols}")
    else:
        fail("T5", f"설계서에 있는 함수가 위반에 포함됨: {mentioned_in_viols}")


# ─────────────────────────────────────────────────────────────────
# T6~T7: TRC-002
# ─────────────────────────────────────────────────────────────────
def test_trc002() -> None:
    section("T6~T7: TRC-002 에러 코드 일치성")

    from app.services.traceability_service import _check_trc002

    code_index = {
        "error_codes": {
            "LEA_ERROR_BAD_PARAM": {"file": "src/lea.c", "value": "-2"},
        }
    }
    rule = {"id": "TRC-002", "type": "error_code_match", "severity": "medium"}

    # T6: 설계서에 있지만 코드에 없는 에러 코드 → 위반
    design_with_err = [{"text": "에러 코드: LEA_ERROR_INVALID_KEY(-1), LEA_ERROR_BAD_PARAM(-2) 정의", "tables": []}]
    viols = _check_trc002(design_with_err, code_index, rule)
    missing_codes = {v["error_code"] for v in viols}
    if "LEA_ERROR_INVALID_KEY" in missing_codes:
        ok("T6", f"코드 미정의 에러 코드 탐지: {missing_codes}")
    else:
        fail("T6", f"탐지 실패 — 위반: {missing_codes}")

    # T7: 설계서에 에러 코드 없으면 위반 없음
    design_no_err = [{"text": "정상 흐름에 대해 설명합니다.", "tables": []}]
    viols2 = _check_trc002(design_no_err, code_index, rule)
    if len(viols2) == 0:
        ok("T7", "에러 코드 없는 설계서 → 위반 없음")
    else:
        fail("T7", f"예상치 못한 위반: {viols2}")


# ─────────────────────────────────────────────────────────────────
# T8~T9: TRC-003
# ─────────────────────────────────────────────────────────────────
def test_trc003() -> None:
    section("T8~T9: TRC-003 시험 커버리지")

    from app.services.traceability_service import _check_trc003

    code_index = {
        "header_funcs": {
            "lea_encrypt": {"file": "include/lea.h", "line": 2, "name": "lea_encrypt"},
            "lea_decrypt": {"file": "include/lea.h", "line": 3, "name": "lea_decrypt"},
            "lea_key_setup": {"file": "include/lea.h", "line": 4, "name": "lea_key_setup"},
            "lea_get_version": {"file": "include/lea.h", "line": 5, "name": "lea_get_version"},
        }
    }
    rule = {"id": "TRC-003", "type": "test_coverage", "severity": "medium"}

    # T8: 시험서에서 절반 미만 언급 → 커버리지 위반
    test_no_coverage = [{"text": "시험 항목 1: lea_encrypt 정상 동작 확인", "tables": []}]
    viols = _check_trc003(code_index, test_no_coverage, rule)
    if viols:
        ok("T8", f"시험 커버리지 부족 탐지: {viols[0]['message'][:60]}")
    else:
        fail("T8", "커버리지 위반 미탐지")

    # T9: 시험서 없으면 위반 없음
    viols2 = _check_trc003(code_index, [], rule)
    if len(viols2) == 0:
        ok("T9", "시험서 없음 → 위반 없음")
    else:
        fail("T9", f"예상치 못한 위반: {len(viols2)}건")


# ─────────────────────────────────────────────────────────────────
# T10: rules 없으면 빈 리스트
# ─────────────────────────────────────────────────────────────────
def test_no_rules() -> None:
    section("T10: rules 없으면 빈 리스트")

    from app.services.traceability_service import run_traceability_checks

    result = run_traceability_checks(
        design_doc={"sections": [{"text": "설계 내용", "tables": []}]},
        code_index={"header_funcs": {}, "source_funcs": {}, "error_codes": {}},
        test_doc={"sections": []},
        rules=[],
    )
    if result == []:
        ok("T10", "rules=[] → 빈 리스트 반환")
    else:
        fail("T10", f"예상치 못한 반환: {result}")


# ─────────────────────────────────────────────────────────────────
# T11: 실제 job 데이터로 파이프라인 테스트
# ─────────────────────────────────────────────────────────────────
def test_real_pipeline() -> None:
    section("T11: 실제 job 파이프라인 통합 테스트")

    import json
    from app.services.traceability_service import run_traceability_checks, build_code_index
    from app.config import settings

    jobs_root = BACKEND / settings.STORAGE_ROOT / settings.JOB_DATA_DIR
    if not jobs_root.exists():
        ok("T11", "job 없음 — 스킵")
        return

    # 첫 번째 job 사용
    job_dir = next(
        (d for d in sorted(jobs_root.iterdir()) if d.is_dir()), None
    )
    if not job_dir:
        ok("T11", "job 없음 — 스킵")
        return

    pp_path = job_dir / "preprocess_result.json"
    doc_path = job_dir / "doc_preprocess_result.json"

    if not pp_path.exists():
        ok("T11", f"preprocess_result.json 없음 — 스킵 ({job_dir.name[:8]})")
        return

    try:
        pre = json.loads(pp_path.read_text(encoding="utf-8"))
        doc = json.loads(doc_path.read_text(encoding="utf-8")) if doc_path.exists() else {"sections": []}

        code_index = build_code_index(pre)

        design_secs = [s for s in doc.get("sections", []) if s.get("doc_type") == "design"]
        test_secs = [s for s in doc.get("sections", []) if s.get("doc_type") == "test"]

        # TRC 룰 로드
        import yaml
        trc_path = BACKEND / "rules" / "traceability" / "traceability.yaml"
        trc_rules = yaml.safe_load(trc_path.read_text(encoding="utf-8")).get("rules", [])

        viols = run_traceability_checks(
            design_doc={"sections": design_secs},
            code_index=code_index,
            test_doc={"sections": test_secs},
            rules=trc_rules,
        )

        hf_count = len(code_index.get("header_funcs", {}))
        sf_count = len(code_index.get("source_funcs", {}))
        ec_count = len(code_index.get("error_codes", {}))
        ok("T11", (
            f"job={job_dir.name[:8]}... | "
            f"header_funcs={hf_count}, source_funcs={sf_count}, error_codes={ec_count} | "
            f"TRC 위반={len(viols)}건"
        ))

    except Exception as e:
        fail("T11", str(e))


# ─────────────────────────────────────────────────────────────────
# 결과 요약
# ─────────────────────────────────────────────────────────────────
def print_summary() -> int:
    total = len(_results)
    passed = sum(1 for r in _results if r["pass"])
    failed = total - passed
    print(f"\n{'='*60}")
    print(f"  TRC 테스트 결과: {passed}/{total} PASS")
    if failed:
        for r in _results:
            if not r["pass"]:
                print(f"    - {r['name']}: {r.get('detail', '')}")
    print(f"{'='*60}\n")
    return 1 if failed else 0


def main() -> int:
    print("TRC (Traceability) 통합 테스트 시작\n")

    for fn in [
        test_build_code_index,
        test_trc001,
        test_trc002,
        test_trc003,
        test_no_rules,
        test_real_pipeline,
    ]:
        try:
            fn()
        except Exception as e:
            fail(fn.__name__, str(e))

    return print_summary()


if __name__ == "__main__":
    sys.exit(main())
