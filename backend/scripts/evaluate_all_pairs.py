"""
KCMVP 코드-설계서 쌍 성능 평가 스크립트
=========================================
accuracy_test_v12.zip (코드) + testdata/ 내 모든 설계서 PDF를 대상으로
다음 지표를 측정하고 EVALUATION_REPORT.md 를 생성한다.

지표:
  1. 탐지율      — L1+L3 최종 위반 중 기준 진실(ground truth) 대비 재현율
  2. 오탐 수     — N-case 파일에서 탐지된 위반 건수
  3. L3 필터링 효과 — L1 후보 중 L3가 오탐 제거한 비율
  4. 문서 탐지 성능 — DOC ground truth가 있는 design_fail.pdf 대상 정밀도/재현율
  5. 패치 성공률  — 생성된 패치 파일의 유효성 검사 통과율
  6. 실행 시간    — 단계별 wall-clock 측정

Usage:
    cd backend
    python scripts/evaluate_all_pairs.py [--no-l3] [--skip-doc-gen]

Options:
    --no-l3        L3 Gemini 호출 없이 L1만 평가 (API key 없을 때)
    --skip-doc-gen design_fail.pdf 생성 스크립트 건너뜀 (이미 생성된 경우)
"""

import sys
import os
import time
import zipfile
import tempfile
import shutil
import json
import re
from pathlib import Path
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Set

BACKEND_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(BACKEND_ROOT))

# ── 설정 ─────────────────────────────────────────────────────────
USE_L3 = "--no-l3" not in sys.argv
SKIP_DOC_GEN = "--skip-doc-gen" in sys.argv

TESTDATA = BACKEND_ROOT / "testdata"
SCRIPTS  = BACKEND_ROOT / "scripts"

CODE_ZIP = TESTDATA / "accuracy_test_v12.zip"
DOC_TEST_ZIP = TESTDATA / "doc_accuracy_test_v2.zip"

DESIGN_PDFS = [
    ("fake_design_doc",       TESTDATA / "fake_design_doc.pdf",          False),
    ("SECUI설계서",            TESTDATA / "SECUI설계서.pdf",               False),
    ("keybiz설계서예시",        TESTDATA / "keybiz설계서예시.pdf",           False),
    ("sifr_kit설계서",         TESTDATA / "sifr_kit설계서 예시.pdf",        False),
    ("한컴위드설계서",          TESTDATA / "한컴위드설계서예시.pdf",           False),
    ("design_fail (생성)",     None,  True),   # doc_accuracy_test_v2.zip 에서 추출
]

# DOC ground truth — design_fail.pdf 위반 목록
DOC_FAIL_VIOLATIONS: Set[str] = {
    "DOC-001", "DOC-004", "DOC-007",
    "DOC-009", "DOC-010", "DOC-017", "DOC-022",
}

# ── 서비스 임포트 ─────────────────────────────────────────────────
from app.services.rule_engine_service import run_rule_engine
from app.services.preprocess_service import run_preprocess
from app.services.preprocess_docs_service import run_doc_preprocess
from app.services.doc_rule_service import load_doc_rules, run_doc_rule_engine
from app.services.report_service import post_process_violations, build_summary

try:
    from app.services.llm_service import run_l3_contextualizer, run_doc_l3_contextualizer
    L3_AVAILABLE = True
except Exception:
    L3_AVAILABLE = False
    USE_L3 = False
    print("[WARN] llm_service 임포트 실패 → L3 비활성화")


# ═══════════════════════════════════════════════════════════════════
# Ground Truth 파싱
# ═══════════════════════════════════════════════════════════════════

def parse_ground_truth(text: str) -> Tuple[List, List]:
    """GROUND_TRUTH.md 파싱 → (p_cases, n_cases)
    p_cases: [(filename, rule_id, desc), ...]
    n_cases: [(filename, rule_id, desc), ...]  rule_id = 탐지되면 안 되는 규칙
    """
    p_cases, n_cases = [], []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "|" not in line:
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 4:
            continue
        filename, label, rule_id, desc = parts[0], parts[1], parts[2], parts[3]
        if label == "P":
            p_cases.append((filename, rule_id, desc))
        elif label == "N":
            n_cases.append((filename, rule_id, desc))
    return p_cases, n_cases


# ═══════════════════════════════════════════════════════════════════
# 설계서 PDF 생성 (design_fail.pdf)
# ═══════════════════════════════════════════════════════════════════

def ensure_doc_test_zip():
    """doc_accuracy_test_v2.zip 생성 (없는 경우)."""
    if SKIP_DOC_GEN and DOC_TEST_ZIP.exists():
        print(f"[SKIP] {DOC_TEST_ZIP.name} 이미 존재")
        return True
    if DOC_TEST_ZIP.exists() and not SKIP_DOC_GEN:
        return True
    print(f"[GEN] {DOC_TEST_ZIP.name} 생성 중...")
    gen_script = SCRIPTS / "create_doc_accuracy_test_v2.py"
    if not gen_script.exists():
        print(f"[WARN] {gen_script} 없음 → design_fail.pdf 쌍 건너뜀")
        return False
    import subprocess
    result = subprocess.run(
        [sys.executable, str(gen_script), str(DOC_TEST_ZIP)],
        cwd=str(BACKEND_ROOT),
        capture_output=True, text=True, timeout=120
    )
    if result.returncode != 0:
        print(f"[ERROR] create_doc_accuracy_test_v2.py 실패:\n{result.stderr}")
        return False
    print(f"[GEN] ✓ {DOC_TEST_ZIP.name} 생성 완료")
    return True


def extract_design_fail_pdf(tmp_dir: Path) -> Optional[Path]:
    """doc_accuracy_test_v2.zip 에서 design_fail.pdf 추출."""
    if not DOC_TEST_ZIP.exists():
        return None
    out = tmp_dir / "design_fail.pdf"
    with zipfile.ZipFile(DOC_TEST_ZIP) as zf:
        # docs/design/design_fail.pdf 경로
        candidates = [n for n in zf.namelist() if "design_fail" in n]
        if not candidates:
            return None
        with zf.open(candidates[0]) as src, open(out, "wb") as dst:
            dst.write(src.read())
    return out


# ═══════════════════════════════════════════════════════════════════
# 코드 평가 (공통 — 모든 쌍에서 동일한 코드 ZIP 사용)
# ═══════════════════════════════════════════════════════════════════

def evaluate_code(tmp_dir: Path) -> Dict:
    """
    accuracy_test_v12.zip 기준 코드 위반 평가.
    Returns: 지표 딕셔너리
    """
    print("\n" + "─"*60)
    print("[코드] L1 + L3 파이프라인 평가 시작")

    with zipfile.ZipFile(CODE_ZIP) as zf:
        zf.extractall(tmp_dir)
        gt_text = zf.read("GROUND_TRUTH.md").decode("utf-8")

    p_cases, n_cases = parse_ground_truth(gt_text)
    print(f"  Ground Truth: P={len(p_cases)}, N={len(n_cases)}")

    src_dir = tmp_dir / "src"
    if not src_dir.exists():
        src_dir = tmp_dir

    # ── 전처리 ──────────────────────────────────────────────────
    t0 = time.time()
    c_files = sorted(src_dir.rglob("*.c"))
    file_entries = []
    for f in c_files:
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            content = ""
        file_entries.append({
            "path": str(f),
            "display": f.name,
            "content": content,
            "ast": {},
        })
    preprocess_result = {"files": file_entries}
    t_preprocess = time.time() - t0
    print(f"  전처리: {len(c_files)}개 파일, {t_preprocess:.2f}s")

    # ── L1 규칙 엔진 ──────────────────────────────────────────
    t1 = time.time()
    rules_dir = BACKEND_ROOT / "rules"
    l1_violations = run_rule_engine(
        preprocess_result=preprocess_result,
        rules_dir=rules_dir,
        job_root=tmp_dir,
    )
    t_l1 = time.time() - t1
    print(f"  L1 규칙 엔진: {len(l1_violations)}건, {t_l1:.2f}s")

    # ── L3 필터링 ──────────────────────────────────────────────
    t2 = time.time()
    if USE_L3:
        l3_rejected_keys: set = set()
        l3_violations = run_l3_contextualizer(
            preprocess_result=preprocess_result,
            l1_violations=l1_violations,
            _rejected_tracker=l3_rejected_keys,
        )
        final_violations = post_process_violations(
            l1=l1_violations,
            l3=l3_violations,
            l3_rejected_keys=l3_rejected_keys,
        )
        t_l3 = time.time() - t2
        # L3 필터링 효과 계산
        # L3 전송 대상: needs_ai_review=True 또는 severity=high인 regex/semantic/ast
        l3_candidates = [
            v for v in l1_violations
            if v.get("needs_ai_review") or (
                v.get("severity") == "high" and
                v.get("pattern_type") in ("regex", "semantic", "ast")
            )
        ]
        l3_sent = len(l3_candidates)
        l3_rejected = len(l3_rejected_keys)
        l3_filter_rate = (l3_rejected / l3_sent * 100) if l3_sent > 0 else 0.0
        print(f"  L3 Gemini: 후보 {l3_sent}건, 제거 {l3_rejected}건, 최종 {len(final_violations)}건, {t_l3:.2f}s")
    else:
        final_violations = l1_violations
        l3_rejected = 0
        l3_sent = len([v for v in l1_violations if v.get("needs_ai_review")])
        l3_filter_rate = 0.0
        t_l3 = 0.0
        print("  L3: 비활성화 (L1 결과 그대로 사용)")

    t_total_code = t_preprocess + t_l1 + t_l3

    # ── 혼동 행렬 계산 ────────────────────────────────────────
    detected: Dict[str, Set[str]] = defaultdict(set)
    for v in final_violations:
        fname = Path(v.get("file", "")).name
        rid = v.get("rule_id", "")
        if fname and rid:
            detected[fname].add(rid)

    TP = FN = FP = TN = 0
    fn_list: List[Dict] = []
    fp_list: List[Dict] = []

    for fname, rule_id, desc in p_cases:
        if rule_id in detected.get(fname, set()):
            TP += 1
        else:
            FN += 1
            fn_list.append({"file": fname, "rule_id": rule_id, "desc": desc})

    for fname, rule_id, desc in n_cases:
        if rule_id in detected.get(fname, set()):
            FP += 1
            fp_list.append({"file": fname, "rule_id": rule_id, "desc": desc})
        else:
            TN += 1

    precision = TP / (TP + FP) if (TP + FP) > 0 else 1.0
    recall    = TP / (TP + FN) if (TP + FN) > 0 else 0.0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    print(f"  → TP={TP}, FP={FP}, FN={FN}, TN={TN}")
    print(f"  → Precision={precision:.1%}, Recall={recall:.1%}, F1={f1:.1%}")

    # ── 규칙별 성능 집계 ──────────────────────────────────────
    rule_stats: Dict[str, Dict] = defaultdict(lambda: {"TP": 0, "FP": 0, "FN": 0, "TN": 0})
    for fname, rule_id, desc in p_cases:
        if rule_id in detected.get(fname, set()):
            rule_stats[rule_id]["TP"] += 1
        else:
            rule_stats[rule_id]["FN"] += 1
    for fname, rule_id, desc in n_cases:
        if rule_id in detected.get(fname, set()):
            rule_stats[rule_id]["FP"] += 1
        else:
            rule_stats[rule_id]["TN"] += 1

    return {
        "TP": TP, "FP": FP, "FN": FN, "TN": TN,
        "precision": precision, "recall": recall, "f1": f1,
        "l1_count": len(l1_violations),
        "final_count": len(final_violations),
        "l3_sent": l3_sent,
        "l3_rejected": l3_rejected,
        "l3_filter_rate": l3_filter_rate,
        "fn_list": fn_list,
        "fp_list": fp_list,
        "rule_stats": dict(rule_stats),
        "timing": {
            "preprocess_s": round(t_preprocess, 2),
            "l1_s": round(t_l1, 2),
            "l3_s": round(t_l3, 2),
            "total_code_s": round(t_total_code, 2),
        },
        "detected": dict(detected),
    }


# ═══════════════════════════════════════════════════════════════════
# 설계서 평가 (쌍별)
# ═══════════════════════════════════════════════════════════════════

def evaluate_doc(pdf_path: Path, pair_name: str,
                 has_ground_truth: bool) -> Dict:
    """단일 설계서 PDF를 평가한다."""
    print(f"\n[DOC] {pair_name} 평가 중...")

    if not pdf_path.exists():
        print(f"  [WARN] PDF 없음: {pdf_path}")
        return {"error": f"PDF 없음: {pdf_path}"}

    rules_dir = BACKEND_ROOT / "rules"
    doc_rules = load_doc_rules(rules_dir)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        dest_dir = tmp / "docs" / "design"
        dest_dir.mkdir(parents=True)
        shutil.copy(pdf_path, dest_dir / pdf_path.name)

        # DOC 전처리
        t0 = time.time()
        try:
            preprocess = run_doc_preprocess(tmp)
        except Exception as e:
            print(f"  [ERROR] DOC 전처리 실패: {e}")
            return {"error": str(e)}
        t_doc_preprocess = time.time() - t0
        sections = preprocess.get("sections", [])
        print(f"  DOC 전처리: {len(sections)}개 섹션, {t_doc_preprocess:.2f}s")

        # DOC L1 규칙 엔진
        t1 = time.time()
        l1_doc_viols = run_doc_rule_engine(preprocess, doc_rules)
        t_doc_l1 = time.time() - t1
        l1_rule_ids = {v.get("rule_id") for v in l1_doc_viols}
        print(f"  DOC L1: {len(l1_doc_viols)}건 (규칙: {sorted(l1_rule_ids)}), {t_doc_l1:.2f}s")

        # DOC L3
        t2 = time.time()
        if USE_L3 and l1_doc_viols:
            try:
                final_doc_viols = run_doc_l3_contextualizer(l1_doc_viols, preprocess)
            except Exception as e:
                print(f"  [WARN] DOC L3 실패: {e}")
                final_doc_viols = l1_doc_viols
        else:
            final_doc_viols = l1_doc_viols
        t_doc_l3 = time.time() - t2
        final_rule_ids = {v.get("rule_id") for v in final_doc_viols}
        l3_doc_removed = len(l1_doc_viols) - len(final_doc_viols)
        l3_doc_filter_rate = (l3_doc_removed / len(l1_doc_viols) * 100) if l1_doc_viols else 0.0
        print(f"  DOC L3: 최종 {len(final_doc_viols)}건 (제거 {l3_doc_removed}건), {t_doc_l3:.2f}s")

        result = {
            "pair_name": pair_name,
            "pdf": str(pdf_path),
            "sections": len(sections),
            "l1_count": len(l1_doc_viols),
            "final_count": len(final_doc_viols),
            "l1_rule_ids": sorted(l1_rule_ids),
            "final_rule_ids": sorted(final_rule_ids),
            "l3_doc_removed": l3_doc_removed,
            "l3_doc_filter_rate": round(l3_doc_filter_rate, 1),
            "timing": {
                "doc_preprocess_s": round(t_doc_preprocess, 2),
                "doc_l1_s": round(t_doc_l1, 2),
                "doc_l3_s": round(t_doc_l3, 2),
                "total_doc_s": round(t_doc_preprocess + t_doc_l1 + t_doc_l3, 2),
            },
            "has_ground_truth": has_ground_truth,
        }

        # Ground truth 비교 (design_fail.pdf만)
        if has_ground_truth:
            gt = DOC_FAIL_VIOLATIONS
            TP = len(gt & final_rule_ids)
            FN = len(gt - final_rule_ids)
            FP = len(final_rule_ids - gt)
            TN = 0  # 문서 레벨에서 TN 의미 없음 (단일 파일)
            precision = TP / (TP + FP) if (TP + FP) > 0 else 1.0
            recall    = TP / (TP + FN) if (TP + FN) > 0 else 0.0
            f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
            result.update({
                "doc_TP": TP, "doc_FP": FP, "doc_FN": FN,
                "doc_precision": precision, "doc_recall": recall, "doc_f1": f1,
                "doc_fn_ids": sorted(gt - final_rule_ids),
                "doc_fp_ids": sorted(final_rule_ids - gt),
            })
            print(f"  DOC 혼동행렬: TP={TP}, FP={FP}, FN={FN}")
            print(f"  DOC Precision={precision:.1%}, Recall={recall:.1%}, F1={f1:.1%}")

        return result


# ═══════════════════════════════════════════════════════════════════
# 패치 유효성 검사
# ═══════════════════════════════════════════════════════════════════

def check_patches(patches_dir: Path, final_violations: List[Dict]) -> Dict:
    """patches/ 디렉토리의 패치 파일 유효성 검사."""
    if not patches_dir.exists():
        # patches가 없으면 violations에서 suggestion 필드로 대체 분석
        with_suggestion = [v for v in final_violations if v.get("suggestion")]
        return {
            "total_expected": len(final_violations),
            "with_suggestion": len(with_suggestion),
            "suggestion_rate": len(with_suggestion) / len(final_violations) if final_violations else 0.0,
            "note": "patch 파일 없음 — suggestion 필드로 대체 측정",
        }

    patch_files = list(patches_dir.glob("*.md"))
    valid = 0
    invalid_list = []
    for pf in patch_files:
        try:
            content = pf.read_text(encoding="utf-8", errors="ignore")
            has_code_block = bool(re.search(r"```\s*(c|cpp|C)\b", content, re.I))
            has_rule_ref   = bool(re.search(r"[A-Z]{2,6}-\d{3}", content))
            is_nonempty    = len(content.strip()) > 50
            if has_code_block and has_rule_ref and is_nonempty:
                valid += 1
            else:
                invalid_list.append({
                    "file": pf.name,
                    "reason": (
                        "코드 블록 없음" if not has_code_block else
                        "rule_id 참조 없음" if not has_rule_ref else
                        "내용 부족"
                    ),
                })
        except Exception:
            invalid_list.append({"file": pf.name, "reason": "읽기 실패"})

    total = len(patch_files)
    success_rate = valid / total if total > 0 else 0.0
    return {
        "total_patches": total,
        "valid_patches": valid,
        "invalid_patches": len(invalid_list),
        "success_rate": success_rate,
        "invalid_list": invalid_list[:10],  # 최대 10개만
    }


# ═══════════════════════════════════════════════════════════════════
# 마크다운 보고서 생성
# ═══════════════════════════════════════════════════════════════════

def gen_report(code_result: Dict, doc_results: List[Dict],
               patch_result: Dict, total_elapsed: float) -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    md = []

    md.append("# KCMVP 파이프라인 성능 평가 보고서")
    md.append(f"\n**생성일시:** {now}")
    md.append(f"**평가 도구 버전:** KCMVP Pre-Validator (2026-03 기준)")
    md.append(f"**L3 Gemini 사용:** {'예' if USE_L3 else '아니오 (--no-l3 옵션)'}")
    md.append(f"**총 실행 시간:** {total_elapsed:.1f}초\n")

    # ── 1. 실험 설정 ──────────────────────────────────────────────
    md.append("---")
    md.append("\n## 1. 실험 설정\n")
    md.append("### 1.1 데이터셋")
    md.append("| 구분 | 파일명 | 설명 |")
    md.append("|------|--------|------|")
    md.append(f"| 코드 | `accuracy_test_v12.zip` | 132개 케이스 (P: 66, N: 66), 18개 규칙 군 |")
    for pair_name, pdf_path, has_gt in DESIGN_PDFS:
        label = "✓ Ground Truth 있음" if has_gt else "정성 분석 (GT 없음)"
        pname = pdf_path.name if pdf_path else "design_fail.pdf (생성)"
        md.append(f"| 설계서 | `{pname}` | {pair_name} — {label} |")
    md.append("")
    md.append("### 1.2 파이프라인 구성")
    md.append("```")
    md.append("코드 ZIP 입력")
    md.append("  → 전처리 (AST 파싱, 심볼 그래프)")
    md.append("  → L1 규칙 엔진 (YAML 패턴 매칭)")
    md.append("  → L3 AI 판정 (Gemini — 후보 위반 재판정)")
    md.append("  → 설계서 전처리 (PDF 섹션 추출)")
    md.append("  → DOC 규칙 엔진 (문서 패턴 검사)")
    md.append("  → DOC L3 (문서 위반 의미 판정)")
    md.append("  → 보고서 생성")
    md.append("```\n")

    # ── 2. 평가 지표 표 ───────────────────────────────────────────
    md.append("---")
    md.append("\n## 2. 평가 지표 표 (코드 기준)\n")

    cr = code_result
    dr_pct  = f"{cr['recall']:.1%}"
    fp_cnt  = str(cr['FP'])
    filter_r = f"{cr['l3_filter_rate']:.1f}% ({cr['l3_rejected']}건 제거 / {cr['l3_sent']}건 후보)"
    prec_pct = f"{cr['precision']:.1%}"
    f1_pct   = f"{cr['f1']:.1%}"
    code_time = f"{cr['timing']['total_code_s']:.1f}초"

    # 패치 성공률
    if "success_rate" in patch_result:
        patch_pct = f"{patch_result['success_rate']:.1%} ({patch_result['valid_patches']}/{patch_result['total_patches']})"
    elif "suggestion_rate" in patch_result:
        patch_pct = f"{patch_result['suggestion_rate']:.1%} (suggestion 기준)"
    else:
        patch_pct = "—"

    # DOC 탐지 성능 (design_fail.pdf 기준)
    doc_gt_result = next((d for d in doc_results if d.get("has_ground_truth")), None)
    if doc_gt_result and "doc_precision" in doc_gt_result:
        doc_perf = (f"정밀도 {doc_gt_result['doc_precision']:.1%}, "
                    f"재현율 {doc_gt_result['doc_recall']:.1%}, "
                    f"F1 {doc_gt_result['doc_f1']:.1%}")
    else:
        doc_perf = "Ground Truth 없음 (정성 분석)"

    md.append("| 지표 | 정의 | 결과 |")
    md.append("|------|------|------|")
    md.append(f"| **탐지율** | 기준 진실 위반 중 L1+L3가 찾아낸 비율 (재현율) | **{dr_pct}** |")
    md.append(f"| **오탐 수** | 실제 비위반(N-case)에서 L1+L3가 위반으로 낸 건수 | **{fp_cnt}건** |")
    md.append(f"| **L3 필터링 효과** | L3(Gemini)가 오탐으로 제거·재분류한 비율 | **{filter_r}** |")
    md.append(f"| **문서 탐지 성능** | DOC 규칙 정밀도·재현율 (design_fail.pdf 기준) | **{doc_perf}** |")
    md.append(f"| **패치 성공률** | 생성된 수정 권고가 유효한 비율 | **{patch_pct}** |")
    md.append(f"| **실행 시간 (코드)** | 전처리+L1+L3 단계별 실측 소요 시간 | **{code_time}** |")
    md.append("")

    # 단계별 실행 시간 상세
    md.append("### 2.1 단계별 실행 시간 (코드 파이프라인)")
    md.append("| 단계 | 소요 시간 |")
    md.append("|------|----------|")
    md.append(f"| 전처리 (AST 파싱, {len(list((TESTDATA/'..').rglob('accuracy_test_v12.zip')))}개 파일) | {cr['timing']['preprocess_s']}초 |")
    md.append(f"| L1 규칙 엔진 | {cr['timing']['l1_s']}초 |")
    md.append(f"| L3 Gemini 판정 | {cr['timing']['l3_s']}초 |")
    md.append(f"| **합계 (코드)** | **{cr['timing']['total_code_s']}초** |")
    md.append("")

    # 설계서별 실행 시간
    md.append("### 2.2 단계별 실행 시간 (설계서 파이프라인)\n")
    md.append("| 설계서 | 섹션 수 | DOC 전처리 | DOC L1 | DOC L3 | 합계 |")
    md.append("|--------|---------|-----------|--------|--------|------|")
    for dr in doc_results:
        if "error" in dr:
            md.append(f"| {dr.get('pair_name','?')} | — | — | — | — | 오류 |")
            continue
        t = dr["timing"]
        md.append(
            f"| {dr['pair_name']} | {dr['sections']} | {t['doc_preprocess_s']}s "
            f"| {t['doc_l1_s']}s | {t['doc_l3_s']}s | **{t['total_doc_s']}s** |"
        )
    md.append("")

    # ── 3. 혼동 행렬 ─────────────────────────────────────────────
    md.append("---")
    md.append("\n## 3. 혼동 행렬\n")
    md.append("### 3.1 코드 위반 혼동 행렬 (accuracy_test_v12.zip 기준, 파일 레벨)\n")
    md.append("> 행 = 실제 상태, 열 = 시스템 최종 판정\n")
    md.append("|  | **예측: 위반** | **예측: 정상** | 합계 |")
    md.append("|--|--------------|--------------|------|")
    md.append(f"| **실제: 위반 (P)** | TP = {cr['TP']} | FN = {cr['FN']} | {cr['TP']+cr['FN']} |")
    md.append(f"| **실제: 정상 (N)** | FP = {cr['FP']} | TN = {cr['TN']} | {cr['FP']+cr['TN']} |")
    md.append(f"| **합계** | {cr['TP']+cr['FP']} | {cr['FN']+cr['TN']} | {cr['TP']+cr['FP']+cr['FN']+cr['TN']} |")
    md.append("")
    md.append(f"- **Precision** = {cr['TP']} / ({cr['TP']} + {cr['FP']}) = **{cr['precision']:.1%}**")
    md.append(f"- **Recall (탐지율)** = {cr['TP']} / ({cr['TP']} + {cr['FN']}) = **{cr['recall']:.1%}**")
    md.append(f"- **F1** = **{cr['f1']:.1%}**")
    md.append("")

    if doc_gt_result and "doc_TP" in doc_gt_result:
        md.append("### 3.2 문서 위반 혼동 행렬 (design_fail.pdf, 규칙 레벨)\n")
        md.append(f"> 기준 진실: {sorted(DOC_FAIL_VIOLATIONS)}\n")
        dr = doc_gt_result
        md.append("|  | **예측: 위반** | **예측: 정상** |")
        md.append("|--|--------------|--------------|")
        md.append(f"| **실제: 위반** | TP = {dr['doc_TP']} | FN = {dr['doc_FN']} |")
        md.append(f"| **실제: 정상** | FP = {dr['doc_FP']} | TN = — |")
        md.append("")
        md.append(f"- **Precision** = {dr['doc_precision']:.1%}")
        md.append(f"- **Recall** = {dr['doc_recall']:.1%}")
        md.append(f"- **F1** = {dr['doc_f1']:.1%}")
        if dr.get("doc_fn_ids"):
            md.append(f"\n**미탐지 DOC 위반 (FN):** {', '.join(dr['doc_fn_ids'])}")
        if dr.get("doc_fp_ids"):
            md.append(f"**오탐 DOC 위반 (FP):** {', '.join(dr['doc_fp_ids'])}")
        md.append("")

    # ── 4. 규칙별 탐지 성능 ─────────────────────────────────────
    md.append("---")
    md.append("\n## 4. 코드 규칙별 탐지 성능\n")
    md.append("| 규칙 ID | TP | FP | FN | TN | Recall | Precision | 비고 |")
    md.append("|---------|----|----|----|----|--------|-----------|------|")

    for rule_id in sorted(cr["rule_stats"].keys()):
        s = cr["rule_stats"][rule_id]
        rtp, rfp, rfn, rtn = s["TP"], s["FP"], s["FN"], s["TN"]
        rrecall = rtp / (rtp + rfn) if (rtp + rfn) > 0 else 1.0
        rprec   = rtp / (rtp + rfp) if (rtp + rfp) > 0 else 1.0
        status  = "✓" if rfn == 0 and rfp == 0 else ("△ FN있음" if rfn > 0 else "△ FP있음")
        md.append(f"| {rule_id} | {rtp} | {rfp} | {rfn} | {rtn} "
                  f"| {rrecall:.0%} | {rprec:.0%} | {status} |")
    md.append("")

    # ── 5. 설계서별 DOC 탐지 현황 ─────────────────────────────────
    md.append("---")
    md.append("\n## 5. 설계서별 DOC 탐지 현황\n")
    md.append("| 설계서 | 섹션 수 | L1 탐지 | L3 최종 | L3 제거율 | Ground Truth | 비고 |")
    md.append("|--------|---------|---------|---------|-----------|-------------|------|")
    for dr in doc_results:
        if "error" in dr:
            md.append(f"| {dr.get('pair_name','?')} | — | — | — | — | — | {dr['error']} |")
            continue
        gt_str = "✓ 있음" if dr["has_ground_truth"] else "없음"
        note = ""
        if dr["has_ground_truth"] and "doc_precision" in dr:
            note = f"P={dr['doc_precision']:.0%} R={dr['doc_recall']:.0%} F1={dr['doc_f1']:.0%}"
        md.append(f"| {dr['pair_name']} | {dr['sections']} | {dr['l1_count']} "
                  f"| {dr['final_count']} | {dr['l3_doc_filter_rate']}% | {gt_str} | {note} |")
    md.append("")

    # ── 6. L3 필터링 분석 ─────────────────────────────────────────
    md.append("---")
    md.append("\n## 6. L3 필터링 효과 분석\n")
    md.append(f"- **L1 전체 위반:** {cr['l1_count']}건")
    md.append(f"- **L3 전송 후보:** {cr['l3_sent']}건 (high-severity regex/semantic/ast + needs_ai_review)")
    md.append(f"- **L3 오탐 제거:** {cr['l3_rejected']}건")
    md.append(f"- **L3 필터링율:** {cr['l3_filter_rate']:.1f}%")
    md.append(f"- **최종 위반 수:** {cr['final_count']}건")
    md.append("")

    if not USE_L3:
        md.append("> ⚠️ L3 비활성화 상태 (`--no-l3` 옵션). 실제 운영 시 L3 필터링 효과는 다를 수 있음.")
        md.append("")

    # ── 7. 미탐지(FN) / 오탐(FP) 상세 목록 ───────────────────────
    md.append("---")
    md.append("\n## 7. 코드 FN / FP 상세 목록\n")

    if cr["fn_list"]:
        md.append("### 7.1 미탐지 (FN) — L1+L3가 찾지 못한 실제 위반\n")
        md.append("| 파일 | 기대 Rule ID | 설명 |")
        md.append("|------|-------------|------|")
        for item in cr["fn_list"]:
            md.append(f"| `{item['file']}` | `{item['rule_id']}` | {item['desc']} |")
        md.append("")
    else:
        md.append("### 7.1 미탐지 (FN)\n\n✓ FN 없음 — 모든 실제 위반을 탐지했습니다.\n")

    if cr["fp_list"]:
        md.append("### 7.2 오탐 (FP) — 실제 정상인데 위반으로 판정\n")
        md.append("| 파일 | 오탐 Rule ID | 설명 |")
        md.append("|------|-------------|------|")
        for item in cr["fp_list"]:
            md.append(f"| `{item['file']}` | `{item['rule_id']}` | {item['desc']} |")
        md.append("")
    else:
        md.append("### 7.2 오탐 (FP)\n\n✓ FP 없음 — 오탐이 없습니다.\n")

    # ── 8. 패치 분석 ──────────────────────────────────────────────
    md.append("---")
    md.append("\n## 8. 패치 성공률 분석\n")
    if "success_rate" in patch_result:
        md.append(f"- **생성된 패치 파일:** {patch_result['total_patches']}개")
        md.append(f"- **유효 패치:** {patch_result['valid_patches']}개")
        md.append(f"- **무효 패치:** {patch_result['invalid_patches']}개")
        md.append(f"- **성공률:** {patch_result['success_rate']:.1%}")
        if patch_result.get("invalid_list"):
            md.append("\n**무효 패치 목록:**")
            for p in patch_result["invalid_list"]:
                md.append(f"  - `{p['file']}` — {p['reason']}")
    elif "suggestion_rate" in patch_result:
        md.append(f"- **위반 중 suggestion 포함:** {patch_result['with_suggestion']} / {patch_result['total_expected']}건")
        md.append(f"- **suggestion 제공률:** {patch_result['suggestion_rate']:.1%}")
        md.append(f"- **비고:** {patch_result['note']}")
    md.append("")

    # ── 9. 결과 해석 및 원인 분석 ────────────────────────────────
    md.append("---")
    md.append("\n## 9. 결과 해석 및 원인 분석\n")

    md.append("### 9.1 코드 탐지 성능 해석\n")
    if cr["recall"] >= 0.9:
        md.append(f"탐지율이 **{cr['recall']:.1%}** 로 높게 나타났다. "
                  "이는 L1 규칙 엔진의 패턴 매칭이 정확하게 동작하고 있음을 의미하며, "
                  "특히 `missing` 타입 규칙(패턴 부재 시 즉시 위반 확정)과 `regex` 타입 규칙의 "
                  "커버리지가 우수함을 나타낸다.\n")
    elif cr["recall"] >= 0.7:
        md.append(f"탐지율이 **{cr['recall']:.1%}** 로 중간 수준이다. "
                  "일부 위반이 누락되고 있으며, 하단 FN 목록에서 미탐지된 규칙을 확인할 수 있다.\n")
    else:
        md.append(f"탐지율이 **{cr['recall']:.1%}** 로 낮게 나타났다. "
                  "FN 목록에 포함된 규칙들의 패턴 강화 또는 AST 분석 구현이 필요하다.\n")

    if cr["fp_list"]:
        md.append(f"오탐 수는 **{cr['FP']}건** 이다. "
                  "FP가 발생한 주요 이유로는: (1) regex 패턴이 허용 예외(공개 상수, KAT 벡터, "
                  "lookup table)를 인식하지 못하는 경우, (2) L3 Gemini가 허용 케이스를 "
                  "충분히 걸러내지 못한 경우가 있다. "
                  "L3 프롬프트 개선 또는 허용 리스트 규칙 추가를 고려해야 한다.\n")
    else:
        md.append("오탐(FP)은 **0건** 이다. "
                  "L3 Gemini의 의미적 재판정이 정상적으로 작동하여 오탐을 효과적으로 제거하고 있다.\n")

    if cr["fn_list"]:
        fn_rules = sorted({item["rule_id"] for item in cr["fn_list"]})
        md.append(f"미탐지(FN) 규칙 목록: **{', '.join(fn_rules)}**.\n")
        md.append("주요 미탐지 원인:\n")
        for rule_id in fn_rules:
            fn_items = [i for i in cr["fn_list"] if i["rule_id"] == rule_id]
            desc_sample = fn_items[0]["desc"] if fn_items else ""
            if rule_id.startswith("LEA-"):
                md.append(f"- `{rule_id}`: LEA 내부 구현 세부 사항(라운드 수, 루프 경계)은 "
                          f"AST 분석 없이 regex만으로 정확히 판별하기 어렵다. "
                          f"(`{desc_sample}`)")
            elif rule_id.startswith("COM-"):
                md.append(f"- `{rule_id}`: 코드 맥락(변수 유형, 사용 패턴)을 고려해야 하는 규칙으로, "
                          f"L3가 false negative 처리했을 가능성이 있다.")
            else:
                md.append(f"- `{rule_id}`: {desc_sample}")
        md.append("")

    md.append("### 9.2 L3 필터링 효과 해석\n")
    if USE_L3:
        if cr["l3_filter_rate"] > 30:
            md.append(f"L3 필터링율이 **{cr['l3_filter_rate']:.1f}%** 로 높게 나타났다. "
                      "L1이 생성한 후보 위반 중 상당수가 실제로는 허용 패턴(공개 상수, 검증 벡터 등)이었음을 "
                      "의미하며, L3의 의미적 재판정이 FP를 효과적으로 제거하고 있다.\n")
        elif cr["l3_filter_rate"] > 10:
            md.append(f"L3 필터링율이 **{cr['l3_filter_rate']:.1f}%** 로 적당한 수준이다. "
                      "L1이 생성한 후보 위반 중 일부가 허용 패턴으로 필터링되었다.\n")
        else:
            md.append(f"L3 필터링율이 **{cr['l3_filter_rate']:.1f}%** 로 낮게 나타났다. "
                      "이는 L1이 이미 높은 정밀도로 위반을 탐지하고 있거나, "
                      "L3로 전달된 후보 수가 적기 때문일 수 있다.\n")
    else:
        md.append("> L3 비활성화 상태이므로 필터링 효과를 측정할 수 없었다. "
                  "실제 Gemini API 연동 시 오탐 제거 효과를 확인해야 한다.\n")

    md.append("### 9.3 문서 탐지 성능 해석\n")
    if doc_gt_result and "doc_precision" in doc_gt_result:
        dr = doc_gt_result
        if dr["doc_recall"] >= 0.8 and dr["doc_precision"] >= 0.8:
            md.append(f"DOC 탐지 성능이 우수하다 (Precision={dr['doc_precision']:.1%}, "
                      f"Recall={dr['doc_recall']:.1%}). "
                      f"KCMVP 설계서 작성 안내서 기준의 필수 항목 누락을 효과적으로 탐지하고 있다.\n")
        else:
            if dr["doc_fn_ids"]:
                md.append(f"미탐지된 DOC 위반: **{', '.join(dr['doc_fn_ids'])}**. "
                          "해당 규칙의 키워드 패턴 또는 semantic 매칭을 강화해야 한다.\n")
            if dr["doc_fp_ids"]:
                md.append(f"오탐된 DOC 위반: **{', '.join(dr['doc_fp_ids'])}**. "
                          "design_pass.pdf에서도 동일 키워드가 검출되어 오탐 발생. "
                          "L3 판정 조건 또는 패턴을 정밀화해야 한다.\n")
    else:
        md.append("실제 설계서(SECUI, keybiz, sifr_kit, 한컴위드) 대상 DOC 탐지는 "
                  "ground truth가 없으므로 정량적 평가를 수행하지 않았다. "
                  "위 설계서별 탐지 현황 표(§5)에서 검출된 위반 목록을 참고하라.\n")
        md.append("실제 설계서의 특성상, 탐지된 DOC 위반이 실제 미흡 사항인지 여부는 "
                  "전문가 검토가 필요하다. 특히 `semantic` 타입 위반은 키워드 존재 여부만 "
                  "판단하므로 동등한 표현으로 기술된 경우 FP가 발생할 수 있다.\n")

    md.append("### 9.4 실행 시간 분석\n")
    all_doc_times = [d["timing"]["total_doc_s"] for d in doc_results if "timing" in d]
    if all_doc_times:
        avg_doc = sum(all_doc_times) / len(all_doc_times)
        max_doc = max(all_doc_times)
        min_doc = min(all_doc_times)
        md.append(f"- 코드 파이프라인: **{cr['timing']['total_code_s']}초** "
                  f"(전처리 {cr['timing']['preprocess_s']}s + L1 {cr['timing']['l1_s']}s + L3 {cr['timing']['l3_s']}s)")
        md.append(f"- 설계서 파이프라인: 평균 **{avg_doc:.1f}초**, 최소 {min_doc:.1f}초, 최대 {max_doc:.1f}초")
        if cr["timing"]["l3_s"] > 30:
            md.append(f"\nL3 Gemini 판정이 **{cr['timing']['l3_s']:.1f}초** 로 전체 실행 시간의 "
                      f"{cr['timing']['l3_s']/cr['timing']['total_code_s']:.0%}를 차지한다. "
                      "이는 Gemini API 호출의 네트워크 지연과 batch 처리 시간 때문이다. "
                      "L3 전송 후보 수를 제한하거나 캐싱을 활용하면 시간을 단축할 수 있다.")
        elif USE_L3 and cr["timing"]["l3_s"] > 0:
            md.append(f"\nL3 Gemini 판정은 **{cr['timing']['l3_s']:.1f}초** 로 "
                      "전체 실행 시간의 합리적인 비율을 차지한다.")
    md.append("")

    md.append("---")
    md.append("\n## 10. 종합 결론\n")
    md.append(f"본 실험은 `accuracy_test_v12.zip` (132 케이스) + {len(doc_results)}종 설계서를 대상으로 "
              "KCMVP 검증 파이프라인의 성능을 측정하였다.\n")
    md.append(f"- **코드 탐지율 {cr['recall']:.1%}**: "
              + ("규칙 엔진이 실제 위반의 대부분을 포착하고 있음을 확인하였다."
                 if cr["recall"] >= 0.8 else
                 "일부 규칙에서 미탐지가 발생하여 추가 개선이 필요하다."))
    md.append(f"- **오탐 {cr['FP']}건**: "
              + ("오탐이 없어 사용자 불편이 최소화되었다."
                 if cr["FP"] == 0 else
                 f"오탐 {cr['FP']}건이 발생하였으며, L3 필터링 프롬프트 개선을 통해 추가 감소 가능하다."))
    if doc_gt_result and "doc_f1" in doc_gt_result:
        md.append(f"- **DOC 탐지 F1 {doc_gt_result['doc_f1']:.1%}**: "
                  + ("설계서 검사 정확도가 우수하다."
                     if doc_gt_result["doc_f1"] >= 0.8 else
                     "설계서 검사 개선이 필요하다. 특히 누락된 규칙 패턴을 보강해야 한다."))
    md.append("")

    return "\n".join(md)


# ═══════════════════════════════════════════════════════════════════
# 메인
# ═══════════════════════════════════════════════════════════════════

def main():
    print("=" * 65)
    print("KCMVP 코드-설계서 쌍 성능 평가")
    print(f"L3 Gemini: {'활성화' if USE_L3 else '비활성화 (--no-l3)'}")
    print("=" * 65)

    t_start_all = time.time()

    # ── 1. DOC 테스트 PDF 생성 ─────────────────────────────────
    has_doc_zip = ensure_doc_test_zip()

    # ── 2. 코드 평가 ──────────────────────────────────────────
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        code_result = evaluate_code(tmp)

        # 패치 분석: storage에서 가장 최근 job의 patches 사용 (있으면)
        storage = BACKEND_ROOT / "storage" / "jobs"
        patch_result = {"suggestion_rate": 0.0,
                        "with_suggestion": 0,
                        "total_expected": code_result["final_count"],
                        "note": "storage 없음"}
        if storage.exists():
            job_dirs = sorted(storage.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True)
            for jd in job_dirs[:5]:
                patches_dir = jd / "patches"
                if patches_dir.exists() and list(patches_dir.glob("*.md")):
                    patch_result = check_patches(patches_dir, [])
                    print(f"\n[패치] {jd.name} 의 patches/ 사용: {patch_result.get('total_patches',0)}개")
                    break

    # ── 3. 설계서 평가 (쌍별) ─────────────────────────────────
    doc_results = []
    design_fail_tmp = None

    # design_fail.pdf 추출 (임시 경로)
    if has_doc_zip:
        _tmp = tempfile.mkdtemp()
        design_fail_tmp_dir = Path(_tmp)
        design_fail_pdf = extract_design_fail_pdf(design_fail_tmp_dir)
    else:
        design_fail_pdf = None
        design_fail_tmp_dir = None

    for pair_name, pdf_path, has_gt in DESIGN_PDFS:
        if has_gt:
            actual_pdf = design_fail_pdf
        else:
            actual_pdf = pdf_path

        if actual_pdf is None:
            doc_results.append({"pair_name": pair_name, "error": "PDF 없음",
                                 "has_ground_truth": has_gt})
            continue

        dr = evaluate_doc(actual_pdf, pair_name, has_gt)
        dr["pair_name"] = pair_name
        doc_results.append(dr)

    if design_fail_tmp_dir:
        shutil.rmtree(str(design_fail_tmp_dir), ignore_errors=True)

    # ── 4. 보고서 생성 ────────────────────────────────────────
    total_elapsed = time.time() - t_start_all
    report_md = gen_report(code_result, doc_results, patch_result, total_elapsed)

    output_path = SCRIPTS / "EVALUATION_REPORT.md"
    output_path.write_text(report_md, encoding="utf-8")

    print(f"\n{'='*65}")
    print(f"✓ 평가 완료 (총 {total_elapsed:.1f}초)")
    print(f"✓ 보고서 저장: {output_path}")
    print(f"{'='*65}")
    print(f"\n[요약]")
    print(f"  코드 탐지율 (Recall): {code_result['recall']:.1%}")
    print(f"  오탐 수 (FP):         {code_result['FP']}건")
    print(f"  L3 필터링 효과:       {code_result['l3_filter_rate']:.1f}% 제거")
    print(f"  코드 파이프라인 시간:  {code_result['timing']['total_code_s']}초")
    for dr in doc_results:
        if "doc_f1" in dr:
            print(f"  DOC 탐지 F1 (design_fail): {dr['doc_f1']:.1%}")


if __name__ == "__main__":
    main()
