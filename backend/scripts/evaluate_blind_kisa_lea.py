"""
Phase 1: KISA 공식 LEA 레퍼런스 블라인드 테스트
================================================
KISA 배포 LEA C 소스코드(v1.3)를 "정상 코드"로 간주하고,
시스템이 얼마나 많은 False Positive를 생성하는지 측정.

정상 코드이므로 탐지되는 모든 위반 = FP (False Positive).
이를 통해:
  1) FP rate (건/1000LOC) 산출
  2) FP 발생 규칙 패턴 분석
  3) 기존 4세트 대비 독립 데이터셋 검증

Usage:
    cd backend
    python scripts/evaluate_blind_kisa_lea.py [--no-l3]
"""

import sys, os, time, json, zipfile, tempfile, shutil
from pathlib import Path
from collections import defaultdict, Counter
from datetime import datetime

BACKEND_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(BACKEND_ROOT))

USE_L3 = "--no-l3" not in sys.argv

# KISA LEA 소스 경로
KISA_LEA_SRC = BACKEND_ROOT.parent / "블록암호_LEA_소스코드(v1.3)" / "LEA_C_Standalone_src"

from app.services.rule_engine_service import run_rule_engine

try:
    from app.services.llm_service import run_l3_contextualizer
    from app.services.report_service import post_process_violations
    L3_AVAILABLE = True
except Exception:
    L3_AVAILABLE = False

if not L3_AVAILABLE:
    USE_L3 = False


def count_loc(src_dir: Path) -> int:
    """C/H 파일 총 LOC 카운트."""
    total = 0
    for ext in ("*.c", "*.h"):
        for f in src_dir.rglob(ext):
            try:
                total += len(f.read_text(encoding="utf-8", errors="ignore").splitlines())
            except:
                pass
    return total


def run_blind_test():
    print("=" * 65)
    print("Phase 1: KISA LEA 공식 레퍼런스 블라인드 테스트")
    print(f"소스 경로: {KISA_LEA_SRC}")
    print(f"L3 (Gemini): {'활성화' if USE_L3 else '비활성화'}")
    print("=" * 65)

    if not KISA_LEA_SRC.exists():
        print(f"[ERROR] KISA LEA 소스 경로 없음: {KISA_LEA_SRC}")
        return

    # 1. 소스 파일 수집
    c_files = sorted(KISA_LEA_SRC.rglob("*.c"))
    h_files = sorted(KISA_LEA_SRC.rglob("*.h"))
    total_loc = count_loc(KISA_LEA_SRC)

    print(f"\n[정보] C 파일: {len(c_files)}개, H 파일: {len(h_files)}개, 총 LOC: {total_loc}")

    # 2. preprocess_result 구성
    file_entries = []
    for f in c_files:
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
        except:
            content = ""
        file_entries.append({
            "path": str(f),
            "display": f.name,
            "content": content,
            "ast": {},
        })
    preprocess_result = {"files": file_entries}

    # 3. L1 규칙 엔진 실행
    print(f"\n[L1] 규칙 엔진 실행 중...")
    t0 = time.time()
    rules_dir = BACKEND_ROOT / "rules"

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        # 소스 복사
        src_dest = tmp / "src"
        shutil.copytree(KISA_LEA_SRC, src_dest)

        l1_violations = run_rule_engine(
            preprocess_result=preprocess_result,
            rules_dir=rules_dir,
            job_root=tmp,
        )
    t_l1 = time.time() - t0
    print(f"  L1 완료: {len(l1_violations)}건 탐지, {t_l1:.1f}s")

    # 4. L3 필터링 (선택)
    l3_rejected_keys = set()
    if USE_L3 and L3_AVAILABLE and l1_violations:
        print(f"\n[L3] Gemini 재판정 중...")
        t1 = time.time()
        try:
            l3_violations = run_l3_contextualizer(
                preprocess_result=preprocess_result,
                l1_violations=l1_violations,
                _rejected_tracker=l3_rejected_keys,
            )
            final_violations = post_process_violations(
                l1=l1_violations, l3=l3_violations,
                l3_rejected_keys=l3_rejected_keys,
            )
        except Exception as e:
            print(f"  [WARN] L3 실패: {e}")
            final_violations = l1_violations
        t_l3 = time.time() - t1
        print(f"  L3 완료: {len(final_violations)}건 최종, "
              f"{len(l3_rejected_keys)}건 제거, {t_l3:.1f}s")
    else:
        final_violations = l1_violations
        t_l3 = 0.0

    # 5. FP 분석 (정상 코드이므로 모든 탐지 = FP)
    print(f"\n{'═' * 65}")
    print("  블라인드 테스트 결과 (KISA LEA v1.3 — 정상 코드)")
    print(f"{'═' * 65}")

    fp_by_rule = Counter()
    fp_by_file = Counter()
    fp_by_severity = Counter()
    fp_by_pattern = Counter()
    fp_details = []

    for v in final_violations:
        rid = v.get("rule_id", "?")
        fname = Path(v.get("file", "")).name
        sev = v.get("severity", "?")
        ptype = v.get("pattern_type", "?")
        fp_by_rule[rid] += 1
        fp_by_file[fname] += 1
        fp_by_severity[sev] += 1
        fp_by_pattern[ptype] += 1
        fp_details.append({
            "rule_id": rid, "file": fname,
            "line": v.get("line", 0),
            "severity": sev, "pattern_type": ptype,
            "message": v.get("message", "")[:100],
        })

    total_fp = len(final_violations)
    fp_per_kloc = total_fp / (total_loc / 1000) if total_loc > 0 else 0.0

    print(f"  총 FP: {total_fp}건")
    print(f"  총 LOC: {total_loc}")
    print(f"  FP rate: {fp_per_kloc:.1f}건/KLOC")
    print(f"{'─' * 65}")

    print(f"\n  [규칙별 FP 분포]")
    for rid, cnt in fp_by_rule.most_common(15):
        print(f"    {rid}: {cnt}건")

    print(f"\n  [파일별 FP 분포]")
    for fname, cnt in fp_by_file.most_common(10):
        print(f"    {fname}: {cnt}건")

    print(f"\n  [심각도별 FP 분포]")
    for sev, cnt in fp_by_severity.most_common():
        print(f"    {sev}: {cnt}건")

    print(f"\n  [패턴타입별 FP 분포]")
    for pt, cnt in fp_by_pattern.most_common():
        print(f"    {pt}: {cnt}건")

    # L1 vs 최종 비교
    l1_total_fp = len(l1_violations)
    l3_removed = len(l3_rejected_keys)
    l3_fp_remove_rate = l3_removed / l1_total_fp if l1_total_fp > 0 else 0.0

    print(f"\n  [L3 FP 제거 효과]")
    print(f"    L1 FP: {l1_total_fp}건")
    print(f"    L3 제거: {l3_removed}건 ({l3_fp_remove_rate:.1%})")
    print(f"    최종 FP: {total_fp}건")
    print(f"{'═' * 65}")

    # 6. 통계적 분석
    print(f"\n{'═' * 65}")
    print("  Phase 2: 통계적 유의성 분석 (기존 4세트 기반)")
    print(f"{'═' * 65}")

    # 기존 evaluation_results.json 로드
    eval_json = BACKEND_ROOT / "scripts" / "evaluation_results.json"
    existing = {}
    if eval_json.exists():
        existing = json.loads(eval_json.read_text(encoding="utf-8"))

    # 세트별 Recall 수집
    set_recalls = []
    set_details = []
    if "code_results" in existing:
        for r in existing["code_results"]:
            gt = r.get("gt_count", 0)
            tp = r.get("TP", 0)
            fn = r.get("FN", 0)
            rc = tp / gt if gt > 0 else 0.0
            set_recalls.append(rc)
            set_details.append({
                "set": r["set_name"], "gt": gt, "tp": tp, "fn": fn, "recall": rc
            })

    if set_recalls:
        import math
        n_total = sum(d["gt"] for d in set_details)
        tp_total = sum(d["tp"] for d in set_details)
        p_hat = tp_total / n_total if n_total > 0 else 0.0

        # Wilson score interval (95% CI)
        z = 1.96
        denom = 1 + z**2 / n_total
        center = (p_hat + z**2 / (2 * n_total)) / denom
        spread = z * math.sqrt(p_hat * (1 - p_hat) / n_total + z**2 / (4 * n_total**2)) / denom
        ci_low = max(0, center - spread)
        ci_high = min(1, center + spread)

        # 세트별 표준편차
        mean_recall = sum(set_recalls) / len(set_recalls)
        variance = sum((r - mean_recall)**2 for r in set_recalls) / len(set_recalls)
        std_recall = math.sqrt(variance)

        print(f"  기존 4세트 합산 Recall: {p_hat:.1%} ({tp_total}/{n_total})")
        print(f"  95% CI (Wilson): [{ci_low:.1%}, {ci_high:.1%}]")
        print(f"  CI 폭: {(ci_high - ci_low)*100:.1f}pp")
        print(f"  세트별 평균 Recall: {mean_recall:.1%}")
        print(f"  세트별 표준편차: {std_recall*100:.1f}pp")
        print(f"  세트별 범위: {min(set_recalls):.1%} ~ {max(set_recalls):.1%}")
        print()
        for d in set_details:
            print(f"    {d['set']}: {d['recall']:.1%} ({d['tp']}/{d['gt']})")

        stats_result = {
            "n": n_total, "tp": tp_total,
            "recall": p_hat,
            "ci_95_low": ci_low, "ci_95_high": ci_high,
            "ci_width_pp": round((ci_high - ci_low) * 100, 1),
            "set_mean": mean_recall, "set_std": std_recall,
            "set_min": min(set_recalls), "set_max": max(set_recalls),
            "set_details": set_details,
        }
    else:
        stats_result = {"error": "기존 evaluation_results.json 없음"}

    print(f"{'═' * 65}")

    # 7. 결과 JSON 저장
    result = {
        "timestamp": datetime.now().isoformat(),
        "phase": "Phase 1 + Phase 2",
        "description": "KISA LEA v1.3 공식 레퍼런스 블라인드 FP 테스트 + 통계 분석",
        "source": "블록암호_LEA_소스코드(v1.3)/LEA_C_Standalone_src",
        "use_l3": USE_L3,
        "loc": total_loc,
        "c_files": len(c_files),
        "h_files": len(h_files),
        "l1_fp_count": l1_total_fp,
        "l3_removed": l3_removed,
        "final_fp_count": total_fp,
        "fp_per_kloc": round(fp_per_kloc, 2),
        "fp_by_rule": dict(fp_by_rule.most_common()),
        "fp_by_file": dict(fp_by_file.most_common()),
        "fp_by_severity": dict(fp_by_severity),
        "fp_by_pattern": dict(fp_by_pattern),
        "fp_details": fp_details,
        "timing": {
            "l1_s": round(t_l1, 1),
            "l3_s": round(t_l3, 1),
            "total_s": round(t_l1 + t_l3, 1),
        },
        "statistics": stats_result,
    }

    out_path = BACKEND_ROOT / "scripts" / "blind_test_kisa_lea_results.json"
    out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2, default=str),
                        encoding="utf-8")
    print(f"\n결과 저장: {out_path}")

    return result


if __name__ == "__main__":
    run_blind_test()
