"""
L1+L2 전체 파이프라인 정확도 평가 스크립트 (실제 Gemini API 호출)

Usage:
    python scripts/run_l2_accuracy.py [zip_path]
    python scripts/run_l2_accuracy.py testdata/accuracy_test_v7.zip

평가 기준:
  - P-case: 최종 violations에 (filename, rule_id) 존재 → TP / 없으면 FN
  - N-case: 최종 violations에 (filename, rule_id) 없음 → TN / 있으면 FP

L2 세부 분석:
  - L2에 전달된 항목 중 P-case 얼마나 확정됐는지 (L2 recall)
  - L2에 전달된 항목 중 N-case 얼마나 걸러졌는지 (L2 FP 제거율)
"""

import sys
import zipfile
import tempfile
import os
from pathlib import Path
from collections import defaultdict

BACKEND_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(BACKEND_ROOT))

from app.services.rule_engine_service import run_rule_engine
from app.services.llm_service import run_l2_contextualizer
from app.services.report_service import post_process_violations


def parse_ground_truth(text: str):
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


def run_eval(zip_path: str):
    print(f"\n{'='*65}")
    print(f"평가 대상: {zip_path}")
    print(f"{'='*65}")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)

        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(tmp)
            gt_text = zf.read("GROUND_TRUTH.md").decode("utf-8")

        p_cases, n_cases = parse_ground_truth(gt_text)
        print(f"Ground Truth: P={len(p_cases)}, N={len(n_cases)}")

        # ── 파일 목록 + 콘텐츠 로드 ──────────────────────────────────
        src_dir = tmp / "src" if (tmp / "src").exists() else tmp
        c_files = sorted(src_dir.rglob("*.c"))

        preprocess_result = {
            "files": [
                {
                    "path": str(f),
                    "display": f.name,
                    "content": f.read_text(encoding="utf-8", errors="ignore"),
                    "ast": {},
                }
                for f in c_files
            ]
        }

        rules_dir = BACKEND_ROOT / "rules"

        # ── L1 실행 ────────────────────────────────────────────────
        print("\n[L1] 룰 엔진 실행 중...")
        l1_violations = run_rule_engine(
            preprocess_result=preprocess_result,
            rules_dir=rules_dir,
            job_root=tmp,
        )
        print(f"[L1] 위반 후보: {len(l1_violations)}건")

        # pattern_type 분포
        from collections import Counter
        pt_dist = Counter(v.get("pattern_type", "?") for v in l1_violations)
        print(f"      분포: {dict(pt_dist)}")

        # ── L2 실행 (실제 Gemini API 호출) ─────────────────────────
        print("\n[L2] Gemini 판정 실행 중... (API 호출 발생)")
        l2_rejected_keys: set = set()
        l2_violations = run_l2_contextualizer(
            preprocess_result=preprocess_result,
            l1_violations=l1_violations,
            _rejected_tracker=l2_rejected_keys,
        )
        print(f"[L2] 확정 위반: {len(l2_violations)}건")
        print(f"[L2] 오탐 제거: {len(l2_rejected_keys)}건")

        # L2 confidence 분포
        if l2_violations:
            scores = [v.get("confidence_score", 0) for v in l2_violations]
            confirmed = sum(1 for v in l2_violations if v.get("confidence") == "확정")
            print(f"      확정(≥70): {confirmed}건 / 후보(<70): {len(l2_violations)-confirmed}건")
            print(f"      평균 confidence: {sum(scores)/len(scores):.1f}")

        # ── 최종 병합 ──────────────────────────────────────────────
        final_violations = post_process_violations(
            l1=l1_violations,
            l2=l2_violations,
            l2_rejected_keys=l2_rejected_keys,
        )
        print(f"\n[최종] 위반 {len(final_violations)}건")

        # ── (file_basename, rule_id) 집합으로 변환 ─────────────────
        detected: dict = defaultdict(set)
        for v in final_violations:
            fname = Path(v.get("file", "")).name
            rid   = v.get("rule_id", "")
            if fname and rid:
                detected[fname].add(rid)

        # ── 혼동 행렬 (전체 파이프라인) ────────────────────────────
        TP = FN = FP = TN = 0
        fn_list, fp_list = [], []

        for fname, rule_id, desc in p_cases:
            if rule_id in detected.get(fname, set()):
                TP += 1
            else:
                FN += 1
                fn_list.append(f"  FN | {fname} | {rule_id} | {desc}")

        for fname, rule_id, desc in n_cases:
            if rule_id in detected.get(fname, set()):
                FP += 1
                fp_list.append(f"  FP | {fname} | {rule_id} | {desc}")
            else:
                TN += 1

        precision = TP / (TP + FP) if (TP + FP) > 0 else 1.0
        recall    = TP / (TP + FN) if (TP + FN) > 0 else 0.0
        f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

        print(f"\n{'─'*50}")
        print(f"  [전체 파이프라인 L1+L2]")
        print(f"  TP={TP}  FP={FP}  FN={FN}  TN={TN}")
        print(f"  Precision={precision:.1%}  Recall={recall:.1%}  F1={f1:.1%}")
        print(f"{'─'*50}")

        if fn_list:
            print("\n[FN — 미탐지 (L2가 제거하거나 L1도 못 잡은 경우)]")
            for l in fn_list: print(l)
        if fp_list:
            print("\n[FP — 오탐 (L2가 걸러내지 못한 경우)]")
            for l in fp_list: print(l)
        if not fn_list and not fp_list:
            print("\n✓ 완벽한 정확도 (FN=0, FP=0)")

        # ── L2 전용 분석 ────────────────────────────────────────────
        print(f"\n{'─'*50}")
        print(f"  [L2 판정 세부 분석]")

        # L2에 실제로 전달된 항목 파악 (l2_violations + l2_rejected_keys)
        l2_sent_pnames: set = set()  # (fname, rule_id)
        for v in l2_violations:
            fname = Path(v.get("file","")).name
            rid   = v.get("rule_id","")
            if fname and rid:
                l2_sent_pnames.add((fname, rid))
        for (file_, rid_, line_) in l2_rejected_keys:
            fname = Path(file_).name
            if fname and rid_:
                l2_sent_pnames.add((fname, rid_))

        l2_tp = l2_fp = l2_fn = l2_tn = 0
        l2_fn_list, l2_fp_list = [], []

        for fname, rule_id, desc in p_cases:
            if (fname, rule_id) not in l2_sent_pnames:
                continue  # L2에 안 보낸 항목은 분석 제외
            if rule_id in detected.get(fname, set()):
                l2_tp += 1
            else:
                l2_fn += 1
                l2_fn_list.append(f"  L2-FN | {fname} | {rule_id} | {desc}")

        for fname, rule_id, desc in n_cases:
            if (fname, rule_id) not in l2_sent_pnames:
                continue
            if rule_id in detected.get(fname, set()):
                l2_fp += 1
                l2_fp_list.append(f"  L2-FP | {fname} | {rule_id} | {desc}")
            else:
                l2_tn += 1

        total_l2_judged = l2_tp + l2_fp + l2_fn + l2_tn
        if total_l2_judged > 0:
            l2_prec   = l2_tp / (l2_tp + l2_fp) if (l2_tp + l2_fp) > 0 else 1.0
            l2_recall = l2_tp / (l2_tp + l2_fn) if (l2_tp + l2_fn) > 0 else 0.0
            l2_f1     = 2 * l2_prec * l2_recall / (l2_prec + l2_recall) if (l2_prec + l2_recall) > 0 else 0.0
            print(f"  L2가 판정한 케이스: {total_l2_judged}건")
            print(f"  TP={l2_tp}  FP={l2_fp}  FN={l2_fn}  TN={l2_tn}")
            print(f"  Precision={l2_prec:.1%}  Recall={l2_recall:.1%}  F1={l2_f1:.1%}")
        else:
            print(f"  L2가 판정한 케이스 없음 (ground truth 케이스가 L2 범위 밖)")
        print(f"{'─'*50}")

        if l2_fn_list:
            print("\n[L2-FN — L2가 실제 위반을 오탐으로 제거]")
            for l in l2_fn_list: print(l)
        if l2_fp_list:
            print("\n[L2-FP — L2가 정상 코드를 위반으로 확정]")
            for l in l2_fp_list: print(l)

        return {
            "TP": TP, "FP": FP, "FN": FN, "TN": TN, "F1": f1,
            "L2_TP": l2_tp, "L2_FP": l2_fp, "L2_FN": l2_fn, "L2_TN": l2_tn,
        }


if __name__ == "__main__":
    zip_path = sys.argv[1] if len(sys.argv) > 1 else str(
        BACKEND_ROOT / "testdata" / "accuracy_test_v7.zip"
    )
    if not os.path.exists(zip_path):
        zip_path = str(BACKEND_ROOT / zip_path)
    run_eval(zip_path)
