"""
L1+L3 전체 파이프라인 정확도 평가 스크립트 (실제 Gemini API 호출)

Usage:
    python scripts/run_l3_accuracy.py [zip_path]
    python scripts/run_l3_accuracy.py testdata/accuracy_test_v7.zip

평가 기준:
  - P-case: 최종 violations에 (filename, rule_id) 존재 → TP / 없으면 FN
  - N-case: 최종 violations에 (filename, rule_id) 없음 → TN / 있으면 FP

L3 세부 분석:
  - L3에 전달된 항목 중 P-case 얼마나 확정됐는지 (L3 recall)
  - L3에 전달된 항목 중 N-case 얼마나 걸러졌는지 (L3 FP 제거율)
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
from app.services.llm_service import run_l3_contextualizer
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

        # ── L3 실행 (실제 Gemini API 호출) ─────────────────────────
        print("\n[L3] Gemini 판정 실행 중... (API 호출 발생)")
        l3_rejected_keys: set = set()
        l3_violations = run_l3_contextualizer(
            preprocess_result=preprocess_result,
            l1_violations=l1_violations,
            _rejected_tracker=l3_rejected_keys,
        )
        print(f"[L3] 확정 위반: {len(l3_violations)}건")
        print(f"[L3] 오탐 제거: {len(l3_rejected_keys)}건")

        # L3 confidence 분포
        if l3_violations:
            scores = [v.get("confidence_score", 0) for v in l3_violations]
            confirmed = sum(1 for v in l3_violations if v.get("confidence") == "확정")
            print(f"      확정(≥70): {confirmed}건 / 후보(<70): {len(l3_violations)-confirmed}건")
            print(f"      평균 confidence: {sum(scores)/len(scores):.1f}")

        # ── 최종 병합 ──────────────────────────────────────────────
        final_violations = post_process_violations(
            l1=l1_violations,
            l3=l3_violations,
            l3_rejected_keys=l3_rejected_keys,
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
        print(f"  [전체 파이프라인 L1+L3]")
        print(f"  TP={TP}  FP={FP}  FN={FN}  TN={TN}")
        print(f"  Precision={precision:.1%}  Recall={recall:.1%}  F1={f1:.1%}")
        print(f"{'─'*50}")

        if fn_list:
            print("\n[FN — 미탐지 (L3가 제거하거나 L1도 못 잡은 경우)]")
            for l in fn_list: print(l)
        if fp_list:
            print("\n[FP — 오탐 (L3가 걸러내지 못한 경우)]")
            for l in fp_list: print(l)
        if not fn_list and not fp_list:
            print("\n✓ 완벽한 정확도 (FN=0, FP=0)")

        # ── L3 전용 분석 ────────────────────────────────────────────
        print(f"\n{'─'*50}")
        print(f"  [L3 판정 세부 분석]")

        # L3에 실제로 전달된 항목 파악 (l3_violations + l3_rejected_keys)
        l3_sent_pnames: set = set()  # (fname, rule_id)
        for v in l3_violations:
            fname = Path(v.get("file","")).name
            rid   = v.get("rule_id","")
            if fname and rid:
                l3_sent_pnames.add((fname, rid))
        for (file_, rid_, line_) in l3_rejected_keys:
            fname = Path(file_).name
            if fname and rid_:
                l3_sent_pnames.add((fname, rid_))

        l3_tp = l3_fp = l3_fn = l3_tn = 0
        l3_fn_list, l3_fp_list = [], []

        for fname, rule_id, desc in p_cases:
            if (fname, rule_id) not in l3_sent_pnames:
                continue  # L3에 안 보낸 항목은 분석 제외
            if rule_id in detected.get(fname, set()):
                l3_tp += 1
            else:
                l3_fn += 1
                l3_fn_list.append(f"  L3-FN | {fname} | {rule_id} | {desc}")

        for fname, rule_id, desc in n_cases:
            if (fname, rule_id) not in l3_sent_pnames:
                continue
            if rule_id in detected.get(fname, set()):
                l3_fp += 1
                l3_fp_list.append(f"  L3-FP | {fname} | {rule_id} | {desc}")
            else:
                l3_tn += 1

        total_l3_judged = l3_tp + l3_fp + l3_fn + l3_tn
        if total_l3_judged > 0:
            l3_prec   = l3_tp / (l3_tp + l3_fp) if (l3_tp + l3_fp) > 0 else 1.0
            l3_recall = l3_tp / (l3_tp + l3_fn) if (l3_tp + l3_fn) > 0 else 0.0
            l3_f1     = 2 * l3_prec * l3_recall / (l3_prec + l3_recall) if (l3_prec + l3_recall) > 0 else 0.0
            print(f"  L3가 판정한 케이스: {total_l3_judged}건")
            print(f"  TP={l3_tp}  FP={l3_fp}  FN={l3_fn}  TN={l3_tn}")
            print(f"  Precision={l3_prec:.1%}  Recall={l3_recall:.1%}  F1={l3_f1:.1%}")
        else:
            print(f"  L3가 판정한 케이스 없음 (ground truth 케이스가 L3 범위 밖)")
        print(f"{'─'*50}")

        if l3_fn_list:
            print("\n[L3-FN — L3가 실제 위반을 오탐으로 제거]")
            for l in l3_fn_list: print(l)
        if l3_fp_list:
            print("\n[L3-FP — L3가 정상 코드를 위반으로 확정]")
            for l in l3_fp_list: print(l)

        return {
            "TP": TP, "FP": FP, "FN": FN, "TN": TN, "F1": f1,
            "L3_TP": l3_tp, "L3_FP": l3_fp, "L3_FN": l3_fn, "L3_TN": l3_tn,
        }


if __name__ == "__main__":
    zip_path = sys.argv[1] if len(sys.argv) > 1 else str(
        BACKEND_ROOT / "testdata" / "accuracy_test_v7.zip"
    )
    if not os.path.exists(zip_path):
        zip_path = str(BACKEND_ROOT / zip_path)
    run_eval(zip_path)
