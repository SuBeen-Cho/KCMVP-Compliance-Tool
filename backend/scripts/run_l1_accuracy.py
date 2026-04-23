"""
L1 룰 엔진 정확도 평가 스크립트 (API 서버 없이 직접 실행)

Usage:
    python scripts/run_l1_accuracy.py [zip_path]
    python scripts/run_l1_accuracy.py testdata/accuracy_test_v4.zip
    python scripts/run_l1_accuracy.py testdata/accuracy_test_v5.zip
"""
import sys
import zipfile
import tempfile
import os
from pathlib import Path
from collections import defaultdict

# backend root를 sys.path에 추가
BACKEND_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(BACKEND_ROOT))

from app.services.rule_engine_service import run_rule_engine


def parse_ground_truth(text: str):
    """GROUND_TRUTH.md 파싱 → P-cases, N-cases 리스트 반환."""
    p_cases = []  # (filename, rule_id, desc)
    n_cases = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "|" not in line:
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
    print(f"\n{'='*60}")
    print(f"평가 대상: {zip_path}")
    print(f"{'='*60}")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)

        # ZIP 압축 해제
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(tmp)
            gt_text = zf.read("GROUND_TRUTH.md").decode("utf-8")

        p_cases, n_cases = parse_ground_truth(gt_text)
        print(f"Ground Truth: P={len(p_cases)}, N={len(n_cases)}")

        # src/ 내 C 파일 수집
        src_dir = tmp / "src"
        if not src_dir.exists():
            src_dir = tmp
        c_files = list(src_dir.rglob("*.c"))

        preprocess_result = {
            "files": [
                {"path": str(f), "ast": {}}
                for f in sorted(c_files)
            ]
        }

        rules_dir = BACKEND_ROOT / "rules"
        violations = run_rule_engine(
            preprocess_result=preprocess_result,
            rules_dir=rules_dir,
            job_root=tmp,
        )

        # (file_basename, rule_id) 집합으로 변환
        detected: dict = defaultdict(set)
        for v in violations:
            fname = Path(v.get("file", "")).name
            rid = v.get("rule_id", "")
            if fname and rid:
                detected[fname].add(rid)

        print(f"\n탐지된 위반: {len(violations)}건 "
              f"(파일별: {dict(sorted((k, len(s)) for k, s in detected.items()))})")

        # ── 혼동 행렬 ──
        TP = FN = FP = TN = 0
        fn_list = []
        fp_list = []

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

        print(f"\n{'─'*40}")
        print(f"  TP={TP}  FP={FP}  FN={FN}  TN={TN}")
        print(f"  Precision={precision:.1%}  Recall={recall:.1%}  F1={f1:.1%}")
        print(f"{'─'*40}")

        if fn_list:
            print("\n[FN — 미탐지]")
            for l in fn_list:
                print(l)
        if fp_list:
            print("\n[FP — 오탐]")
            for l in fp_list:
                print(l)
        if not fn_list and not fp_list:
            print("\n✓ 완벽한 정확도 (FN=0, FP=0)")

        return {"TP": TP, "FP": FP, "FN": FN, "TN": TN, "F1": f1}


if __name__ == "__main__":
    zip_path = sys.argv[1] if len(sys.argv) > 1 else str(
        BACKEND_ROOT / "testdata" / "accuracy_test_v4.zip"
    )
    if not os.path.exists(zip_path):
        # relative path 처리
        zip_path = str(BACKEND_ROOT / zip_path)
    run_eval(zip_path)
