"""
방안 5: GT 기반 FP 분류기 학습
==============================
4개 테스트 세트에서 L1 위반을 수집, TP/FP 레이블링 후
특징 벡터 추출 → 분류기 학습 → leave-one-set-out 교차검증.

Usage:
    cd backend
    python scripts/train_fp_classifier.py
"""

import sys, os, re, json, zipfile
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Set, Tuple

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import classification_report, confusion_matrix

BACKEND_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(BACKEND_ROOT))

from app.services.rule_engine_service import run_rule_engine

KCMVP_ROOT = BACKEND_ROOT.parent.parent
SET_BASE = KCMVP_ROOT / "스크립트" / "코드 - 설계서 세트"


# ═══ GT 추출 ═══
def extract_code_gt_from_zip(zip_path: Path) -> Dict[str, List[Dict]]:
    pattern = re.compile(r'\[위반[:\s]*([A-Z]+-[A-Z]*-?\d+)\]')
    gt = defaultdict(list)
    seen = defaultdict(set)
    with zipfile.ZipFile(zip_path) as zf:
        for name in zf.namelist():
            if not name.endswith('.c'):
                continue
            content = zf.read(name).decode('utf-8', errors='ignore')
            fname = Path(name).name
            for i, line in enumerate(content.split('\n'), 1):
                for rid in pattern.findall(line):
                    if rid not in seen[fname]:
                        seen[fname].add(rid)
                        gt[fname].append({"rule_id": rid, "line": i})
    return dict(gt)


# ═══ 특징 추출 ═══
_MODE_KW = {"cbc", "ctr", "gcm", "ccm", "cfb", "ofb", "ecb", "cmac"}
_ROLE_KW = {"key_schedule", "keyschedule", "round", "block", "encrypt", "decrypt", "mct", "kat", "test"}
_KEY_SCHED_RE = re.compile(r"(key_schedule|roundkey|round_key|delta\s*\[|RK\s*\[)", re.IGNORECASE)
_MCT_RE = re.compile(r"(mct|MCT|monte.?carlo)", re.IGNORECASE)
_ROUND_RE = re.compile(r"(LEA_ROUND|lea_round|ROUND_FUNC|for\s*\(.*\b(round|rnd)\b)", re.IGNORECASE)


def extract_features(
    violation: Dict,
    file_content: str,
    file_name: str,
) -> Dict[str, float]:
    """위반 1건에 대해 특징 벡터 추출."""
    rule_id = violation.get("rule_id", "")
    pattern_type = violation.get("pattern_type", "unknown")
    fname_lower = file_name.lower()

    # 규칙 카테고리
    prefix = rule_id.split("-")[0] if "-" in rule_id else rule_id
    cats = {"COM": 0, "LEA": 0, "CBC": 0, "CTR": 0, "GCM": 0, "CCM": 0,
            "ECB": 0, "CFB": 0, "OFB": 0, "CMAC": 0, "ARIA": 0}
    if prefix in cats:
        cats[prefix] = 1

    # 패턴 타입
    pt = {"pt_ast": 0, "pt_regex": 0, "pt_semantic": 0, "pt_missing": 0}
    pt_key = f"pt_{pattern_type}" if f"pt_{pattern_type}" in pt else "pt_regex"
    pt[pt_key] = 1

    # 파일명에 모드 키워드 포함?
    file_has_mode = 0
    file_mode = ""
    for kw in _MODE_KW:
        if kw in fname_lower:
            file_has_mode = 1
            file_mode = kw
            break

    # 규칙 모드와 파일 모드 일치?
    rule_mode = ""
    for kw in _MODE_KW:
        if kw.upper() in rule_id.upper():
            rule_mode = kw
            break
    mode_match = 1 if (rule_mode and file_mode and rule_mode == file_mode) else 0
    mode_mismatch = 1 if (rule_mode and file_mode and rule_mode != file_mode) else 0

    # 파일 역할 키워드
    file_has_role = 0
    for kw in _ROLE_KW:
        if kw in fname_lower:
            file_has_role = 1
            break

    # 파일 내용 기반 특징
    has_key_sched = 1 if _KEY_SCHED_RE.search(file_content) else 0
    has_mct = 1 if _MCT_RE.search(file_content) else 0
    has_round = 1 if _ROUND_RE.search(file_content) else 0

    # 규칙-파일 관련성 (키 스케줄 규칙인데 키 스케줄 없음 등)
    rule_needs_keysched = 1 if rule_id in ("LEA-010", "LEA-024", "LEA-025") else 0
    rule_needs_mct = 1 if rule_id in ("LEA-047", "LEA-057") else 0
    rule_needs_round = 1 if rule_id in ("LEA-040",) else 0

    relevance_missing = 0
    if rule_needs_keysched and not has_key_sched:
        relevance_missing = 1
    if rule_needs_mct and not has_mct:
        relevance_missing = 1

    # 파일 크기 (줄 수)
    line_count = file_content.count('\n')

    # 위반 라인 위치 (0~1 정규화)
    vline = violation.get("line") or 0
    line_pos = vline / max(line_count, 1)

    features = {
        **cats, **pt,
        "file_has_mode": file_has_mode,
        "mode_match": mode_match,
        "mode_mismatch": mode_mismatch,
        "file_has_role": file_has_role,
        "has_key_sched": has_key_sched,
        "has_mct": has_mct,
        "has_round": has_round,
        "rule_needs_keysched": rule_needs_keysched,
        "rule_needs_mct": rule_needs_mct,
        "rule_needs_round": rule_needs_round,
        "relevance_missing": relevance_missing,
        "line_count": min(line_count / 500, 1.0),
        "line_pos": line_pos,
    }
    return features


# ═══ 데이터 수집 ═══
def collect_data() -> List[Dict]:
    """4개 테스트 세트에서 L1 위반 수집 + TP/FP 레이블링."""
    sets = []
    for i in range(1, 5):
        set_dir = SET_BASE / f"세트 {i}"
        zip_files = list(set_dir.glob("*.zip"))
        code_zip = None
        for zf in zip_files:
            if "설계서" not in zf.name and "doc" not in zf.name.lower():
                code_zip = zf
                break
        if not code_zip:
            print(f"세트 {i}: ZIP 없음, 스킵")
            continue

        code_gt = extract_code_gt_from_zip(code_zip)
        gt_rules = set()
        for fname, vlist in code_gt.items():
            for v in vlist:
                gt_rules.add((fname, v["rule_id"]))

        print(f"세트 {i}: GT={len(gt_rules)} pairs, ZIP={code_zip.name}")

        # L1 실행
        import tempfile, shutil
        tmpdir = tempfile.mkdtemp()
        with zipfile.ZipFile(code_zip) as zf:
            zf.extractall(tmpdir)

        from app.services.preprocess_service import run_preprocess
        prep = run_preprocess(Path(tmpdir))

        # 파일 내용 캐시
        file_contents = {}
        for item in prep.get("files", []):
            lines = item.get("lines")
            if lines:
                fname = Path(item.get("path", "")).name
                file_contents[fname] = "\n".join(lines)

        rules_dir = BACKEND_ROOT / "rules"
        l1 = run_rule_engine(prep, rules_dir=rules_dir, job_root=Path(tmpdir), symbol_graph=None)
        print(f"  L1: {len(l1)}건")

        # 각 위반에 레이블 부여
        samples = []
        for v in l1:
            fname = Path(v.get("file", "")).name
            rid = v.get("rule_id", "")
            is_tp = (fname, rid) in gt_rules
            content = file_contents.get(fname, "")

            feats = extract_features(v, content, fname)
            samples.append({
                "set_id": i,
                "file": fname,
                "rule_id": rid,
                "label": 1 if is_tp else 0,
                "features": feats,
            })

        sets.append(samples)
        shutil.rmtree(tmpdir, ignore_errors=True)

    return sets


# ═══ 학습 + 교차검증 ═══
def train_and_evaluate(all_sets: List[List[Dict]]):
    """Leave-one-set-out 교차검증."""
    feat_names = sorted(all_sets[0][0]["features"].keys())
    print(f"\n특징 수: {len(feat_names)}")
    print(f"특징: {feat_names}")

    # 전체 통계
    total_tp = sum(s["label"] for sets in all_sets for s in sets)
    total_fp = sum(1 - s["label"] for sets in all_sets for s in sets)
    print(f"전체: TP={total_tp}, FP={total_fp}, 합계={total_tp + total_fp}")

    results = []
    for test_idx in range(len(all_sets)):
        # Train on all but test_idx
        X_train, y_train = [], []
        for i, sets in enumerate(all_sets):
            if i == test_idx:
                continue
            for s in sets:
                X_train.append([s["features"][f] for f in feat_names])
                y_train.append(s["label"])

        X_test, y_test = [], []
        test_items = []
        for s in all_sets[test_idx]:
            X_test.append([s["features"][f] for f in feat_names])
            y_test.append(s["label"])
            test_items.append(s)

        X_train = np.array(X_train)
        y_train = np.array(y_train)
        X_test = np.array(X_test)
        y_test = np.array(y_test)

        # GradientBoosting (작은 데이터에 적합)
        clf = GradientBoostingClassifier(
            n_estimators=50, max_depth=3, min_samples_leaf=5,
            random_state=42,
        )
        clf.fit(X_train, y_train)
        y_pred = clf.predict(X_test)
        y_prob = clf.predict_proba(X_test)[:, 1]

        # 보수적 임계값: TP 예측 확률이 0.3 미만이면 FP로 분류
        # (Recall 최우선 — TP를 FP로 잘못 분류하면 안 됨)
        y_pred_conservative = (y_prob >= 0.3).astype(int)

        tp = sum(1 for yt, yp in zip(y_test, y_pred_conservative) if yt == 1 and yp == 1)
        fn = sum(1 for yt, yp in zip(y_test, y_pred_conservative) if yt == 1 and yp == 0)
        fp_removed = sum(1 for yt, yp in zip(y_test, y_pred_conservative) if yt == 0 and yp == 0)
        fp_kept = sum(1 for yt, yp in zip(y_test, y_pred_conservative) if yt == 0 and yp == 1)

        print(f"\n=== 세트 {test_idx + 1} (테스트) ===")
        print(f"  TP 유지={tp}, FN(TP 오분류)={fn}, FP 제거={fp_removed}, FP 유지={fp_kept}")
        print(f"  Recall={tp / (tp + fn) if (tp + fn) else 1:.1%}")
        print(f"  FP 제거율={fp_removed / (fp_removed + fp_kept) if (fp_removed + fp_kept) else 0:.1%}")

        # FN 항목 상세
        if fn > 0:
            print(f"  ⚠️ FN 항목:")
            for item, yt, yp, prob in zip(test_items, y_test, y_pred_conservative, y_prob):
                if yt == 1 and yp == 0:
                    print(f"    {item['file']}:{item['rule_id']} (prob={prob:.3f})")

        # FP 정확 제거 항목
        if fp_removed > 0:
            print(f"  ✅ FP 제거 항목 (상위 10건):")
            fp_items = [(item, prob) for item, yt, yp, prob in zip(test_items, y_test, y_pred_conservative, y_prob)
                        if yt == 0 and yp == 0]
            fp_items.sort(key=lambda x: x[1])
            for item, prob in fp_items[:10]:
                print(f"    {item['file']}:{item['rule_id']} (prob={prob:.3f})")

        results.append({
            "test_set": test_idx + 1,
            "tp": tp, "fn": fn,
            "fp_removed": fp_removed, "fp_kept": fp_kept,
            "recall": tp / (tp + fn) if (tp + fn) else 1.0,
        })

        # Feature importance
        if test_idx == 0:
            print(f"\n  [특징 중요도 (GBM)]")
            imp = clf.feature_importances_
            sorted_idx = np.argsort(imp)[::-1]
            for j in sorted_idx[:10]:
                print(f"    {feat_names[j]:25s}: {imp[j]:.4f}")

    # 전체 요약
    print("\n" + "=" * 60)
    print("교차검증 전체 요약")
    print("=" * 60)
    total_tp = sum(r["tp"] for r in results)
    total_fn = sum(r["fn"] for r in results)
    total_fp_removed = sum(r["fp_removed"] for r in results)
    total_fp_kept = sum(r["fp_kept"] for r in results)
    overall_recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) else 1.0
    overall_fp_removal = total_fp_removed / (total_fp_removed + total_fp_kept) if (total_fp_removed + total_fp_kept) else 0

    print(f"  TP 유지: {total_tp}, FN(TP 오분류): {total_fn}")
    print(f"  FP 제거: {total_fp_removed}, FP 유지: {total_fp_kept}")
    print(f"  전체 Recall: {overall_recall:.1%}")
    print(f"  전체 FP 제거율: {overall_fp_removal:.1%}")
    print(f"  {'✅ Recall 100% 유지' if total_fn == 0 else '❌ Recall 손실 발생'}")

    return results


if __name__ == "__main__":
    print("=" * 60)
    print("방안 5: GT 기반 FP 분류기 학습 + 교차검증")
    print("=" * 60)
    all_sets = collect_data()
    if all_sets:
        train_and_evaluate(all_sets)
