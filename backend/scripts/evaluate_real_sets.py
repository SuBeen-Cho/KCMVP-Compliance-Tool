"""
KCMVP 실제 코드-설계서 세트 성능 평가 스크립트
==============================================
스크립트/코드 - 설계서 세트/세트 1~4 에 대해 코드+설계서 평가 수행.

1단계: 코드 C 파일 내 [위반: RULE-ID] 주석을 파싱하여 코드 ground truth 자동 추출
2단계: 정답지_위반목록.md 에서 설계서 ground truth 추출 (세트 2~4)
3단계: L1(+L3) 파이프라인 실행 → 탐지 결과와 GT 대조
4단계: DOC 규칙 엔진 실행 → 탐지 결과와 GT 대조
5단계: 결과 집계 및 마크다운 보고서 생성 (논문 표 7 형식)

Usage:
    cd backend
    python scripts/evaluate_real_sets.py [--no-l3]
"""

import sys, os, re, time, json, zipfile, tempfile, shutil
from pathlib import Path
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Set, Tuple, Optional

BACKEND_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(BACKEND_ROOT))

USE_L3 = "--no-l3" not in sys.argv

KCMVP_ROOT = BACKEND_ROOT.parent.parent  # KCMVP/
SET_BASE = KCMVP_ROOT / "스크립트" / "코드 - 설계서 세트"

from app.services.rule_engine_service import run_rule_engine
from app.services.preprocess_docs_service import run_doc_preprocess
from app.services.doc_rule_service import load_doc_rules, run_doc_rule_engine

try:
    from app.services.llm_service import run_l3_contextualizer, run_doc_l3_contextualizer
    from app.services.report_service import post_process_violations
    L3_AVAILABLE = True
except Exception:
    L3_AVAILABLE = False

if not L3_AVAILABLE:
    USE_L3 = False


# ═══════════════════════════════════════════════════════════════════
# 1. 코드 GT 자동 추출: C 파일 내 [위반: RULE-ID] 주석 파싱
# ═══════════════════════════════════════════════════════════════════

# KISA API 명칭 강제 룰 — 실제 KCMVP 요건이 아님, GT에서 제외
_GT_EXCLUDE_RULES = frozenset({
    "CBC-LEA-004",   # lea_cbc_enc/dec 명칭 강제
    "CTR-LEA-004",   # lea_ctr_enc/dec 명칭 강제
    "GCM-LEA-001",   # lea_gcm_* 명칭 강제
    "CMAC-LEA-001",  # lea_cmac_* 명칭 강제
    "CCM-LEA-001",   # lea_ccm_enc/dec 명칭 강제
    "ECB-001",       # lea_ecb_enc/dec 명칭 강제
    "OFB-LEA-001",   # lea_ofb_enc/dec 명칭 강제
    "CFB-LEA-001",   # lea_cfb128_enc/dec 명칭 강제
    "COM-006",       # lea_* 접두사 함수명 강제
    "LEA-051",       # lea_set_key 명칭 강제
})


def extract_code_gt_from_zip(zip_path: Path) -> Dict[str, List[Dict]]:
    """
    ZIP 내 C 파일의 [위반: RULE-ID] 주석을 파싱.
    Returns: {filename: [{rule_id, line, comment}, ...]}
    """
    pattern = re.compile(r'\[위반[:\s]*([A-Z]+-[A-Z]*-?\d+)\]')
    gt = defaultdict(list)
    seen = defaultdict(set)  # (filename, rule_id) 중복 방지

    with zipfile.ZipFile(zip_path) as zf:
        for name in zf.namelist():
            if not name.endswith('.c'):
                continue
            content = zf.read(name).decode('utf-8', errors='ignore')
            fname = Path(name).name
            for i, line in enumerate(content.split('\n'), 1):
                # 한 줄에 여러 [위반: RULE-ID] 주석이 있을 수 있음 → findall 사용
                matches = pattern.findall(line)
                for rid in matches:
                    if rid in _GT_EXCLUDE_RULES:
                        continue  # API 명칭 강제 룰 제외
                    if rid not in seen[fname]:
                        seen[fname].add(rid)
                        gt[fname].append({
                            "rule_id": rid,
                            "line": i,
                            "comment": line.strip()[:150],
                        })
    return dict(gt)


# ═══════════════════════════════════════════════════════════════════
# 2. 설계서 GT 파싱: 정답지_위반목록.md
# ═══════════════════════════════════════════════════════════════════

def parse_design_gt(gt_path: Path) -> List[Dict]:
    """정답지에서 설계서(design) 위반만 추출."""
    if not gt_path.exists():
        return []
    text = gt_path.read_text(encoding='utf-8')
    violations = []
    in_design = False
    current = None

    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("## 설계서"):
            in_design = True
            continue
        if stripped.startswith("## 형상관리") or stripped.startswith("## 시험서"):
            in_design = False
            continue
        if not in_design:
            continue

        # ### N. [RULE-ID] — page
        header_match = re.match(r'###\s+\d+\.\s+\[([^\]]+)\]\s*—?\s*(.*)', stripped)
        if header_match:
            rule_id = header_match.group(1).strip()
            page_info = header_match.group(2).strip()
            current = {"rule_id": rule_id, "page": page_info}
            continue

        # > 설명 텍스트
        if stripped.startswith(">") and current:
            current["description"] = stripped.lstrip("> ").strip()
            violations.append(current)
            current = None

    return violations


# ═══════════════════════════════════════════════════════════════════
# 3. 코드 평가 (L3 필터링 정확도 포함)
# ═══════════════════════════════════════════════════════════════════

def evaluate_code_set(zip_path: Path, set_name: str) -> Dict:
    """코드 ZIP에 대해 L1(+L3) 평가."""
    print(f"\n{'─'*60}")
    print(f"[코드] {set_name} 평가 시작")

    code_gt = extract_code_gt_from_zip(zip_path)
    gt_rules = set()
    for fname, vlist in code_gt.items():
        for v in vlist:
            gt_rules.add((fname, v["rule_id"]))
    print(f"  코드 GT: {len(gt_rules)}개 (파일×규칙) from {len(code_gt)} files")
    for fname in sorted(code_gt.keys()):
        rids = sorted({v["rule_id"] for v in code_gt[fname]})
        print(f"    {fname}: {', '.join(rids)}")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(tmp)

        src_dir = tmp / "src" if (tmp / "src").exists() else tmp
        c_files = sorted(src_dir.rglob("*.c"))

        file_entries = []
        for f in c_files:
            try:
                content = f.read_text(encoding="utf-8", errors="ignore")
            except:
                content = ""
            file_entries.append({
                "path": str(f), "display": f.name,
                "content": content, "ast": {},
            })
        preprocess_result = {"files": file_entries}

        # L1
        t0 = time.time()
        rules_dir = BACKEND_ROOT / "rules"
        l1_violations = run_rule_engine(
            preprocess_result=preprocess_result,
            rules_dir=rules_dir,
            job_root=tmp,
        )
        t_l1 = time.time() - t0
        print(f"  L1: {len(l1_violations)}건, {t_l1:.1f}s")

        # L3 (L3)
        t1 = time.time()
        l3_rejected_keys = set()
        l3_rejected_detail = []  # (fname, rule_id) 목록
        if USE_L3 and L3_AVAILABLE:
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
        else:
            final_violations = l1_violations
        t_l3 = time.time() - t1
        print(f"  L3: 최종 {len(final_violations)}건, 제거 {len(l3_rejected_keys)}건, {t_l3:.1f}s")

        # L3 필터링 정확도 계산
        l3_correct = 0  # GT 외 오탐 → 정확 제거
        l3_wrong = 0    # GT 내 → 오판 (FN 유발)
        for (rej_file, rej_rid, rej_line) in l3_rejected_keys:
            fname = Path(rej_file).name
            if (fname, rej_rid) in gt_rules:
                l3_wrong += 1
                l3_rejected_detail.append({"file": fname, "rule_id": rej_rid, "correct": False})
            else:
                l3_correct += 1
                l3_rejected_detail.append({"file": fname, "rule_id": rej_rid, "correct": True})

    # 탐지 결과 집계 (파일명, rule_id)
    detected = defaultdict(set)
    detected_detail = defaultdict(list)
    for v in final_violations:
        fname = Path(v.get("file", "")).name
        rid = v.get("rule_id", "")
        if fname and rid:
            detected[fname].add(rid)
            detected_detail[fname].append(v)

    # 혼동행렬 (GT 기준)
    TP = 0; FN = 0; FP_extra = 0
    tp_list = []; fn_list = []; fp_list = []

    for fname, vlist in code_gt.items():
        expected_rids = {v["rule_id"] for v in vlist}
        detected_rids = detected.get(fname, set())

        for rid in expected_rids:
            if rid in detected_rids:
                TP += 1
                tp_list.append({"file": fname, "rule_id": rid})
            else:
                FN += 1
                fn_list.append({"file": fname, "rule_id": rid})

        # GT에 없는 추가 탐지 (over-detection)
        extra = detected_rids - expected_rids
        for rid in extra:
            FP_extra += 1
            fp_list.append({"file": fname, "rule_id": rid})

    total_gt = TP + FN
    recall = TP / total_gt if total_gt > 0 else 0.0
    precision = TP / (TP + FP_extra) if (TP + FP_extra) > 0 else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    print(f"  → GT={total_gt}, TP={TP}, FN={FN}, 추가탐지={FP_extra}")
    print(f"  → Recall={recall:.1%}, Precision={precision:.1%}, F1={f1:.1%}")
    if l3_rejected_keys:
        l3_total = len(l3_rejected_keys)
        print(f"  → L3 제거 {l3_total}건: 정확={l3_correct}건({l3_correct/l3_total:.1%}), 오판={l3_wrong}건({l3_wrong/l3_total:.1%})")

    return {
        "set_name": set_name,
        "code_gt": code_gt,
        "gt_count": total_gt,
        "TP": TP, "FN": FN, "FP_extra": FP_extra,
        "precision": precision, "recall": recall, "f1": f1,
        "l1_count": len(l1_violations),
        "l3_rejected": len(l3_rejected_keys),
        "l3_correct_removals": l3_correct,
        "l3_wrong_removals": l3_wrong,
        "l3_rejected_detail": l3_rejected_detail,
        "final_count": len(final_violations),
        "tp_list": tp_list, "fn_list": fn_list, "fp_list": fp_list,
        "timing": {"l1_s": round(t_l1, 1), "l3_s": round(t_l3, 1),
                    "total_s": round(t_l1 + t_l3, 1)},
        "detected": {k: str(v) for k, v in detected.items()},
    }


# ═══════════════════════════════════════════════════════════════════
# 4. 설계서 평가
# ═══════════════════════════════════════════════════════════════════

def evaluate_design_set(pdf_path: Path, set_name: str,
                        design_gt: List[Dict]) -> Dict:
    """설계서 PDF에 대해 DOC L1(+L3) 평가."""
    print(f"\n[DOC] {set_name} 설계서 평가 중...")

    if not pdf_path.exists():
        return {"error": f"PDF 없음: {pdf_path}", "set_name": set_name,
                "l1_count": 0, "final_count": 0, "detected_rules": [],
                "gt_rules": [], "gt_count": 0, "TP_doc": 0, "FN_doc": 0,
                "FP_doc": 0, "recall_doc": 0.0, "matched": [], "undetected": [],
                "extra": [], "design_gt_details": [],
                "timing": {"prep_s": 0, "l1_s": 0, "l3_s": 0, "total_s": 0}}

    rules_dir = BACKEND_ROOT / "rules"
    doc_rules = load_doc_rules(rules_dir)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        dest_dir = tmp / "docs" / "design"
        dest_dir.mkdir(parents=True)
        shutil.copy(pdf_path, dest_dir / pdf_path.name)

        t0 = time.time()
        try:
            preprocess = run_doc_preprocess(tmp)
        except Exception as e:
            print(f"  [ERROR] DOC 전처리 실패: {e}")
            return {"error": str(e), "set_name": set_name,
                    "l1_count": 0, "final_count": 0, "detected_rules": [],
                    "gt_rules": [], "gt_count": 0, "TP_doc": 0, "FN_doc": 0,
                    "FP_doc": 0, "recall_doc": 0.0, "matched": [], "undetected": [],
                    "extra": [], "design_gt_details": design_gt,
                    "timing": {"prep_s": 0, "l1_s": 0, "l3_s": 0, "total_s": 0}}
        t_prep = time.time() - t0
        sections = preprocess.get("sections", [])
        print(f"  DOC 전처리: {len(sections)}개 섹션, {t_prep:.1f}s")

        t1 = time.time()
        l1_doc = run_doc_rule_engine(preprocess, doc_rules)
        t_l1 = time.time() - t1
        print(f"  DOC L1: {len(l1_doc)}건, {t_l1:.1f}s")

        t2 = time.time()
        if USE_L3 and L3_AVAILABLE and l1_doc:
            try:
                final_doc = run_doc_l3_contextualizer(l1_doc, preprocess)
            except Exception as e:
                print(f"  [WARN] DOC L3 실패: {e}")
                final_doc = l1_doc
        else:
            final_doc = l1_doc
        t_l3 = time.time() - t2

        detected_rule_ids = {v.get("rule_id") for v in final_doc}
        print(f"  DOC L3 최종: {len(final_doc)}건, {t_l3:.1f}s")
        print(f"  탐지된 규칙: {sorted(detected_rule_ids)}")

    # GT 대비 평가
    if design_gt:
        gt_rule_ids = set()
        for v in design_gt:
            gt_rule_ids.add(v["rule_id"])

        matched = gt_rule_ids & detected_rule_ids
        undetected = gt_rule_ids - detected_rule_ids
        extra = detected_rule_ids - gt_rule_ids

        TP_doc = len(matched)
        FN_doc = len(undetected)
        FP_doc = len(extra)

        recall_doc = TP_doc / len(gt_rule_ids) if gt_rule_ids else 0.0

        print(f"  GT={len(gt_rule_ids)}, 직접매칭TP={TP_doc}, FN={FN_doc}")
        print(f"  미탐지 GT: {sorted(undetected)}")
    else:
        TP_doc = FN_doc = FP_doc = 0
        gt_rule_ids = set()
        matched = set()
        undetected = set()
        extra = detected_rule_ids
        recall_doc = 0.0

    return {
        "set_name": set_name,
        "sections": len(sections),
        "l1_count": len(l1_doc),
        "final_count": len(final_doc),
        "detected_rules": sorted(detected_rule_ids),
        "gt_rules": sorted(gt_rule_ids) if design_gt else [],
        "gt_count": len(gt_rule_ids),
        "TP_doc": TP_doc, "FN_doc": FN_doc, "FP_doc": FP_doc,
        "recall_doc": recall_doc,
        "matched": sorted(matched),
        "undetected": sorted(undetected),
        "extra": sorted(extra),
        "design_gt_details": design_gt,
        "timing": {"prep_s": round(t_prep, 1), "l1_s": round(t_l1, 1),
                    "l3_s": round(t_l3, 1), "total_s": round(t_prep + t_l1 + t_l3, 1)},
    }


# ═══════════════════════════════════════════════════════════════════
# 5. 논문 표 7 형식 출력
# ═══════════════════════════════════════════════════════════════════

def print_paper_table(all_code_results: List[Dict], all_doc_results: List[Dict]) -> Dict:
    """논문 '표 7: 코드 위반 탐지 성능' 형식으로 전체 지표 출력."""

    # ── 코드 집계 ──
    total_code_gt  = sum(r.get("gt_count", 0) for r in all_code_results)
    total_code_tp  = sum(r.get("TP", 0)       for r in all_code_results)
    total_code_fn  = sum(r.get("FN", 0)       for r in all_code_results)
    total_fp_extra = sum(r.get("FP_extra", 0) for r in all_code_results)
    code_recall    = total_code_tp / total_code_gt if total_code_gt else 0.0

    # ── L3 필터링 집계 ──
    total_l3_removed  = sum(r.get("l3_rejected", 0)         for r in all_code_results)
    total_l3_correct  = sum(r.get("l3_correct_removals", 0) for r in all_code_results)
    total_l3_wrong    = sum(r.get("l3_wrong_removals", 0)   for r in all_code_results)
    l3_correct_rate   = total_l3_correct / total_l3_removed if total_l3_removed else 0.0
    l3_wrong_rate     = total_l3_wrong   / total_l3_removed if total_l3_removed else 0.0
    l3_remove_rate    = total_l3_removed / (total_code_tp + total_fp_extra + total_l3_removed) \
                        if (total_code_tp + total_fp_extra + total_l3_removed) else 0.0

    # ── 설계서 집계 ──
    doc_counts   = [r.get("final_count", 0) for r in all_doc_results if "error" not in r]
    doc_avg      = sum(doc_counts) / len(doc_counts) if doc_counts else 0.0
    total_doc_gt = sum(r.get("gt_count", 0) for r in all_doc_results)
    total_doc_tp = sum(r.get("TP_doc", 0)   for r in all_doc_results)
    total_doc_fn = sum(r.get("FN_doc", 0)   for r in all_doc_results)

    # ── 전체 GT 및 TP 합산 (코드 + 설계서 GT 매칭분) ──
    total_gt_all = total_code_gt + total_doc_gt
    total_tp_all = total_code_tp + total_doc_tp
    total_fn_all = total_code_fn + total_doc_fn
    combined_recall = total_tp_all / total_gt_all if total_gt_all else 0.0

    print("\n" + "═" * 65)
    print("  표 7: 코드 위반 탐지 성능 (4세트 합산)")
    print("═" * 65)
    print(f"  GT 총계                          : {total_gt_all}건"
          f"  (코드 {total_code_gt}건 + 설계서 {total_doc_gt}건)")
    print("─" * 65)
    print(f"  True Positive (TP)               : {total_tp_all}건"
          f"  (코드 {total_code_tp} + 설계서 {total_doc_tp})")
    print(f"  False Negative (FN)              : {total_fn_all}건")
    print(f"  탐지율 (Recall)                  : {combined_recall:.1%}")
    print(f"  GT 외 추가 탐지 건               : {total_fp_extra}건")
    print("─" * 65)
    if USE_L3:
        print(f"  L3 필터링 — 제거 건수            : {total_l3_removed}건"
              f"  ({l3_remove_rate:.1%})")
        if total_l3_removed:
            print(f"  L3 필터링 — 정확 제거율          : {l3_correct_rate:.1%}"
                  f"  ({total_l3_correct}/{total_l3_removed})")
            print(f"  L3 필터링 — 오판 (FN 유발)       : {total_l3_wrong}건"
                  f"  ({l3_wrong_rate:.1%})")
    else:
        print("  L3 필터링                        : 비활성화 (--no-l3)")
    print("─" * 65)
    print(f"  문서 구조 누락 탐지              : 평균 {doc_avg:.1f}건/세트")
    print("═" * 65)

    # 세트별 상세
    print("\n  [세트별 코드 Recall]")
    for r in all_code_results:
        gt  = r.get("gt_count", 0)
        tp  = r.get("TP", 0)
        rej = r.get("l3_rejected", 0)
        fn  = r.get("FN", 0)
        rc  = tp / gt if gt else 0
        print(f"    {r['set_name']}: {tp}/{gt} = {rc:.1%}  "
              f"(L3 제거 {rej}건, FN {fn}건)")

    print()

    return {
        "total_code_gt": total_code_gt,
        "total_doc_gt": total_doc_gt,
        "total_gt": total_gt_all,
        "total_code_tp": total_code_tp, "total_code_fn": total_code_fn,
        "total_doc_tp": total_doc_tp,   "total_doc_fn": total_doc_fn,
        "combined_recall": combined_recall,
        "code_recall": code_recall,
        "fp_extra": total_fp_extra,
        "l3_removed": total_l3_removed,
        "l3_correct": total_l3_correct, "l3_wrong": total_l3_wrong,
        "l3_correct_rate": l3_correct_rate, "l3_wrong_rate": l3_wrong_rate,
        "doc_avg_per_set": doc_avg,
    }


# ═══════════════════════════════════════════════════════════════════
# 메인
# ═══════════════════════════════════════════════════════════════════

def main():
    print("=" * 65)
    print("KCMVP 실제 코드-설계서 세트 성능 평가")
    print(f"L3 Gemini: {'활성화' if USE_L3 else '비활성화'}")
    print(f"세트 경로: {SET_BASE}")
    print("=" * 65)

    t_start = time.time()
    all_code_results = []
    all_doc_results = []

    for i in range(1, 5):
        set_dir = SET_BASE / f"세트 {i}"
        set_name = f"세트 {i}"

        zip_path = set_dir / "kcmvp_combined.zip"
        pdf_path = set_dir / "kcmvp_violations_design.pdf"
        gt_path  = set_dir / "정답지_위반목록.md"

        if not zip_path.exists():
            print(f"\n[SKIP] {set_name}: ZIP 없음")
            continue

        # 코드 평가
        code_result = evaluate_code_set(zip_path, set_name)
        all_code_results.append(code_result)

        # 설계서 평가
        design_gt = parse_design_gt(gt_path) if gt_path.exists() else []
        doc_result = evaluate_design_set(pdf_path, set_name, design_gt)
        all_doc_results.append(doc_result)

    total_elapsed = time.time() - t_start
    print(f"\n총 소요 시간: {total_elapsed:.1f}초")

    # 논문 표 7 형식 출력
    summary = print_paper_table(all_code_results, all_doc_results)

    # JSON 결과 저장
    results = {
        "timestamp": datetime.now().isoformat(),
        "use_l3": USE_L3,
        "total_elapsed_s": round(total_elapsed, 1),
        "code_results": all_code_results,
        "doc_results": all_doc_results,
        "summary": summary,
    }
    json_path = BACKEND_ROOT / "scripts" / "evaluation_results.json"
    json_path.write_text(json.dumps(results, ensure_ascii=False, indent=2, default=str),
                         encoding='utf-8')
    print(f"\n결과 JSON 저장: {json_path}")


if __name__ == "__main__":
    main()
