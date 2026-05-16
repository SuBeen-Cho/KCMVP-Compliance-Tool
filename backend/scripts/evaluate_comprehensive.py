"""
KCMVP 종합 성능 평가 (보완 버전)
====================================
1. 세트 1~7 코드 평가 (L1 + L3, 토큰 추적)
2. 0_KCMVP 블라인드 평가 (GT 없음)
3. Ablation Study: 세트 1~4 + 0_KCMVP 전체 FP 기준, 병렬 실행

Usage:
    python scripts/evaluate_comprehensive.py               # 전체 실행
    python scripts/evaluate_comprehensive.py --no-ablation # ablation 제외
    python scripts/evaluate_comprehensive.py --only-ablation        # ablation만 (순차)
    python scripts/evaluate_comprehensive.py --ablation-parallel    # ablation만 (병렬, 권장)
    python scripts/evaluate_comprehensive.py --ablation-single baseline  # 단일 조건
"""

import sys, os, re, time, json, zipfile, tempfile, io, subprocess
from pathlib import Path
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Set, Optional, Any

BACKEND_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(BACKEND_ROOT))

USE_L3             = "--no-l3"             not in sys.argv
RUN_ABLATION       = "--no-ablation"       not in sys.argv
ONLY_ABLATION      = "--only-ablation"     in sys.argv
ABLATION_PARALLEL  = "--ablation-parallel" in sys.argv

# --ablation-single <config_name> 모드
_SINGLE_CONFIG: Optional[str] = None
for _i, _a in enumerate(sys.argv):
    if _a == "--ablation-single" and _i + 1 < len(sys.argv):
        _SINGLE_CONFIG = sys.argv[_i + 1]
        break

# --ablation-sets 1,2,3,4  (기본값: 1,2,3,4)
ABLATION_SETS: List[int] = [1, 2, 3, 4]
for _i, _a in enumerate(sys.argv):
    if _a == "--ablation-sets" and _i + 1 < len(sys.argv):
        ABLATION_SETS = [int(x) for x in sys.argv[_i + 1].split(",")]
        break

KCMVP_ROOT = BACKEND_ROOT.parent.parent          # …/KCMVP/
SET_BASE   = KCMVP_ROOT / "스크립트" / "코드 - 설계서 세트"
BLIND_ZIP  = BACKEND_ROOT.parent / "0_KCMVP.zip"  # 보완 root
RULES_DIR  = BACKEND_ROOT / "rules"

# ─── 서비스 임포트 ───────────────────────────────────────────────────
from app.services.rule_engine_service import run_rule_engine

try:
    from app.services.llm.l3_judge import run_l3_contextualizer
    from app.services.report_service import post_process_violations
    import app.services.llm.gemini_client as _gc_mod
    import app.services.llm.prompt_builder as _pb_mod
    L3_AVAILABLE = True
except Exception as _e:
    print(f"[WARN] L3 임포트 실패: {_e}")
    L3_AVAILABLE = False

if not L3_AVAILABLE:
    USE_L3 = False

# ─── GT 제외 규칙 (API 명칭 강제 등) ────────────────────────────────
_GT_EXCLUDE_RULES = frozenset({
    "CBC-LEA-004", "CTR-LEA-004", "GCM-LEA-001", "CMAC-LEA-001",
    "CCM-LEA-001", "ECB-001", "OFB-LEA-001", "CFB-LEA-001",
    "COM-006", "LEA-051", "LEA-052", "LEA-054", "LEA-055",
    "CTR-LEA-005", "LEA-012", "LEA-049", "LEA-050", "LEA-058",
})

# ─── 제출 아티팩트 스코프 규칙 (파일 단위 → 프로젝트 단위 매칭) ──────
# LEA-048/062는 KAT REQUEST/RESPONSE 파일이 프로젝트에 존재하는지 확인하는 규칙.
# 개별 코드 파일이 아닌 "프로젝트 전체"에 아티팩트가 있는지로 평가해야 함.
# → TP/FN 판정 시 파일명 무관하게 rule_id가 프로젝트 어딘가에서 탐지되면 TP로 처리.
_PROJECT_SCOPE_RULES = frozenset({"LEA-048", "LEA-062"})

# Gemini 비용 단가 (입력 $0.10/1M, 출력 $0.40/1M — Flash Lite)
_PRICE_IN  = 0.10 / 1_000_000
_PRICE_OUT = 0.40 / 1_000_000


# ═══════════════════════════════════════════════════════════════════
# GT 추출
# ═══════════════════════════════════════════════════════════════════

def extract_code_gt(zip_path: Path) -> Dict[str, List[Dict]]:
    pattern = re.compile(r'\[위반[:\s]*([A-Z]+-[A-Z]*-?\d+)\]')
    gt: Dict[str, List] = defaultdict(list)
    seen: Dict[str, Set] = defaultdict(set)
    with zipfile.ZipFile(zip_path) as zf:
        for name in zf.namelist():
            if not name.endswith('.c'):
                continue
            content = zf.read(name).decode('utf-8', errors='ignore')
            fname = Path(name).name
            for i, line in enumerate(content.split('\n'), 1):
                for rid in pattern.findall(line):
                    if rid in _GT_EXCLUDE_RULES:
                        continue
                    if rid not in seen[fname]:
                        seen[fname].add(rid)
                        gt[fname].append({"rule_id": rid, "line": i})
    return dict(gt)


# ═══════════════════════════════════════════════════════════════════
# 코드 세트 평가 (토큰 추적 포함)
# ═══════════════════════════════════════════════════════════════════

def _reset_tokens():
    if L3_AVAILABLE:
        _gc_mod.reset_token_usage()

def _get_tokens() -> Dict[str, int]:
    if L3_AVAILABLE:
        return _gc_mod.get_token_usage()
    return {"input": 0, "output": 0, "calls": 0}


def _run_pipeline(zip_path: Path, *, use_l3: bool = True) -> Dict:
    """ZIP → L1(+L3) 실행. dict 반환."""
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
            except Exception:
                content = ""
            file_entries.append({
                "path": str(f), "display": f.name,
                "content": content, "lines": content.splitlines(),
                "ast": {},
            })
        preprocess_result = {"files": file_entries}

        # L1
        t0 = time.time()
        l1_violations = run_rule_engine(
            preprocess_result=preprocess_result,
            rules_dir=RULES_DIR,
            job_root=tmp,
        )
        t_l1 = time.time() - t0

        # L3
        t1 = time.time()
        rejected_keys: set = set()
        if use_l3 and USE_L3 and L3_AVAILABLE:
            try:
                l3_violations = run_l3_contextualizer(
                    preprocess_result=preprocess_result,
                    l1_violations=l1_violations,
                    _rejected_tracker=rejected_keys,
                )
                final_violations = post_process_violations(
                    l1=l1_violations, l3=l3_violations,
                    l3_rejected_keys=rejected_keys,
                )
            except Exception as e:
                print(f"  [WARN] L3 실패: {e}")
                final_violations = l1_violations
        else:
            final_violations = l1_violations
        t_l3 = time.time() - t1

    return {
        "file_entries": file_entries,
        "l1_violations": l1_violations,
        "final_violations": final_violations,
        "rejected_keys": rejected_keys,
        "t_l1": t_l1, "t_l3": t_l3,
    }


def evaluate_code_set(zip_path: Path, set_name: str) -> Dict:
    print(f"\n{'─'*60}")
    print(f"[세트] {set_name} 평가 시작")

    code_gt = extract_code_gt(zip_path)
    gt_rules: Set = set()
    for fname, vlist in code_gt.items():
        for v in vlist:
            gt_rules.add((fname, v["rule_id"]))
    print(f"  GT: {len(gt_rules)}건  ({len(code_gt)} 파일)")

    _reset_tokens()
    pipeline = _run_pipeline(zip_path)
    tokens = _get_tokens()
    cost = tokens["input"] * _PRICE_IN + tokens["output"] * _PRICE_OUT

    final_violations = pipeline["final_violations"]
    rejected_keys    = pipeline["rejected_keys"]

    # 탐지 집계
    detected: Dict[str, Set] = defaultdict(set)
    project_scope_detected: Set[str] = set()  # LEA-048/062 등 프로젝트 단위 규칙
    for v in final_violations:
        fname = Path(v.get("file", "")).name
        rid   = v.get("rule_id", "")
        if fname and rid:
            detected[fname].add(rid)
            if rid in _PROJECT_SCOPE_RULES:
                project_scope_detected.add(rid)

    # 프로젝트 단위 GT 집계 (LEA-048/062: 파일 무관, rule_id 존재 여부만)
    project_scope_gt: Set[str] = set()
    for _, vlist in code_gt.items():
        for v in vlist:
            if v["rule_id"] in _PROJECT_SCOPE_RULES:
                project_scope_gt.add(v["rule_id"])
    # 프로젝트 단위 규칙은 file×rule 중복 GT 제거 (1 rule_id = 1 GT 항목)
    project_scope_counted: Set[str] = set()

    TP = FN = FP = 0
    fn_list: List = []
    for fname, vlist in code_gt.items():
        expected = {v["rule_id"] for v in vlist}
        found    = detected.get(fname, set())
        for rid in expected:
            if rid in _PROJECT_SCOPE_RULES:
                # 프로젝트 단위: 이미 카운트한 rule_id면 스킵 (중복 GT 방지)
                if rid in project_scope_counted:
                    continue
                project_scope_counted.add(rid)
                if rid in project_scope_detected:
                    TP += 1
                else:
                    FN += 1
                    fn_list.append(f"[PROJECT]{rid}")
            elif rid in found:
                TP += 1
            else:
                FN += 1
                fn_list.append(f"{fname}:{rid}")
        for rid in found - expected:
            if rid in _PROJECT_SCOPE_RULES:
                continue  # 프로젝트 단위 FP는 아래에서 별도 계산
            FP += 1
    # 프로젝트 단위 규칙 FP: 탐지했으나 GT에 없는 경우
    for rid in project_scope_detected:
        if rid not in project_scope_gt:
            FP += 1

    total_gt  = TP + FN
    recall    = TP / total_gt if total_gt else 0.0
    precision = TP / (TP + FP) if (TP + FP) else 1.0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    # L3 필터 정확도
    l3_correct = l3_wrong = 0
    for (rf, rr, _) in rejected_keys:
        fname = Path(rf).name
        if (fname, rr) in gt_rules:
            l3_wrong += 1
        else:
            l3_correct += 1

    print(f"  GT={total_gt}, TP={TP}, FN={FN}, FP={FP}")
    print(f"  Recall={recall:.1%}, Prec={precision:.1%}, F1={f1:.1%}")
    print(f"  L3 제거={len(rejected_keys)} (정확={l3_correct}, 오판={l3_wrong})")
    print(f"  토큰: 입력 {tokens['input']:,} / 출력 {tokens['output']:,} / 비용 ${cost:.4f}")

    return {
        "set_name": set_name,
        "gt_count": total_gt, "TP": TP, "FN": FN, "FP": FP,
        "recall": recall, "precision": precision, "f1": f1,
        "l1_count": len(pipeline["l1_violations"]),
        "final_count": len(final_violations),
        "l3_rejected": len(rejected_keys),
        "l3_correct": l3_correct, "l3_wrong": l3_wrong,
        "fn_list": fn_list,
        "tokens": tokens, "cost_usd": round(cost, 6),
        "timing": {"l1_s": round(pipeline["t_l1"], 1),
                   "l3_s": round(pipeline["t_l3"], 1)},
    }


# ═══════════════════════════════════════════════════════════════════
# 0_KCMVP 블라인드 평가
# ═══════════════════════════════════════════════════════════════════

def evaluate_blind_kcmvp() -> Dict:
    print(f"\n{'─'*60}")
    print("[블라인드] 0_KCMVP 평가 시작")

    if not BLIND_ZIP.exists():
        print(f"  [SKIP] {BLIND_ZIP} 없음")
        return {"error": "ZIP 없음"}

    # 0_KCMVP.zip → smart-crypto-master.zip 추출
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        with zipfile.ZipFile(BLIND_ZIP) as outer:
            inner_names = [n for n in outer.namelist() if n.endswith('.zip')]
            if inner_names:
                inner_data = outer.read(inner_names[0])
                inner_zip  = tmp / "inner.zip"
                inner_zip.write_bytes(inner_data)
                target_zip = inner_zip
            else:
                outer.extractall(tmp)
                zips = list(tmp.rglob("*.zip"))
                target_zip = zips[0] if zips else BLIND_ZIP

        # target_zip의 C 파일 추출
        src_tmp = tmp / "src"
        src_tmp.mkdir()
        with zipfile.ZipFile(target_zip) as zf:
            total_files = len(zf.namelist())
            c_names = [n for n in zf.namelist() if n.endswith('.c')]
            zf.extractall(src_tmp)

        c_files = sorted(src_tmp.rglob("*.c"))
        total_kloc = 0
        file_entries = []
        for f in c_files:
            try:
                content = f.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                content = ""
            total_kloc += len(content.splitlines())
            file_entries.append({
                "path": str(f), "display": f.name,
                "content": content, "lines": content.splitlines(),
                "ast": {},
            })
        total_kloc = total_kloc / 1000

        preprocess_result = {"files": file_entries}

        _reset_tokens()
        t0 = time.time()
        l1_violations = run_rule_engine(
            preprocess_result=preprocess_result,
            rules_dir=RULES_DIR,
            job_root=src_tmp,
        )
        t_l1 = time.time() - t0

        t1 = time.time()
        rejected_keys: set = set()
        if USE_L3 and L3_AVAILABLE:
            try:
                l3_violations = run_l3_contextualizer(
                    preprocess_result=preprocess_result,
                    l1_violations=l1_violations,
                    _rejected_tracker=rejected_keys,
                )
                final_violations = post_process_violations(
                    l1=l1_violations, l3=l3_violations,
                    l3_rejected_keys=rejected_keys,
                )
            except Exception as e:
                print(f"  [WARN] L3 실패: {e}")
                final_violations = l1_violations
        else:
            final_violations = l1_violations
        t_l3 = time.time() - t1

    tokens = _get_tokens()
    cost   = tokens["input"] * _PRICE_IN + tokens["output"] * _PRICE_OUT

    # 심각도 분포
    sev_dist: Dict[str, int] = defaultdict(int)
    rule_counts: Dict[str, int] = defaultdict(int)
    for v in final_violations:
        sev_dist[v.get("severity", "unknown")] += 1
        rule_counts[v.get("rule_id", "UNKNOWN")] += 1

    top_rules = sorted(rule_counts.items(), key=lambda x: -x[1])[:10]

    print(f"  C 파일: {len(c_files)}개 / {total_kloc:.1f} KLOC")
    print(f"  L1: {len(l1_violations)}건 → L3 최종: {len(final_violations)}건")
    print(f"  심각도: {dict(sev_dist)}")
    print(f"  토큰: 입력 {tokens['input']:,} / 출력 {tokens['output']:,} / 비용 ${cost:.4f}")

    return {
        "c_files": len(c_files), "kloc": round(total_kloc, 1),
        "l1_count": len(l1_violations),
        "l3_rejected": len(rejected_keys),
        "final_count": len(final_violations),
        "severity_dist": dict(sev_dist),
        "top_rules": [{"rule_id": r, "count": c} for r, c in top_rules],
        "tokens": tokens, "cost_usd": round(cost, 6),
        "timing": {"l1_s": round(t_l1, 1), "l3_s": round(t_l3, 1)},
    }


# ═══════════════════════════════════════════════════════════════════
# Ablation Study (세트 1~4 + 0_KCMVP 전체 FP 기준, 병렬 지원)
# ═══════════════════════════════════════════════════════════════════

_ABLATION_CONFIGS = {
    "baseline":       {"ABLATION_NO_COT": "0", "ABLATION_NO_REJUDGE": "0",
                       "ABLATION_NO_GCFS": "0", "ABLATION_NO_DUAL_VERIFY": "0",
                       "ABLATION_NO_L3": "0"},
    "no_cot":         {"ABLATION_NO_COT": "1", "ABLATION_NO_REJUDGE": "0",
                       "ABLATION_NO_GCFS": "0", "ABLATION_NO_DUAL_VERIFY": "0",
                       "ABLATION_NO_L3": "0"},
    "no_rejudge":     {"ABLATION_NO_COT": "0", "ABLATION_NO_REJUDGE": "1",
                       "ABLATION_NO_GCFS": "0", "ABLATION_NO_DUAL_VERIFY": "0",
                       "ABLATION_NO_L3": "0"},
    "no_gcfs":        {"ABLATION_NO_COT": "0", "ABLATION_NO_REJUDGE": "0",
                       "ABLATION_NO_GCFS": "1", "ABLATION_NO_DUAL_VERIFY": "0",
                       "ABLATION_NO_L3": "0"},
    "no_dual_verify": {"ABLATION_NO_COT": "0", "ABLATION_NO_REJUDGE": "0",
                       "ABLATION_NO_GCFS": "0", "ABLATION_NO_DUAL_VERIFY": "1",
                       "ABLATION_NO_L3": "0"},
    "no_l3":          {"ABLATION_NO_COT": "0", "ABLATION_NO_REJUDGE": "0",
                       "ABLATION_NO_GCFS": "0", "ABLATION_NO_DUAL_VERIFY": "0",
                       "ABLATION_NO_L3": "1", "ABLATION_NO_MISSING_PROTECT": "0"},
    "no_missing_protect": {"ABLATION_NO_COT": "0", "ABLATION_NO_REJUDGE": "0",
                       "ABLATION_NO_GCFS": "0", "ABLATION_NO_DUAL_VERIFY": "0",
                       "ABLATION_NO_L3": "0", "ABLATION_NO_MISSING_PROTECT": "1"},
}

_ABLATION_FLAGS = [
    "ABLATION_NO_COT", "ABLATION_NO_REJUDGE",
    "ABLATION_NO_GCFS", "ABLATION_NO_DUAL_VERIFY", "ABLATION_NO_L3",
    "ABLATION_NO_MISSING_PROTECT",
]


def _collect_unique_pairs(violations: List[Dict]) -> Set:
    """위반 목록에서 고유 (filename, rule_id) 쌍을 반환."""
    pairs: Set = set()
    for v in violations:
        fname = Path(v.get("file", "")).name
        rid   = v.get("rule_id", "")
        if fname and rid:
            pairs.add((fname, rid))
    return pairs


def _run_blind_pipeline_for_ablation(use_l3: bool = True) -> int:
    """0_KCMVP 블라인드 파이프라인 실행, FP 고유 쌍 수 반환 (모두 FP로 간주)."""
    if not BLIND_ZIP.exists():
        return 0
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        with zipfile.ZipFile(BLIND_ZIP) as outer:
            inner_names = [n for n in outer.namelist() if n.endswith('.zip')]
            if inner_names:
                inner_data = outer.read(inner_names[0])
                inner_zip  = tmp / "inner.zip"
                inner_zip.write_bytes(inner_data)
                target_zip = inner_zip
            else:
                outer.extractall(tmp)
                zips = list(tmp.rglob("*.zip"))
                target_zip = zips[0] if zips else BLIND_ZIP

        src_tmp = tmp / "src"
        src_tmp.mkdir()
        with zipfile.ZipFile(target_zip) as zf:
            zf.extractall(src_tmp)

        c_files = sorted(src_tmp.rglob("*.c"))
        file_entries = []
        for f in c_files:
            try:
                content = f.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                content = ""
            file_entries.append({
                "path": str(f), "display": f.name,
                "content": content, "lines": content.splitlines(),
                "ast": {},
            })
        preprocess_result = {"files": file_entries}
        l1_v = run_rule_engine(
            preprocess_result=preprocess_result,
            rules_dir=RULES_DIR,
            job_root=src_tmp,
        )
        rejected_keys: set = set()
        if use_l3 and L3_AVAILABLE:
            try:
                l3_v = run_l3_contextualizer(
                    preprocess_result=preprocess_result,
                    l1_violations=l1_v,
                    _rejected_tracker=rejected_keys,
                )
                final_v = post_process_violations(
                    l1=l1_v, l3=l3_v, l3_rejected_keys=rejected_keys,
                )
            except Exception as e:
                print(f"  [WARN] L3 실패(blind): {e}")
                final_v = l1_v
        else:
            final_v = l1_v
    return len(_collect_unique_pairs(final_v))


def run_ablation_single_config(config_name: str, env_vals: Dict) -> Dict:
    """세트 1~4 + 0_KCMVP에서 단일 ablation 조건 실행 (전체 FP 기준)."""
    if not L3_AVAILABLE:
        return {"config": config_name, "error": "L3 모듈 없음"}

    # 환경 변수 설정
    for k, v in env_vals.items():
        os.environ[k] = v
    _pb_mod._l3_cache.clear()
    _reset_tokens()

    t_start = time.time()
    all_TP = all_FP_sets = all_FN = 0

    use_l3_this = env_vals.get("ABLATION_NO_L3") != "1"

    # ── 세트 평가 (세트별 독립 GT 비교) ──
    for i in ABLATION_SETS:
        zip_path = SET_BASE / f"세트 {i}" / "kcmvp_combined.zip"
        if not zip_path.exists():
            continue
        code_gt = extract_code_gt(zip_path)
        set_gt_pairs: Set = set()
        for fname, vlist in code_gt.items():
            for v in vlist:
                set_gt_pairs.add((fname, v["rule_id"]))

        pipeline = _run_pipeline(zip_path, use_l3=use_l3_this)
        detected = _collect_unique_pairs(pipeline["final_violations"])

        for pair in detected:
            if pair in set_gt_pairs:
                all_TP += 1
            else:
                all_FP_sets += 1
        for pair in set_gt_pairs:
            if pair not in detected:
                all_FN += 1

    # ── 0_KCMVP 블라인드 (검증된 모듈 → 탐지 전부 FP) ──
    fp_blind = _run_blind_pipeline_for_ablation(use_l3=use_l3_this)

    tokens = _get_tokens()
    cost   = tokens["input"] * _PRICE_IN + tokens["output"] * _PRICE_OUT

    FP_total  = all_FP_sets + fp_blind
    total_gt  = all_TP + all_FN
    recall    = all_TP / total_gt if total_gt else 0.0
    precision = all_TP / (all_TP + FP_total) if (all_TP + FP_total) else 1.0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    elapsed = time.time() - t_start
    print(f"    [{config_name}] Recall={recall:.1%}, Prec={precision:.1%}, F1={f1:.1%}, "
          f"FP={FP_total}(세트={all_FP_sets}, blind={fp_blind}), 소요={elapsed:.0f}s")

    # 환경 변수 원복
    for k in _ABLATION_FLAGS:
        os.environ.pop(k, None)
    _pb_mod._l3_cache.clear()

    return {
        "config": config_name,
        "env": env_vals,
        "TP": all_TP, "FN": all_FN,
        "FP_sets": all_FP_sets, "FP_blind": fp_blind, "FP_total": FP_total,
        "recall": recall, "precision": precision, "f1": f1,
        "tokens": tokens, "cost_usd": round(cost, 6),
        "elapsed_s": round(elapsed, 1),
    }


def run_ablation_sequential() -> List[Dict]:
    """5개 조건 순차 실행."""
    if not L3_AVAILABLE:
        print("[SKIP] Ablation: L3 모듈 없음")
        return []

    print(f"\n{'─'*60}")
    print("[Ablation] 세트 1~4 + 0_KCMVP 전체 FP 기준, 5조건 순차 실행")
    results = []
    for config_name, env_vals in _ABLATION_CONFIGS.items():
        print(f"\n  [Ablation] {config_name}")
        r = run_ablation_single_config(config_name, env_vals)
        results.append(r)
    return results


def run_ablation_parallel_procs() -> List[Dict]:
    """5개 조건을 서브프로세스로 병렬 실행 (3개씩 배치)."""
    print(f"\n{'─'*60}")
    print("[Ablation] 병렬 실행 시작 (배치 3개씩)")

    script_path = Path(__file__).resolve()
    python_exe  = sys.executable
    out_dir     = BACKEND_ROOT / "scripts"

    configs = list(_ABLATION_CONFIGS.keys())
    results_map: Dict[str, Dict] = {}

    for batch_start in range(0, len(configs), 3):
        batch = configs[batch_start:batch_start + 3]
        print(f"\n  배치: {batch}")
        procs: Dict[str, Any] = {}
        log_handles: Dict[str, Any] = {}

        for cfg in batch:
            log_path = out_dir / f"ablation_{cfg}.log"
            env = os.environ.copy()
            env["PYTHONUNBUFFERED"] = "1"
            lf = open(log_path, "w", encoding="utf-8")
            log_handles[cfg] = lf
            sets_arg = ",".join(str(s) for s in ABLATION_SETS)
            p = subprocess.Popen(
                [python_exe, str(script_path),
                 "--ablation-single", cfg,
                 "--ablation-sets", sets_arg],
                stdout=lf, stderr=subprocess.STDOUT,
                env=env,
            )
            procs[cfg] = p
            print(f"    PID {p.pid} → {cfg}  (로그: {log_path.name})")

        for cfg, p in procs.items():
            p.wait()
            log_handles[cfg].close()
            print(f"    [{cfg}] 종료 (rc={p.returncode})")

            sets_sfx = "s" + "".join(str(s) for s in ABLATION_SETS)
            result_path = out_dir / f"ablation_{cfg}_{sets_sfx}.json"
            if result_path.exists():
                try:
                    results_map[cfg] = json.loads(
                        result_path.read_text(encoding="utf-8"))
                except Exception as e:
                    results_map[cfg] = {"config": cfg, "error": str(e)}
            else:
                results_map[cfg] = {"config": cfg, "error": "결과 파일 없음"}

    return [results_map.get(cfg, {"config": cfg, "error": "실행 안됨"})
            for cfg in configs]


# ═══════════════════════════════════════════════════════════════════
# 메인
# ═══════════════════════════════════════════════════════════════════

def main():
    # ── 단일 config 서브프로세스 모드 (병렬 실행 시 자식 프로세스) ──
    if _SINGLE_CONFIG is not None:
        cfg = _SINGLE_CONFIG
        env_vals = _ABLATION_CONFIGS.get(cfg)
        if env_vals is None:
            print(f"[ERR] 알 수 없는 config: {cfg}")
            sys.exit(1)
        print(f"[Ablation-Single] {cfg} 시작")
        sets_suffix = "s" + "".join(str(s) for s in ABLATION_SETS)
        result = run_ablation_single_config(cfg, env_vals)
        out_path = BACKEND_ROOT / "scripts" / f"ablation_{cfg}_{sets_suffix}.json"
        out_path.write_text(
            json.dumps(result, ensure_ascii=False, indent=2, default=str),
            encoding="utf-8",
        )
        print(f"[Ablation-Single] {cfg} 완료 → {out_path.name}")
        return

    print("=" * 65)
    print("KCMVP 종합 성능 평가 (보완 버전)")
    print(f"L3: {'활성화' if USE_L3 else '비활성화'}")
    print(f"Ablation: {'활성화' if RUN_ABLATION else '비활성화'}")
    print(f"병렬 Ablation: {'활성화' if ABLATION_PARALLEL else '비활성화'}")
    print(f"측정일: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print("=" * 65)

    t_global = time.time()

    # ── Only-ablation 모드: 이전 결과 로드 후 ablation만 실행 ─────
    if ONLY_ABLATION:
        prev_path = BACKEND_ROOT / "scripts" / "comprehensive_eval_results.json"
        prev = json.loads(prev_path.read_text(encoding="utf-8")) if prev_path.exists() else {}
        if USE_L3 and L3_AVAILABLE:
            if ABLATION_PARALLEL:
                ablation_results = run_ablation_parallel_procs()
            else:
                ablation_results = run_ablation_sequential()
        else:
            ablation_results = []
        total_elapsed = time.time() - t_global
        print(f"\nAblation 소요 시간: {total_elapsed:.0f}초")
        prev["ablation"] = ablation_results
        prev["ablation_timestamp"] = datetime.now().isoformat()
        out_path = BACKEND_ROOT / "scripts" / "comprehensive_eval_results.json"
        out_path.write_text(json.dumps(prev, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        print(f"결과 JSON 갱신: {out_path}")
        return

    # ── 세트 1~7 평가 ────────────────────────────────────────────
    all_results = []
    for i in range(1, 8):
        set_dir  = SET_BASE / f"세트 {i}"
        zip_path = set_dir / "kcmvp_combined.zip"
        if not zip_path.exists():
            print(f"\n[SKIP] 세트 {i}: ZIP 없음 ({zip_path})")
            continue
        result = evaluate_code_set(zip_path, f"세트 {i}")
        all_results.append(result)

    # ── 세트 1~4 집계 ──
    r14 = [r for r in all_results if r["set_name"] in [f"세트 {i}" for i in range(1, 5)]]
    r57 = [r for r in all_results if r["set_name"] in [f"세트 {i}" for i in range(5, 8)]]

    def _agg(rs):
        gt = sum(r["gt_count"] for r in rs)
        tp = sum(r["TP"] for r in rs)
        fn = sum(r["FN"] for r in rs)
        fp = sum(r["FP"] for r in rs)
        rc = tp / gt if gt else 0.0
        pr = tp / (tp + fp) if (tp + fp) else 1.0
        f1 = 2 * pr * rc / (pr + rc) if (pr + rc) else 0.0
        cost = sum(r["cost_usd"] for r in rs)
        return {"GT": gt, "TP": tp, "FN": fn, "FP": fp,
                "Recall": rc, "Precision": pr, "F1": f1, "cost_usd": cost}

    agg14 = _agg(r14)
    agg57 = _agg(r57)
    agg_all = _agg(all_results)

    print("\n" + "=" * 65)
    print("  [세트 1~4 합계]")
    print(f"  GT={agg14['GT']}, TP={agg14['TP']}, FN={agg14['FN']}, FP={agg14['FP']}")
    print(f"  Recall={agg14['Recall']:.1%}, Prec={agg14['Precision']:.1%}, F1={agg14['F1']:.1%}")
    print(f"  비용: ${agg14['cost_usd']:.4f}")
    if r57:
        print(f"\n  [세트 5~7 합계 (뮤테이션)]")
        print(f"  GT={agg57['GT']}, TP={agg57['TP']}, FN={agg57['FN']}, FP={agg57['FP']}")
        print(f"  Recall={agg57['Recall']:.1%}, Prec={agg57['Precision']:.1%}, F1={agg57['F1']:.1%}")
        print(f"  비용: ${agg57['cost_usd']:.4f}")
    print(f"\n  [전체 1~7 합계]")
    print(f"  GT={agg_all['GT']}, TP={agg_all['TP']}, FN={agg_all['FN']}, FP={agg_all['FP']}")
    print(f"  Recall={agg_all['Recall']:.1%}, Prec={agg_all['Precision']:.1%}, F1={agg_all['F1']:.1%}")
    total_tokens = {"input": 0, "output": 0, "calls": 0}
    for r in all_results:
        for k in total_tokens:
            total_tokens[k] += r["tokens"].get(k, 0)
    total_cost = sum(r["cost_usd"] for r in all_results)
    print(f"  토큰 합계: 입력 {total_tokens['input']:,} / 출력 {total_tokens['output']:,}")
    print(f"  총 비용: ${total_cost:.4f}")
    print("=" * 65)

    # ── 0_KCMVP 블라인드 ──────────────────────────────────────────
    blind_result = evaluate_blind_kcmvp()

    # ── Ablation ─────────────────────────────────────────────────
    ablation_results = []
    if RUN_ABLATION and USE_L3 and L3_AVAILABLE:
        if ABLATION_PARALLEL:
            ablation_results = run_ablation_parallel_procs()
        else:
            ablation_results = run_ablation_sequential()

    total_elapsed = time.time() - t_global
    print(f"\n총 소요 시간: {total_elapsed:.0f}초 ({total_elapsed/60:.1f}분)")

    # ── JSON 저장 ──────────────────────────────────────────────────
    output = {
        "timestamp": datetime.now().isoformat(),
        "use_l3": USE_L3,
        "total_elapsed_s": round(total_elapsed, 1),
        "sets_1_to_7": all_results,
        "aggregate_1_4": agg14,
        "aggregate_5_7": agg57,
        "aggregate_all": agg_all,
        "total_tokens": total_tokens,
        "total_cost_usd": round(total_cost, 6),
        "blind_kcmvp": blind_result,
        "ablation": ablation_results,
    }
    out_path = BACKEND_ROOT / "scripts" / "comprehensive_eval_results.json"
    out_path.write_text(
        json.dumps(output, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )
    print(f"결과 JSON 저장: {out_path}")


if __name__ == "__main__":
    main()
