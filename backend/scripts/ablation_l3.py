"""
L3 프롬프트 엔지니어링 Ablation Study
======================================
각 프롬프트 구성요소(Few-shot / CoT / GCFS / Dual-Verify / RAG / AST-Protect)의
기여도를 정량적으로 측정.

비결정성 처리: 시나리오당 N_REPS=3회 반복, majority vote 적용.

Usage:
    cd backend
    python scripts/ablation_l3.py [--reps N] [--configs baseline,no_cot,...]

측정 지표:
    L3 Recall     = TP_kept / TP_in
    FP Removal    = FP_removed / FP_in
    FN_created    = GT 위반 중 L3가 오탐으로 제거한 건수
    Net F1        = 최종 precision/recall 기준 F1
"""

import sys, os, re, time, json, zipfile, shutil
from pathlib import Path
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Set, Tuple, Optional

BACKEND_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(BACKEND_ROOT))

SET_BASE = BACKEND_ROOT.parent / "코드 - 설계서 세트"

# ─── 실험 파라미터 ────────────────────────────────────────────────
N_REPS = 3

_args = sys.argv[1:]
if "--reps" in _args:
    idx = _args.index("--reps")
    N_REPS = int(_args[idx + 1])

_all_configs = [
    "baseline", "no_few_shot", "no_cot", "minimal",
    "no_dual_verify", "no_rag", "no_ast_protect", "no_gcfs",
]
if "--configs" in _args:
    idx = _args.index("--configs")
    _all_configs = _args[idx + 1].split(",")

# few_shot / cot / dual_verify / rag / ast_protect
CONFIGS: Dict[str, Dict[str, bool]] = {
    # ── 기존 few-shot / CoT ablation ──────────────────────────────
    "baseline":       {"few_shot": True,  "cot": True,  "dual_verify": True,  "rag": True,  "ast_protect": True,  "gcfs": True},
    "no_few_shot":    {"few_shot": False, "cot": True,  "dual_verify": True,  "rag": True,  "ast_protect": True,  "gcfs": True},
    "no_cot":         {"few_shot": True,  "cot": False, "dual_verify": True,  "rag": True,  "ast_protect": True,  "gcfs": True},
    "minimal":        {"few_shot": False, "cot": False, "dual_verify": True,  "rag": True,  "ast_protect": True,  "gcfs": True},
    # ── 추가 프롬프트 스타일 최적성 검증 ────────────────────────────
    "no_dual_verify": {"few_shot": True,  "cot": True,  "dual_verify": False, "rag": True,  "ast_protect": True,  "gcfs": True},
    "no_rag":         {"few_shot": True,  "cot": True,  "dual_verify": True,  "rag": False, "ast_protect": True,  "gcfs": True},
    "no_ast_protect": {"few_shot": True,  "cot": True,  "dual_verify": True,  "rag": True,  "ast_protect": False, "gcfs": True},
    "no_gcfs":        {"few_shot": True,  "cot": True,  "dual_verify": True,  "rag": True,  "ast_protect": True,  "gcfs": False},
}

ACTIVE_CONFIGS = {k: v for k, v in CONFIGS.items() if k in _all_configs}

# ─── 서비스 임포트 ─────────────────────────────────────────────────
from app.services.rule_engine_service import run_rule_engine
try:
    from app.services.symbol_graph_service import build_symbol_graph as _build_symbol_graph
    _SYMBOL_GRAPH_AVAILABLE = True
except Exception as _e:
    print(f"[WARN] symbol_graph 임포트 실패: {_e}")
    _SYMBOL_GRAPH_AVAILABLE = False
try:
    from app.services.llm_service import run_l3_contextualizer
    from app.services.report_service import post_process_violations
    import app.services.llm.l3_judge as _l3_mod
    import app.services.llm.prompt_templates as _pt_mod
    L3_AVAILABLE = True
except Exception as e:
    print(f"[WARN] L3 임포트 실패: {e}")
    L3_AVAILABLE = False

if not L3_AVAILABLE:
    print("[ABORT] L3 모듈을 임포트할 수 없습니다. 종료.")
    sys.exit(1)


# ═══════════════════════════════════════════════════════════════════
# 1. Few-shot 예시 섹션 제거 유틸
# ═══════════════════════════════════════════════════════════════════

_FEW_SHOT_RE = re.compile(r'【[^】]*예시[^】]*】[^【]*', re.DOTALL)

def _strip_few_shot_examples(template: str) -> str:
    return _FEW_SHOT_RE.sub('', template).strip()

def _count_few_shot_rules() -> int:
    return sum(1 for v in _pt_mod.PROMPT_TEMPLATES.values() if _FEW_SHOT_RE.search(v))


# ═══════════════════════════════════════════════════════════════════
# 2. Monkey-patch 컨텍스트 매니저
# ═══════════════════════════════════════════════════════════════════

class _PatchContext:
    """config에 따라 L3 모듈을 임시 패치하고 복원."""

    def __init__(self, config: Dict[str, bool]):
        self.config = config
        self._orig_isolation   = None
        self._orig_templates   = {}
        self._orig_verify_fp   = None
        self._orig_ast_protect = None

    def __enter__(self):
        # ── CoT off: HIGH_ISOLATION_RULES 비우기 ──
        if not self.config.get("cot", True):
            self._orig_isolation = _l3_mod._HIGH_ISOLATION_RULES
            _l3_mod._HIGH_ISOLATION_RULES = frozenset()
            print("  [patch] CoT OFF: HIGH_ISOLATION_RULES → 빈 집합")

        # ── Few-shot off: PROMPT_TEMPLATES 예시 섹션 제거 ──
        if not self.config.get("few_shot", True):
            self._orig_templates = {k: v for k, v in _pt_mod.PROMPT_TEMPLATES.items()}
            stripped = 0
            for k in list(_pt_mod.PROMPT_TEMPLATES.keys()):
                old = _pt_mod.PROMPT_TEMPLATES[k]
                new = _strip_few_shot_examples(old)
                if old != new:
                    _pt_mod.PROMPT_TEMPLATES[k] = new
                    stripped += 1
            print(f"  [patch] Few-shot OFF: {stripped}개 규칙 예시 섹션 제거")

        # ── Dual-verify off: _verify_fp_removal → 항상 True (즉시 FP 제거) ──
        if not self.config.get("dual_verify", True):
            self._orig_verify_fp = _l3_mod._verify_fp_removal
            _l3_mod._verify_fp_removal = lambda *a, **k: True
            print("  [patch] dual_verify OFF: _verify_fp_removal → always True")

        # ── AST-protect off: _AST_TP_PROTECT 비우기 (fp_high 95 → 80으로 하향) ──
        if not self.config.get("ast_protect", True):
            self._orig_ast_protect = _l3_mod._AST_TP_PROTECT
            _l3_mod._AST_TP_PROTECT = frozenset()
            print("  [patch] ast_protect OFF: _AST_TP_PROTECT → 빈 집합 (fp_high: 95→80)")

        return self

    def __exit__(self, *_):
        if self._orig_isolation is not None:
            _l3_mod._HIGH_ISOLATION_RULES = self._orig_isolation
            self._orig_isolation = None
        if self._orig_templates:
            for k, v in self._orig_templates.items():
                _pt_mod.PROMPT_TEMPLATES[k] = v
            self._orig_templates = {}
        if self._orig_verify_fp is not None:
            _l3_mod._verify_fp_removal = self._orig_verify_fp
            self._orig_verify_fp = None
        if self._orig_ast_protect is not None:
            _l3_mod._AST_TP_PROTECT = self._orig_ast_protect
            self._orig_ast_protect = None


# ═══════════════════════════════════════════════════════════════════
# 3. 코드 GT 추출
# ═══════════════════════════════════════════════════════════════════

def extract_code_gt(zip_path: Path) -> Set[Tuple[str, str]]:
    pattern = re.compile(r'\[위반[:\s]*([A-Z]+-[A-Z]*-?\d+)\]')
    gt: Set[Tuple[str, str]] = set()
    with zipfile.ZipFile(zip_path) as zf:
        for name in zf.namelist():
            if not name.endswith('.c'):
                continue
            content = zf.read(name).decode('utf-8', errors='ignore')
            fname = Path(name).name
            for rid in set(pattern.findall(content)):
                gt.add((fname, rid))
    return gt


# ═══════════════════════════════════════════════════════════════════
# 4. 세트 L1 fixture 구축
# ═══════════════════════════════════════════════════════════════════

def build_set_fixture(set_dir: Path, tmp_root: Path) -> Optional[Dict[str, Any]]:
    zips = list(set_dir.glob("*.zip"))
    if not zips:
        print(f"  [SKIP] ZIP 없음: {set_dir}")
        return None
    zip_path = zips[0]
    set_name = set_dir.name

    tmp = tmp_root / set_name
    tmp.mkdir(parents=True, exist_ok=True)

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
            "content": content, "ast": {},
            "lines": content.splitlines(),
        })

    preprocess_result = {"files": file_entries}

    rules_dir = BACKEND_ROOT / "rules"
    print(f"  L1 실행: {set_name} ({len(c_files)}개 C 파일)...")
    t0 = time.time()
    l1_violations = run_rule_engine(
        preprocess_result=preprocess_result,
        rules_dir=rules_dir,
        job_root=tmp,
    )
    print(f"  L1: {len(l1_violations)}건 ({time.time()-t0:.1f}s)")

    gt_rules = extract_code_gt(zip_path)
    print(f"  GT: {len(gt_rules)}건 (파일+규칙 쌍)")

    # GCFS: symbol_graph 빌드 (libclang 사용 시 더 풍부한 그래프)
    symbol_graph = None
    if _SYMBOL_GRAPH_AVAILABLE:
        try:
            t_sg = time.time()
            symbol_graph = _build_symbol_graph(preprocess_result, src_root=src_dir)
            backend_used = symbol_graph.get("backend", "unknown") if symbol_graph else "N/A"
            n_defs = len(symbol_graph.get("definitions", {})) if symbol_graph else 0
            n_calls = len(symbol_graph.get("call_graph", [])) if symbol_graph else 0
            print(f"  symbol_graph: backend={backend_used}, defs={n_defs}, calls={n_calls} ({time.time()-t_sg:.1f}s)")
        except Exception as e:
            print(f"  [WARN] symbol_graph 빌드 실패: {e}")

    return {
        "set_name": set_name,
        "zip_path": zip_path,
        "preprocess_result": preprocess_result,
        "l1_violations": l1_violations,
        "gt_rules": gt_rules,
        "tmp_dir": tmp,
        "symbol_graph": symbol_graph,
    }


# ═══════════════════════════════════════════════════════════════════
# 5. 단일 L3 실행
# ═══════════════════════════════════════════════════════════════════

def run_single_l3(fixture: Dict[str, Any], config: Optional[Dict[str, bool]] = None) -> Dict[str, Any]:
    """
    L3를 한 번 실행하고 결과 반환.
    config["rag"]=False 시 violations의 rag_guideline_text를 임시 제거 후 복원.
    """
    config = config or {}
    violations = fixture["l1_violations"]

    # ── RAG off: rag_guideline_text 임시 제거 ──
    rag_backup: List[Tuple[int, Any]] = []
    if not config.get("rag", True):
        for i, v in enumerate(violations):
            if "rag_guideline_text" in v:
                rag_backup.append((i, v.pop("rag_guideline_text")))
        if rag_backup:
            print(f"  [patch] rag OFF: {len(rag_backup)}건 rag_guideline_text 임시 제거")

    rejected_keys: Set[Tuple] = set()
    t0 = time.time()
    try:
        # GCFS: config["gcfs"]=True이면 symbol_graph 전달, False이면 None
        _symbol_graph = fixture.get("symbol_graph") if config.get("gcfs", True) else None
        l3_violations = run_l3_contextualizer(
            preprocess_result=fixture["preprocess_result"],
            l1_violations=violations,
            _rejected_tracker=rejected_keys,
            symbol_graph=_symbol_graph,
        )
        post_process_violations(
            l1=violations,
            l3=l3_violations,
            l3_rejected_keys=rejected_keys,
        )
    except Exception as e:
        print(f"    [WARN] L3 실패: {e}")
        import traceback; traceback.print_exc()
        rejected_keys = set()
    finally:
        # ── RAG 복원 ──
        for i, orig in rag_backup:
            violations[i]["rag_guideline_text"] = orig

    return {
        "rejected_keys": rejected_keys,
        "duration": time.time() - t0,
    }


# ═══════════════════════════════════════════════════════════════════
# 6. Majority vote
# ═══════════════════════════════════════════════════════════════════

def majority_vote_rejected(reps_rejected: List[Set[Tuple]]) -> Set[Tuple]:
    thresh = len(reps_rejected) // 2 + 1
    counts: Dict[Tuple, int] = defaultdict(int)
    for rejected in reps_rejected:
        for key in rejected:
            counts[key] += 1
    return {k for k, c in counts.items() if c >= thresh}


# ═══════════════════════════════════════════════════════════════════
# 7. 지표 계산
# ═══════════════════════════════════════════════════════════════════

def compute_metrics(
    l1_violations: List[Dict[str, Any]],
    rejected_keys: Set[Tuple],
    gt_rules: Set[Tuple[str, str]],
) -> Dict[str, Any]:
    tp_in = fp_in = 0
    for v in l1_violations:
        fname = Path(v.get("file") or v.get("file_path") or "").name
        rid = v.get("rule_id") or ""
        if (fname, rid) in gt_rules:
            tp_in += 1
        else:
            fp_in += 1

    fn_created = fp_removed = 0
    for (rej_file, rej_rid, rej_line) in rejected_keys:
        fname = Path(rej_file).name
        if (fname, rej_rid) in gt_rules:
            fn_created += 1
        else:
            fp_removed += 1

    tp_kept = tp_in - fn_created
    fp_kept = fp_in - fp_removed

    l3_recall       = tp_kept / tp_in if tp_in > 0 else 1.0
    fp_removal_rate = fp_removed / fp_in if fp_in > 0 else 0.0

    total_kept = tp_kept + fp_kept
    precision = tp_kept / total_kept if total_kept > 0 else 0.0
    r, p = l3_recall, precision
    f1 = 2*p*r/(p+r) if (p+r) > 0 else 0.0

    return {
        "tp_in": tp_in, "fp_in": fp_in,
        "fn_created": fn_created, "fp_removed": fp_removed,
        "tp_kept": tp_kept, "fp_kept": fp_kept,
        "l3_recall":  round(l3_recall, 4),
        "fp_removal": round(fp_removal_rate, 4),
        "precision":  round(precision, 4),
        "f1":         round(f1, 4),
        "total_rejected": len(rejected_keys),
    }


# ═══════════════════════════════════════════════════════════════════
# 8. 메인
# ═══════════════════════════════════════════════════════════════════

def main():
    print("=" * 70)
    print("L3 프롬프트 엔지니어링 Ablation Study (확장판)")
    print(f"  configs: {list(ACTIVE_CONFIGS.keys())}")
    print(f"  reps/config: {N_REPS} (majority vote)")
    print("=" * 70)

    n_few_shot = _count_few_shot_rules()
    print(f"\n[사전 확인] Few-shot 예시 있는 규칙: {n_few_shot}개 / {len(_pt_mod.PROMPT_TEMPLATES)}개")
    print(f"[사전 확인] CoT 대상 HIGH_ISOLATION_RULES: {len(_l3_mod._HIGH_ISOLATION_RULES)}개")
    print(f"[사전 확인] AST_TP_PROTECT 규칙: {len(_l3_mod._AST_TP_PROTECT)}개")
    print(f"[사전 확인] GCFS: symbol_graph {'사용 가능' if _SYMBOL_GRAPH_AVAILABLE else '불가 (임포트 실패)'}")
    print()

    set_dirs = sorted(d for d in SET_BASE.iterdir()
                      if d.is_dir() and d.name.startswith("세트"))
    if not set_dirs:
        print(f"[ERROR] 세트 디렉터리 없음: {SET_BASE}")
        sys.exit(1)

    print(f"[세트] {[d.name for d in set_dirs]}")
    print()

    all_results: Dict[str, Any] = {
        "timestamp": datetime.now().isoformat(),
        "n_reps": N_REPS,
        "configs": list(ACTIVE_CONFIGS.keys()),
        "sets": {},
        "aggregate": {},
    }

    tmp_root = BACKEND_ROOT / "scripts" / "_ablation_tmp"
    tmp_root.mkdir(exist_ok=True)

    try:
        # Step 1: L1 Fixture
        print("▶ Step 1: L1 Fixture 구축")
        fixtures: List[Dict[str, Any]] = []
        for set_dir in set_dirs:
            print(f"\n  [{set_dir.name}]")
            fx = build_set_fixture(set_dir, tmp_root)
            if fx:
                fixtures.append(fx)

        if not fixtures:
            print("[ERROR] 유효한 세트 없음")
            return

        total_l1 = sum(len(fx["l1_violations"]) for fx in fixtures)
        total_gt = sum(len(fx["gt_rules"]) for fx in fixtures)
        print(f"\n▶ L1 위반 합계: {total_l1}건 | GT 쌍: {total_gt}건")

        # Step 2: Config × Rep 루프
        print("\n▶ Step 2: Config × Rep 실험")

        for config_name, config_flags in ACTIVE_CONFIGS.items():
            print(f"\n{'─'*60}")
            print(f"  [CONFIG: {config_name}]  "
                  f"few_shot={config_flags['few_shot']}  "
                  f"cot={config_flags['cot']}  "
                  f"dual_verify={config_flags.get('dual_verify', True)}  "
                  f"rag={config_flags.get('rag', True)}  "
                  f"ast_protect={config_flags.get('ast_protect', True)}  "
                  f"gcfs={config_flags.get('gcfs', True)}")
            print(f"{'─'*60}")

            reps_per_set: Dict[str, List[Set]] = {fx["set_name"]: [] for fx in fixtures}

            for rep in range(1, N_REPS + 1):
                print(f"\n  Rep {rep}/{N_REPS}")
                with _PatchContext(config_flags):
                    for fx in fixtures:
                        print(f"    {fx['set_name']}: L3 실행 중...")
                        result = run_single_l3(fx, config_flags)
                        reps_per_set[fx["set_name"]].append(result["rejected_keys"])
                        n_rej = len(result["rejected_keys"])
                        print(f"    → 제거 {n_rej}건 ({result['duration']:.1f}s)")
                        if hasattr(_l3_mod, "_l3_cache"):
                            _l3_mod._l3_cache.clear()

            # Majority vote 및 지표 집계
            print(f"\n  [Majority Vote] {N_REPS}회 → 과반({N_REPS//2+1}회 이상) 제거 확정")
            config_metrics_per_set: List[Dict] = []

            for fx in fixtures:
                voted = majority_vote_rejected(reps_per_set[fx["set_name"]])
                m = compute_metrics(fx["l1_violations"], voted, fx["gt_rules"])
                m["set_name"] = fx["set_name"]
                config_metrics_per_set.append(m)

                print(f"    {fx['set_name']}: "
                      f"Recall={m['l3_recall']*100:.1f}%  "
                      f"FP_removal={m['fp_removal']*100:.1f}%  "
                      f"FN={m['fn_created']}  "
                      f"F1={m['f1']*100:.1f}%")

                all_results["sets"].setdefault(fx["set_name"], {})[config_name] = m

            # 합산
            agg = {k: sum(m[k] for m in config_metrics_per_set)
                   for k in ("tp_in","fp_in","fn_created","fp_removed","tp_kept","fp_kept")}
            agg["l3_recall"]  = round(agg["tp_kept"] / agg["tp_in"], 4) if agg["tp_in"] > 0 else 1.0
            agg["fp_removal"] = round(agg["fp_removed"] / agg["fp_in"], 4) if agg["fp_in"] > 0 else 0.0
            tk = agg["tp_kept"] + agg["fp_kept"]
            agg["precision"] = round(agg["tp_kept"] / tk, 4) if tk > 0 else 0.0
            r, p = agg["l3_recall"], agg["precision"]
            agg["f1"] = round(2*p*r/(p+r), 4) if (p+r) > 0 else 0.0

            all_results["aggregate"][config_name] = agg
            print(f"\n  ★ {config_name} 합산: "
                  f"Recall={agg['l3_recall']*100:.1f}%  "
                  f"FP_removal={agg['fp_removal']*100:.1f}%  "
                  f"FN={agg['fn_created']}  "
                  f"F1={agg['f1']*100:.1f}%")

    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)

    # 최종 표
    print("\n" + "=" * 70)
    print("최종 결과 비교 (세트 1~4 합산, Majority Vote)")
    print("=" * 70)
    print(f"{'Config':<18} {'L3 Recall':>10} {'FP Removal':>11} {'FN':>5} {'Precision':>10} {'F1':>8}")
    print("─" * 68)
    for cfg, agg in all_results["aggregate"].items():
        print(f"{cfg:<18} "
              f"{agg['l3_recall']*100:>9.1f}%  "
              f"{agg['fp_removal']*100:>10.1f}%  "
              f"{agg['fn_created']:>4}  "
              f"{agg['precision']*100:>9.1f}%  "
              f"{agg['f1']*100:>7.1f}%")
    print("─" * 68)

    ts = datetime.now().strftime("%Y%m%d_%H%M")
    out_path = BACKEND_ROOT / "scripts" / f"ablation_result_{ts}.json"
    out_path.write_text(json.dumps(all_results, ensure_ascii=False, indent=2, default=str))
    print(f"\n결과 저장: {out_path}")

    return all_results


if __name__ == "__main__":
    main()
