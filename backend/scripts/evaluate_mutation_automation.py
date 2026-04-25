"""
Phase 6: Mutation 자동화 — GT 확대 및 통계적 신뢰도 향상
=========================================================
Phase 3의 15건 mutation을 자동 변형(파라메트릭 변이)하여
다수의 mutation을 체계적으로 생성하고 실행.

목적:
- GT 표본 크기를 늘려 95% CI 폭 축소
- 다양한 변이 패턴에 대한 탐지 일관성 확인
- Mutation Recall의 통계적 신뢰도 확보

방법론:
1. 기존 M01~M15 mutation에서 파라메트릭 변형 생성
   - 수치 변조: off-by-one, ×2, 0으로 대체 등
   - 삽입 위치 변형: 파일별로 동일 mutation 적용
   - 규칙 조합: 2개 mutation 동시 적용 (compound)

Usage:
    cd backend
    python scripts/evaluate_mutation_automation.py [--no-l3] [--max N]
"""

import sys, os, re, time, json, tempfile, shutil, math
from pathlib import Path
from collections import defaultdict
from datetime import datetime
from itertools import combinations

BACKEND_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(BACKEND_ROOT))

USE_L3 = "--no-l3" not in sys.argv

# --max 인자 처리
MAX_MUTATIONS = 100
for i, arg in enumerate(sys.argv):
    if arg == "--max" and i + 1 < len(sys.argv):
        MAX_MUTATIONS = int(sys.argv[i + 1])

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


# ═══════════════════════════════════════════════════════════════════
# 파라메트릭 Mutation 생성기
# ═══════════════════════════════════════════════════════════════════

def generate_parametric_mutations():
    """기존 mutation 틀에서 파라메트릭 변형을 생성."""
    mutations = []
    mid = 0

    # === 카테고리 1: LEA-003 라운드 수 변형 ===
    round_targets = [
        ("(mk_len >> 1) + 16", "라운드 수 연산"),
        ("key->round > 24", "라운드 조건 24"),
        ("key->round > 28", "라운드 조건 28"),
    ]
    for orig, desc_prefix in round_targets:
        for delta, delta_desc in [(-1, "-1"), (+1, "+1"), (-2, "-2")]:
            mid += 1
            if "+" in orig and "+16" in orig:
                new_val = 16 + delta
                new_str = orig.replace("+16", f"+ {new_val}")
            elif "> 24" in orig:
                new_val = 24 + delta
                new_str = orig.replace("> 24", f"> {new_val}")
            elif "> 28" in orig:
                new_val = 28 + delta
                new_str = orig.replace("> 28", f"> {new_val}")
            else:
                continue
            mutations.append({
                "id": f"A{mid:03d}", "target_rule": "LEA-003",
                "file": "src/lea_core.c",
                "description": f"{desc_prefix} {delta_desc}",
                "search": orig,
                "replace": f"{new_str} /* MUTATION: A{mid:03d} */",
                "first_only": True,
            })

    # === 카테고리 2: LEA-010 델타 상수 변형 ===
    delta_constants = [
        "0xc3efe9db", "0x44626b02", "0x79e27c8a", "0x78df30ec",
        "0x715ea49e", "0xc785da0a", "0xe04ef22a", "0xe7a12214",
    ]
    for dc in delta_constants:
        # LSB flip
        mid += 1
        flipped = hex(int(dc, 16) ^ 1)
        mutations.append({
            "id": f"A{mid:03d}", "target_rule": "LEA-010",
            "file": "src/lea_core.c",
            "description": f"델타 상수 {dc} LSB flip",
            "search": dc,
            "replace": f"{flipped} /* MUTATION: delta flip */",
            "first_only": True,
        })
        # MSB flip
        mid += 1
        msb_flipped = hex(int(dc, 16) ^ 0x80000000)
        mutations.append({
            "id": f"A{mid:03d}", "target_rule": "LEA-010",
            "file": "src/lea_core.c",
            "description": f"델타 상수 {dc} MSB flip",
            "search": dc,
            "replace": f"{msb_flipped} /* MUTATION: delta MSB flip */",
            "first_only": True,
        })

    # === 카테고리 3: LEA-034 비트 회전량 변형 ===
    rotation_patterns = [
        ("ROR((X2 ^ key->rk[  4]) + (X3 ^ key->rk[  5]), 3)", 3, "ROR 3"),
        ("ROR((X1 ^ key->rk[  2]) + (X2 ^ key->rk[  3]), 5)", 5, "ROR 5"),
    ]
    for orig_pat, orig_rot, desc in rotation_patterns:
        for new_rot in [orig_rot - 1, orig_rot + 1, orig_rot * 2]:
            if new_rot <= 0 or new_rot > 31:
                continue
            mid += 1
            new_pat = orig_pat.replace(f", {orig_rot})", f", {new_rot}) /* MUTATION: rot {orig_rot}→{new_rot} */")
            mutations.append({
                "id": f"A{mid:03d}", "target_rule": "LEA-034",
                "file": "src/lea_core.c",
                "description": f"{desc} → {new_rot}",
                "search": orig_pat,
                "replace": new_pat,
                "first_only": True,
            })

    # === 카테고리 4: LEA-040 키 스케줄 ROL 변형 ===
    key_sched_rols = [
        ("ROL(loadU32(_mk[0]) + delta[0][ 0], 1)", 1),
    ]
    for orig_pat, orig_rot in key_sched_rols:
        for new_rot in [0, 2, 3, 8]:
            mid += 1
            new_pat = orig_pat.replace(f", {orig_rot})", f", {new_rot}) /* MUTATION: key ROL {orig_rot}→{new_rot} */")
            mutations.append({
                "id": f"A{mid:03d}", "target_rule": "LEA-040",
                "file": "src/lea_core.c",
                "description": f"키 스케줄 ROL {orig_rot} → {new_rot}",
                "search": orig_pat,
                "replace": new_pat,
                "first_only": True,
            })

    # === 카테고리 5: COM 규칙 다양한 위반 삽입 ===
    com_insertions = [
        # COM-003: 다양한 하드코딩 키 패턴
        ("A_COM003_1", "COM-003", "AES 키 형태 하드코딩",
         'static const unsigned char AES_KEY[32] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f}; /* MUTATION */'),
        ("A_COM003_2", "COM-003", "#define 매크로 키",
         '#define SECRET_KEY "0123456789abcdef" /* MUTATION: macro key */'),
        # COM-002: 다양한 비표준 RNG
        ("A_COM002_1", "COM-002", "random() 사용",
         'void gen_key(unsigned char *k, int n) { for(int i=0;i<n;i++) k[i]=(unsigned char)(random()&0xff); } /* MUTATION */'),
        # COM-004: 다양한 비표준 시드
        ("A_COM004_1", "COM-004", "시드 없는 rand()",
         'void init(void) { int x = rand(); (void)x; } /* MUTATION: unseeded rand */'),
        # ECB-002: ECB 변형
        ("A_ECB002_1", "ECB-002", "ECB 루프 변형",
         'void ecb_process(const unsigned char *in, unsigned char *out, int blocks) { for(int b=0; b<blocks; b++) { /* ECB MUTATION */ } }'),
    ]
    target_files = ["lea_vs.c", "main.c", "benchmark.c"]
    for ins_id, rule, desc, code in com_insertions:
        for tfile in target_files[:2]:  # 각 삽입은 2개 파일에만
            mid += 1
            mutations.append({
                "id": f"A{mid:03d}", "target_rule": rule,
                "file": tfile,
                "description": f"{desc} in {tfile}",
                "insert_after_pattern": r"#include",
                "insert_text": f"\n{code}\n",
                "insert_once": True,
            })

    # === 카테고리 6: 운영 모드 위반 삽입 ===
    mode_insertions = [
        ("CBC-001", "CBC no IV init",
         'void cbc_no_iv(unsigned char *ct, const unsigned char *pt, int len) { /* MUTATION: CBC-001 no IV */ memcpy(ct, pt, len); }'),
        ("CTR-002", "CTR counter wrap",
         'void ctr_unsafe(unsigned int *c) { (*c)++; /* MUTATION: CTR-002 no wrap check */ }'),
        ("GCM-001", "GCM no auth",
         'int gcm_noauth(const unsigned char *ct, int len) { /* MUTATION: GCM-001 */ return 0; }'),
    ]
    for rule, desc, code in mode_insertions:
        for tfile in ["lea_vs.c", "main.c"]:
            mid += 1
            mutations.append({
                "id": f"A{mid:03d}", "target_rule": rule,
                "file": tfile,
                "description": f"{desc} in {tfile}",
                "insert_after_pattern": r"#include",
                "insert_text": f"\n{code}\n",
                "insert_once": True,
            })

    return mutations[:MAX_MUTATIONS]


def apply_mutation(src_dir, mutation):
    """단일 mutation 적용."""
    target_file = src_dir / mutation["file"]
    if not target_file.exists():
        alt = src_dir / mutation["file"].replace("src/", "")
        if alt.exists():
            target_file = alt
        else:
            return False

    try:
        content = target_file.read_text(encoding="utf-8", errors="ignore")
    except:
        return False

    if "search" in mutation and "replace" in mutation:
        if mutation["search"] not in content:
            return False
        if mutation.get("first_only"):
            content = content.replace(mutation["search"], mutation["replace"], 1)
        else:
            content = content.replace(mutation["search"], mutation["replace"])
        target_file.write_text(content, encoding="utf-8")
        return True

    if "insert_after_pattern" in mutation:
        pat = re.compile(mutation["insert_after_pattern"])
        lines = content.split("\n")
        inserted = False
        for i, line in enumerate(lines):
            if pat.search(line):
                lines.insert(i + 1, mutation["insert_text"])
                inserted = True
                if mutation.get("insert_once"):
                    break
        if not inserted:
            return False
        target_file.write_text("\n".join(lines), encoding="utf-8")
        return True

    if mutation.get("action") == "comment_out_first_match":
        pat = re.compile(mutation["search_pattern"])
        lines = content.split("\n")
        for i, line in enumerate(lines):
            if pat.search(line):
                lines[i] = "// " + line + "  /* MUTATION */"
                target_file.write_text("\n".join(lines), encoding="utf-8")
                return True
        return False

    return False


def run_pipeline_on_dir(src_dir):
    """L1(+L3) 파이프라인 실행."""
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
    rules_dir = BACKEND_ROOT / "rules"
    l1 = run_rule_engine(preprocess_result=preprocess_result,
                         rules_dir=rules_dir, job_root=src_dir.parent)

    if USE_L3 and L3_AVAILABLE and l1:
        l3_rejected = set()
        try:
            l3 = run_l3_contextualizer(preprocess_result=preprocess_result,
                                       l1_violations=l1, _rejected_tracker=l3_rejected)
            return post_process_violations(l1=l1, l3=l3, l3_rejected_keys=l3_rejected)
        except:
            return l1
    return l1


def main():
    print("=" * 65)
    print("Phase 6: Mutation 자동화 — GT 확대")
    print(f"L3: {'활성화' if USE_L3 else '비활성화'}")
    print(f"최대 mutation: {MAX_MUTATIONS}건")
    print("=" * 65)

    if not KISA_LEA_SRC.exists():
        print(f"[ERROR] 소스 경로 없음: {KISA_LEA_SRC}")
        return

    mutations = generate_parametric_mutations()
    print(f"\n생성된 mutation: {len(mutations)}건")

    # 규칙별 분포
    rule_dist = defaultdict(int)
    for m in mutations:
        rule_dist[m["target_rule"]] += 1
    print(f"\n[규칙별 분포]")
    for rule, cnt in sorted(rule_dist.items()):
        print(f"  {rule}: {cnt}건")

    results = []
    tp = fn = skip = 0
    t_start = time.time()

    for i, mut in enumerate(mutations):
        mid = mut["id"]
        target = mut["target_rule"]
        desc = mut["description"]
        print(f"\n[{i+1}/{len(mutations)}] {mid} ({target}): {desc}")

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_src = Path(tmpdir) / "src"
            shutil.copytree(KISA_LEA_SRC, tmp_src)

            success = apply_mutation(tmp_src, mut)
            if not success:
                skip += 1
                results.append({
                    "id": mid, "target_rule": target,
                    "description": desc, "status": "SKIP",
                    "detected": False,
                })
                print(f"    [SKIP]")
                continue

            t0 = time.time()
            violations = run_pipeline_on_dir(tmp_src)
            elapsed = time.time() - t0

            detected = any(v.get("rule_id") == target for v in violations)
            status = "TP" if detected else "FN"
            if detected:
                tp += 1
            else:
                fn += 1

            matched = sum(1 for v in violations if v.get("rule_id") == target)
            print(f"    → {status}: {matched}건 탐지, {elapsed:.0f}s")

            results.append({
                "id": mid, "target_rule": target,
                "description": desc, "status": status,
                "detected": detected,
                "matched_count": matched,
                "total_violations": len(violations),
                "elapsed_s": round(elapsed, 1),
            })

    total_elapsed = time.time() - t_start
    total_applied = tp + fn
    recall = tp / total_applied if total_applied > 0 else 0.0

    # Wilson CI
    z = 1.96
    if total_applied > 0:
        p = recall
        n = total_applied
        denom = 1 + z**2 / n
        center = (p + z**2 / (2*n)) / denom
        spread = z * math.sqrt(p*(1-p)/n + z**2/(4*n**2)) / denom
        ci_low = max(0, center - spread)
        ci_high = min(1, center + spread)
    else:
        ci_low = ci_high = 0

    print(f"\n{'═' * 65}")
    print(f"  Phase 6 결과: Mutation 자동화 Recall")
    print(f"{'═' * 65}")
    print(f"  생성 mutation: {len(mutations)}건")
    print(f"  적용 성공: {total_applied}건 (skip: {skip}건)")
    print(f"  TP: {tp}건 | FN: {fn}건")
    print(f"  **Mutation Recall: {recall:.1%}**")
    print(f"  **95% CI (Wilson): [{ci_low:.1%}, {ci_high:.1%}]**")
    print(f"  소요 시간: {total_elapsed:.0f}초 ({total_elapsed/60:.0f}분)")

    # FN 상세
    if fn > 0:
        print(f"\n  [FN 상세]")
        for r in results:
            if r["status"] == "FN":
                print(f"    {r['id']} ({r['target_rule']}): {r['description']}")

    # 규칙별 Recall
    print(f"\n  [규칙별 Recall]")
    rule_tp = defaultdict(int)
    rule_total = defaultdict(int)
    for r in results:
        if r["status"] in ("TP", "FN"):
            rule_total[r["target_rule"]] += 1
            if r["status"] == "TP":
                rule_tp[r["target_rule"]] += 1
    for rule in sorted(rule_total.keys()):
        rtp = rule_tp[rule]
        rt = rule_total[rule]
        rr = rtp / rt if rt > 0 else 0
        print(f"    {rule}: {rr:.0%} ({rtp}/{rt})")

    print(f"\n{'═' * 65}")

    # Phase 3 + Phase 6 합산 Recall
    phase3_path = BACKEND_ROOT / "scripts" / "blind_mutation_results.json"
    combined_tp = tp
    combined_total = total_applied
    if phase3_path.exists():
        p3 = json.loads(phase3_path.read_text(encoding="utf-8"))
        combined_tp += p3.get("TP", 0)
        combined_total += p3.get("applied", 0)
    combined_recall = combined_tp / combined_total if combined_total > 0 else 0
    p_c = combined_recall
    n_c = combined_total
    if n_c > 0:
        denom_c = 1 + z**2 / n_c
        center_c = (p_c + z**2 / (2*n_c)) / denom_c
        spread_c = z * math.sqrt(p_c*(1-p_c)/n_c + z**2/(4*n_c**2)) / denom_c
        ci_c_low = max(0, center_c - spread_c)
        ci_c_high = min(1, center_c + spread_c)
    else:
        ci_c_low = ci_c_high = 0

    print(f"\n  [Phase 3 + Phase 6 합산 Mutation Recall]")
    print(f"  합산: {combined_tp}/{combined_total} = {combined_recall:.1%}")
    print(f"  합산 95% CI: [{ci_c_low:.1%}, {ci_c_high:.1%}]")
    print(f"{'═' * 65}")

    # JSON 저장
    output = {
        "timestamp": datetime.now().isoformat(),
        "phase": "Phase 6",
        "description": "Mutation 자동화 — 파라메트릭 변형 기반 GT 확대",
        "use_l3": USE_L3,
        "total_generated": len(mutations),
        "applied": total_applied,
        "skipped": skip,
        "TP": tp, "FN": fn,
        "mutation_recall": recall,
        "ci_95_low": ci_low,
        "ci_95_high": ci_high,
        "elapsed_s": round(total_elapsed, 1),
        "combined_with_phase3": {
            "total": combined_total,
            "tp": combined_tp,
            "recall": combined_recall,
            "ci_95_low": ci_c_low,
            "ci_95_high": ci_c_high,
        },
        "by_rule": {rule: {"tp": rule_tp[rule], "total": rule_total[rule]}
                    for rule in rule_total},
        "results": results,
    }
    out_path = BACKEND_ROOT / "scripts" / "mutation_automation_results.json"
    out_path.write_text(json.dumps(output, ensure_ascii=False, indent=2, default=str),
                        encoding="utf-8")
    print(f"\n결과 저장: {out_path}")
    return output


if __name__ == "__main__":
    main()
