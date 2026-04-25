"""
외부 코드 데이터셋 블라인드 FP 테스트
======================================
외부 C 소스코드(정상 코드)에 대해 FP를 측정.
자기참조 비판 해소 + 다중 구현체 범용성 검증.

Usage:
    cd backend
    python scripts/evaluate_external_blind.py [--no-l3]
"""

import sys, os, time, json, zipfile, tempfile, shutil
from pathlib import Path
from collections import Counter
from datetime import datetime

BACKEND_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(BACKEND_ROOT))

USE_L3 = "--no-l3" not in sys.argv

from app.services.rule_engine_service import run_rule_engine

try:
    from app.services.llm_service import run_l3_contextualizer
    from app.services.report_service import post_process_violations
    L3_AVAILABLE = True
except Exception:
    L3_AVAILABLE = False

if not L3_AVAILABLE:
    USE_L3 = False

# ── 외부 데이터셋 정의 ──
EXTERNAL_DIR = BACKEND_ROOT / "testdata" / "external"

DATASETS = [
    {
        "name": "CryptoModule (LEA+ARIA+AES)",
        "zip_path": EXTERNAL_DIR / "CryptoModule.zip",
        "description": "Hacker-Code-J/CryptoModule — LEA+ARIA+AES, ECB/CBC/CTR/GCM, Apache-2.0",
    },
    {
        "name": "HackerCodeJ LEA (CBC/CTR)",
        "zip_path": EXTERNAL_DIR / "HackerCodeJ_LEA.zip",
        "description": "Hacker-Code-J/LEA — LEA128 CBC/CTR MOVS, MIT",
    },
]


def count_loc(src_dir: Path) -> int:
    total = 0
    for ext in ("*.c", "*.h"):
        for f in src_dir.rglob(ext):
            try:
                total += len(f.read_text(encoding="utf-8", errors="ignore").splitlines())
            except:
                pass
    return total


def run_single_blind(name: str, src_dir: Path, description: str) -> dict:
    """단일 데이터셋 블라인드 테스트."""
    print(f"\n{'═' * 65}")
    print(f"  블라인드 테스트: {name}")
    print(f"  경로: {src_dir}")
    print(f"  설명: {description}")
    print(f"{'═' * 65}")

    # 소스 파일 수집
    c_files = sorted(src_dir.rglob("*.c"))
    h_files = sorted(src_dir.rglob("*.h"))
    total_loc = count_loc(src_dir)
    print(f"  C 파일: {len(c_files)}개, H 파일: {len(h_files)}개, 총 LOC: {total_loc}")

    if not c_files:
        print("  [SKIP] C 파일 없음")
        return {"name": name, "error": "no C files"}

    # preprocess_result 구성
    file_entries = []
    for f in c_files:
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
        except:
            content = ""
        # 상대 경로 유지
        rel = f.relative_to(src_dir)
        file_entries.append({
            "path": str(f),
            "display": str(rel),
            "content": content,
            "ast": {},
        })
    preprocess_result = {"files": file_entries}

    # L1 규칙 엔진
    print(f"  [L1] 규칙 엔진 실행 중...")
    t0 = time.time()
    rules_dir = BACKEND_ROOT / "rules"

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        src_dest = tmp / "src"
        shutil.copytree(src_dir, src_dest)
        l1_violations = run_rule_engine(
            preprocess_result=preprocess_result,
            rules_dir=rules_dir,
            job_root=tmp,
        )
    t_l1 = time.time() - t0
    print(f"  L1 완료: {len(l1_violations)}건 탐지, {t_l1:.1f}s")

    # L3 필터링
    l3_rejected_keys = set()
    if USE_L3 and L3_AVAILABLE and l1_violations:
        print(f"  [L3] Gemini 재판정 중...")
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

    # FP 분석
    fp_by_rule = Counter()
    fp_by_file = Counter()
    fp_by_pattern = Counter()
    fp_details = []

    for v in final_violations:
        rid = v.get("rule_id", "?")
        fname = Path(v.get("file", "")).name
        ptype = v.get("pattern_type", "?")
        fp_by_rule[rid] += 1
        fp_by_file[fname] += 1
        fp_by_pattern[ptype] += 1
        fp_details.append({
            "rule_id": rid, "file": fname,
            "line": v.get("line", 0),
            "pattern_type": ptype,
            "message": v.get("message", "")[:100],
        })

    total_fp = len(final_violations)
    fp_per_kloc = total_fp / (total_loc / 1000) if total_loc > 0 else 0.0

    print(f"\n  총 FP: {total_fp}건, LOC: {total_loc}, FP/KLOC: {fp_per_kloc:.2f}")
    print(f"  [규칙별 TOP-10]")
    for rid, cnt in fp_by_rule.most_common(10):
        print(f"    {rid}: {cnt}건")
    print(f"  [패턴타입별]")
    for pt, cnt in fp_by_pattern.most_common():
        print(f"    {pt}: {cnt}건")

    return {
        "name": name,
        "description": description,
        "loc": total_loc,
        "c_files": len(c_files),
        "h_files": len(h_files),
        "l1_fp_count": len(l1_violations),
        "l3_removed": len(l3_rejected_keys),
        "final_fp_count": total_fp,
        "fp_per_kloc": round(fp_per_kloc, 2),
        "fp_by_rule": dict(fp_by_rule.most_common()),
        "fp_by_file": dict(fp_by_file.most_common()),
        "fp_by_pattern": dict(fp_by_pattern),
        "fp_details": fp_details,
        "timing_s": round(t_l1 + t_l3, 1),
    }


def main():
    print("=" * 65)
    print("  외부 코드 데이터셋 블라인드 FP 테스트")
    print(f"  L3 (Gemini): {'활성화' if USE_L3 else '비활성화'}")
    print("=" * 65)

    results = []
    for ds in DATASETS:
        zip_path = ds["zip_path"]
        if not zip_path.exists():
            print(f"\n[SKIP] {ds['name']} — ZIP 없음: {zip_path}")
            continue

        # ZIP 해제
        with tempfile.TemporaryDirectory() as tmpdir:
            extract_dir = Path(tmpdir) / "src"
            with zipfile.ZipFile(zip_path) as zf:
                zf.extractall(extract_dir)

            result = run_single_blind(ds["name"], extract_dir, ds["description"])
            results.append(result)

    # 종합 결과
    print(f"\n\n{'═' * 65}")
    print("  종합 결과")
    print(f"{'═' * 65}")
    print(f"  {'데이터셋':<35} {'LOC':>6} {'FP':>5} {'FP/KLOC':>8}")
    print(f"  {'─' * 55}")

    for r in results:
        if "error" in r:
            continue
        print(f"  {r['name']:<35} {r['loc']:>6} {r['final_fp_count']:>5} {r['fp_per_kloc']:>8.2f}")

    # 기존 KISA LEA 결과도 표시
    kisa_json = BACKEND_ROOT / "scripts" / "blind_test_kisa_lea_results.json"
    if kisa_json.exists():
        kisa = json.loads(kisa_json.read_text(encoding="utf-8"))
        print(f"  {'KISA LEA v1.3 (기존)':<35} {kisa.get('loc', 0):>6} "
              f"{kisa.get('final_fp_count', 0):>5} {kisa.get('fp_per_kloc', 0):>8.2f}")

    print(f"{'═' * 65}")

    # JSON 저장
    output = {
        "timestamp": datetime.now().isoformat(),
        "use_l3": USE_L3,
        "datasets": results,
    }
    out_path = BACKEND_ROOT / "scripts" / "external_blind_results.json"
    out_path.write_text(json.dumps(output, ensure_ascii=False, indent=2, default=str),
                        encoding="utf-8")
    print(f"\n결과 저장: {out_path}")


if __name__ == "__main__":
    main()
