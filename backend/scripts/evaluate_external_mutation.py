"""
외부 코드 Mutation 기반 블라인드 Recall 테스트
================================================
제3자 코드(HackerCodeJ LEA)에 알려진 위반을 삽입한 뒤,
시스템이 삽입된 위반을 탐지하는지 측정.

자기참조 비판 해소: GT도 코드도 팀이 만든 것이 아닌 외부 코드 사용.

Usage:
    cd backend
    python scripts/evaluate_external_mutation.py [--no-l3]
"""

import sys, os, re, time, json, zipfile, tempfile, shutil
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

EXTERNAL_ZIP = BACKEND_ROOT / "testdata" / "external" / "HackerCodeJ_LEA.zip"

# ═══════════════════════════════════════════════════════════════════
# Mutation 정의 — HackerCodeJ LEA 코드 구조에 맞춤
# ═══════════════════════════════════════════════════════════════════

MUTATIONS = [
    # --- LEA 알고리즘 규칙 ---
    {
        "id": "EM01", "target_rule": "LEA-003",
        "file": "src/lea_core.c",
        "description": "LEA-128 라운드 수 변조 (Nr=24 → Nr=23)",
        "search": "const int Nr = 24;",
        "replace": "const int Nr = 23; /* MUTATION: wrong round count */",
        "first_only": True,
    },
    {
        "id": "EM02", "target_rule": "LEA-003",
        "file": "src/lea_core.c",
        "description": "LEA-192 라운드 수 변조 (Nr=28 → Nr=27)",
        "search": "const int Nr = 28;",
        "replace": "const int Nr = 27; /* MUTATION: wrong round count */",
        "first_only": True,
    },
    {
        "id": "EM03", "target_rule": "LEA-010",
        "file": "src/lea_core.c",
        "description": "델타 상수 LSB 변조 (0xc3efe9dbU → 0xc3efe9daU)",
        "search": "0xc3efe9dbU",
        "replace": "0xc3efe9daU /* MUTATION: delta LSB flip */",
        "first_only": True,
    },
    {
        "id": "EM04", "target_rule": "LEA-040",
        "file": "src/lea_core.c",
        "description": "키 스케줄 ROL 회전량 변조 (ROTL32(..., 1) → ROTL32(..., 2))",
        "search": "T[0] = ROTL32(T[0] + ROTL32(delta[i % 4], i + 0),  1);",
        "replace": "T[0] = ROTL32(T[0] + ROTL32(delta[i % 4], i + 0),  2); /* MUTATION: wrong rotation */",
        "first_only": True,
    },
    {
        "id": "EM05", "target_rule": "LEA-034",
        "file": "src/lea_core.c",
        "description": "암호화 ROTR32 회전량 변조 (5 → 4)",
        "search": "ROTR32((t[1] ^ roundKeys[j + 2])\n                    + (t[2] ^ roundKeys[j + 3]), 5)",
        "replace": "ROTR32((t[1] ^ roundKeys[j + 2])\n                    + (t[2] ^ roundKeys[j + 3]), 4) /* MUTATION: wrong rotation */",
        "first_only": True,
    },
    # --- 공통 보안 규칙 ---
    {
        "id": "EM06", "target_rule": "COM-001",
        "file": "src/lea_core.c",
        "description": "라운드키 배열 제로화 누락 (함수 끝에 memset 없음 명시)",
        "insert_after_pattern": r"void leaEncrypt\(",
        "insert_text": '/* MUTATION: roundKeys on stack but never zeroed after use — COM-001 violation */\n',
        "insert_once": True,
    },
    {
        "id": "EM07", "target_rule": "COM-003",
        "file": "src/lea_core.c",
        "description": "하드코딩 키 삽입",
        "insert_after_pattern": r"#include",
        "insert_text": '\nstatic const unsigned char HARDCODED_KEY[16] = {0x0f,0x1e,0x2d,0x3c,0x4b,0x5a,0x69,0x78,0x87,0x96,0xa5,0xb4,0xc3,0xd2,0xe1,0xf0}; /* MUTATION: hardcoded key */\n',
        "insert_once": True,
    },
    {
        "id": "EM08", "target_rule": "COM-004",
        "file": "src/lea_utils.c",
        "description": "비표준 난수 함수 사용 (rand 호출)",
        "insert_after_pattern": r"#include",
        "insert_text": '\nvoid generate_iv(unsigned char *iv, int len) { for(int i=0;i<len;i++) iv[i]=(unsigned char)(rand()%256); } /* MUTATION: weak RNG */\n',
        "insert_once": True,
    },
    {
        "id": "EM09", "target_rule": "ECB-002",
        "file": "src/lea_modes.c",
        "description": "ECB 모드 직접 사용 패턴",
        "insert_after_pattern": r"#include",
        "insert_text": '\nvoid ecb_encrypt_blocks(void *ctx, const unsigned char *in, unsigned char *out, int nblocks) {\n    for(int i=0;i<nblocks;i++) { /* MUTATION: ECB mode direct use */ }\n}\n',
        "insert_once": True,
    },
    {
        "id": "EM10", "target_rule": "CBC-001",
        "file": "src/lea_modes.c",
        "description": "CBC IV XOR 누락 패턴 삽입",
        "insert_after_pattern": r"#include",
        "insert_text": '\nvoid cbc_encrypt_no_xor(void *ctx, const unsigned char *pt, unsigned char *ct, int len) {\n    /* MUTATION: CBC without IV XOR - CBC-001 violation */\n    unsigned char block[16];\n    for(int i=0; i<len/16; i++) {\n        memcpy(block, pt+i*16, 16);\n        /* missing: XOR with IV or previous ciphertext */\n    }\n}\n',
        "insert_once": True,
    },
    {
        "id": "EM11", "target_rule": "CTR-002",
        "file": "src/lea_modes.c",
        "description": "CTR 카운터 오버플로우 미검사",
        "insert_after_pattern": r"#include",
        "insert_text": '\nvoid ctr_encrypt_no_overflow_check(unsigned int *counter, int nblocks) {\n    /* MUTATION: CTR counter overflow not checked - CTR-002 */\n    for(int i=0; i<nblocks; i++) { (*counter)++; }\n}\n',
        "insert_once": True,
    },
    {
        "id": "EM12", "target_rule": "COM-004",
        "file": "src/main.c",
        "description": "srand(time(NULL)) 비표준 시드",
        "insert_after_pattern": r"#include",
        "insert_text": '\n#include <time.h>\nvoid init_random(void) { srand(time(NULL)); } /* MUTATION: non-CSPRNG seed */\n',
        "insert_once": True,
    },
]


def apply_mutation(src_dir: Path, mutation: dict) -> bool:
    """단일 mutation을 소스 디렉터리에 적용. 성공 시 True."""
    target_file = src_dir / mutation["file"]
    if not target_file.exists():
        # rglob fallback
        candidates = list(src_dir.rglob(Path(mutation["file"]).name))
        if candidates:
            target_file = candidates[0]
        else:
            print(f"    [SKIP] 파일 없음: {mutation['file']}")
            return False

    try:
        content = target_file.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return False

    mid = mutation["id"]

    # 단순 문자열 치환
    if "search" in mutation and "replace" in mutation:
        if mutation["search"] not in content:
            print(f"    [SKIP] {mid}: 패턴 '{mutation['search'][:50]}' 미발견")
            return False
        if mutation.get("first_only"):
            content = content.replace(mutation["search"], mutation["replace"], 1)
        else:
            content = content.replace(mutation["search"], mutation["replace"])
        target_file.write_text(content, encoding="utf-8")
        return True

    # 정규식 기반 첫 매칭 주석처리
    if mutation.get("action") == "comment_out_first_match":
        pat = re.compile(mutation["search_pattern"])
        lines = content.split("\n")
        found = False
        for i, line in enumerate(lines):
            if pat.search(line):
                lines[i] = "// " + line + "  /* MUTATION: removed */"
                found = True
                break
        if not found:
            print(f"    [SKIP] {mid}: regex 미매칭")
            return False
        target_file.write_text("\n".join(lines), encoding="utf-8")
        return True

    # 코드 삽입
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
            print(f"    [SKIP] {mid}: 삽입 위치 미발견")
            return False
        target_file.write_text("\n".join(lines), encoding="utf-8")
        return True

    print(f"    [SKIP] {mid}: 알 수 없는 mutation 타입")
    return False


def run_pipeline_on_dir(src_dir: Path) -> list:
    """주어진 소스 디렉터리에 L1(+L3) 파이프라인 실행."""
    c_files = sorted(src_dir.rglob("*.c"))
    file_entries = []
    for f in c_files:
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            content = ""
        rel = f.relative_to(src_dir)
        file_entries.append({
            "path": str(f), "display": str(rel),
            "content": content, "ast": {},
        })
    preprocess_result = {"files": file_entries}

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

    if USE_L3 and L3_AVAILABLE and l1_violations:
        l3_rejected = set()
        try:
            l3_violations = run_l3_contextualizer(
                preprocess_result=preprocess_result,
                l1_violations=l1_violations,
                _rejected_tracker=l3_rejected,
            )
            final = post_process_violations(
                l1=l1_violations, l3=l3_violations,
                l3_rejected_keys=l3_rejected,
            )
        except Exception:
            final = l1_violations
    else:
        final = l1_violations

    return final


def check_detection(violations: list, target_rule: str) -> bool:
    """위반 목록에서 target_rule이 탐지되었는지 확인."""
    for v in violations:
        if v.get("rule_id") == target_rule:
            return True
    return False


def main():
    print("=" * 65)
    print("  외부 코드 Mutation 기반 블라인드 Recall 테스트")
    print(f"  데이터셋: HackerCodeJ LEA (제3자 코드)")
    print(f"  L3: {'활성화' if USE_L3 else '비활성화'}")
    print(f"  Mutation 수: {len(MUTATIONS)}건")
    print("=" * 65)

    if not EXTERNAL_ZIP.exists():
        print(f"[ERROR] ZIP 없음: {EXTERNAL_ZIP}")
        return

    results = []
    tp = 0
    fn = 0
    skip = 0
    t_start = time.time()

    for mut in MUTATIONS:
        mid = mut["id"]
        target = mut["target_rule"]
        desc = mut["description"]
        print(f"\n[{mid}] {target}: {desc}")

        # ZIP에서 클린 복사본 추출
        with tempfile.TemporaryDirectory() as tmpdir:
            extract_dir = Path(tmpdir) / "src"
            with zipfile.ZipFile(EXTERNAL_ZIP) as zf:
                zf.extractall(extract_dir)

            # mutation 적용
            success = apply_mutation(extract_dir, mut)
            if not success:
                skip += 1
                results.append({
                    "id": mid, "target_rule": target,
                    "description": desc, "status": "SKIP",
                    "detected": False,
                })
                continue

            # 파이프라인 실행
            print(f"    파이프라인 실행 중...")
            t0 = time.time()
            violations = run_pipeline_on_dir(extract_dir)
            elapsed = time.time() - t0

            detected = check_detection(violations, target)
            status = "TP" if detected else "FN"
            if detected:
                tp += 1
            else:
                fn += 1

            matched = [v for v in violations if v.get("rule_id") == target]
            print(f"    -> {status} ({target}): {len(matched)}건 탐지, "
                  f"총 {len(violations)}건, {elapsed:.1f}s")

            results.append({
                "id": mid, "target_rule": target,
                "description": desc, "status": status,
                "detected": detected,
                "matched_count": len(matched),
                "total_violations": len(violations),
                "elapsed_s": round(elapsed, 1),
            })

    total_elapsed = time.time() - t_start
    total_applied = tp + fn
    recall = tp / total_applied if total_applied > 0 else 0.0

    print(f"\n{'=' * 65}")
    print(f"  외부 Mutation Recall 결과")
    print(f"{'=' * 65}")
    print(f"  데이터셋: HackerCodeJ LEA (제3자 코드)")
    print(f"  총 mutation: {len(MUTATIONS)}건")
    print(f"  적용 성공: {total_applied}건 (skip: {skip}건)")
    print(f"  TP (탐지 성공): {tp}건")
    print(f"  FN (미탐지): {fn}건")
    print(f"  **Mutation Recall: {recall:.1%}**")
    print(f"  소요 시간: {total_elapsed:.0f}초")
    print(f"{'=' * 65}")

    if fn > 0:
        print(f"\n  [미탐지 mutation 상세]")
        for r in results:
            if r["status"] == "FN":
                print(f"    {r['id']} ({r['target_rule']}): {r['description']}")

    # 규칙 범주별 집계
    rule_cats = Counter()
    rule_cats_tp = Counter()
    for r in results:
        if r["status"] != "SKIP":
            cat = r["target_rule"].split("-")[0]
            rule_cats[cat] += 1
            if r["detected"]:
                rule_cats_tp[cat] += 1

    print(f"\n  [범주별 Recall]")
    for cat in sorted(rule_cats):
        print(f"    {cat}: {rule_cats_tp[cat]}/{rule_cats[cat]}")

    # JSON 저장
    output = {
        "timestamp": datetime.now().isoformat(),
        "description": "외부 코드(HackerCodeJ LEA) Mutation 기반 블라인드 Recall 테스트",
        "dataset": "HackerCodeJ LEA (github.com/Hacker-Code-J/LEA, MIT)",
        "use_l3": USE_L3,
        "total_mutations": len(MUTATIONS),
        "applied": total_applied,
        "skipped": skip,
        "TP": tp, "FN": fn,
        "mutation_recall": recall,
        "elapsed_s": round(total_elapsed, 1),
        "results": results,
    }
    out_path = BACKEND_ROOT / "scripts" / "external_mutation_results.json"
    out_path.write_text(json.dumps(output, ensure_ascii=False, indent=2, default=str),
                        encoding="utf-8")
    print(f"\n결과 저장: {out_path}")

    return output


if __name__ == "__main__":
    main()
