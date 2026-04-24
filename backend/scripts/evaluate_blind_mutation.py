"""
Phase 3: KISA LEA 레퍼런스 Mutation 기반 블라인드 Recall 테스트
================================================================
정상 LEA 코드에 알려진 위반(mutation)을 삽입한 뒤,
시스템이 삽입된 위반을 탐지하는지 측정 (블라인드 Recall).

각 mutation은 독립적으로 적용 → 개별 탐지 여부 기록.

Usage:
    cd backend
    python scripts/evaluate_blind_mutation.py [--no-l2]
"""

import sys, os, re, time, json, zipfile, tempfile, shutil, copy
from pathlib import Path
from collections import defaultdict
from datetime import datetime

BACKEND_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(BACKEND_ROOT))

USE_L2 = "--no-l2" not in sys.argv

KISA_LEA_SRC = BACKEND_ROOT.parent / "블록암호_LEA_소스코드(v1.3)" / "LEA_C_Standalone_src"

from app.services.rule_engine_service import run_rule_engine

try:
    from app.services.llm_service import run_l2_contextualizer
    from app.services.report_service import post_process_violations
    L2_AVAILABLE = True
except Exception:
    L2_AVAILABLE = False

if not L2_AVAILABLE:
    USE_L2 = False


# ═══════════════════════════════════════════════════════════════════
# Mutation 정의
# ═══════════════════════════════════════════════════════════════════

MUTATIONS = [
    # --- LEA 알고리즘 규칙 ---
    {
        "id": "M01", "target_rule": "LEA-003",
        "file": "src/lea_core.c",
        "description": "라운드 수 연산 변조 (+16 → +15)",
        "search": "(mk_len >> 1) + 16",
        "replace": "(mk_len >> 1) + 15 /* MUTATION: off-by-one round count */",
    },
    {
        "id": "M02", "target_rule": "LEA-003",
        "file": "src/lea_core.c",
        "description": "라운드 수 조건 변조 (> 24 → > 25)",
        "search": "key->round > 24",
        "replace": "key->round > 25 /* MUTATION: round threshold */",
        "first_only": True,
    },
    {
        "id": "M03", "target_rule": "LEA-003",
        "file": "src/lea_core.c",
        "description": "라운드 수 조건 변조 (> 28 → > 29)",
        "search": "key->round > 28",
        "replace": "key->round > 29 /* MUTATION: round threshold */",
        "first_only": True,
    },
    {
        "id": "M04", "target_rule": "COM-001",
        "file": "lea_vs.c",
        "description": "키 데이터 제로화 memset 제거",
        "search_pattern": r"memset\s*\(\s*answ\s*,\s*0",
        "action": "comment_out_first_match",
    },
    {
        "id": "M05", "target_rule": "COM-003",
        "file": "lea_vs.c",
        "description": "하드코딩 키 삽입",
        "insert_after_pattern": r"#include",
        "insert_text": '\nstatic const unsigned char HARDCODED_KEY[16] = {0x0f,0x1e,0x2d,0x3c,0x4b,0x5a,0x69,0x78,0x87,0x96,0xa5,0xb4,0xc3,0xd2,0xe1,0xf0}; /* MUTATION: hardcoded key */\n',
        "insert_once": True,
    },
    {
        "id": "M06", "target_rule": "COM-004",
        "file": "lea_vs.c",
        "description": "비표준 난수 함수 사용 (rand 호출)",
        "insert_after_pattern": r"#include",
        "insert_text": '\nvoid generate_iv(unsigned char *iv, int len) { for(int i=0;i<len;i++) iv[i]=(unsigned char)(rand()%256); } /* MUTATION: weak RNG */\n',
        "insert_once": True,
    },
    {
        "id": "M07", "target_rule": "LEA-010",
        "file": "src/lea_core.c",
        "description": "델타 상수 LSB 변조",
        "search": "0xc3efe9db",
        "replace": "0xc3efe9da /* MUTATION: delta LSB flip */",
        "first_only": True,
    },
    {
        "id": "M08", "target_rule": "LEA-021",
        "file": "src/lea_core.c",
        "description": "라운드키 인덱스 변조 (key->rk[6] → key->rk[7])",
        "search": "key->rk[  6]",
        "replace": "key->rk[  7] /* MUTATION: wrong round key index */",
        "first_only": True,
    },
    {
        "id": "M09", "target_rule": "COM-004",
        "file": "main.c",
        "description": "srand(time(NULL)) 비표준 시드",
        "insert_after_pattern": r"#include",
        "insert_text": '\n#include <time.h>\nvoid init_random(void) { srand(time(NULL)); } /* MUTATION: non-CSPRNG seed */\n',
        "insert_once": True,
    },
    {
        "id": "M10", "target_rule": "ECB-002",
        "file": "lea_vs.c",
        "description": "ECB 모드 직접 사용 패턴",
        "insert_after_pattern": r"#include",
        "insert_text": '\nvoid ecb_encrypt_blocks(void *ctx, const unsigned char *in, unsigned char *out, int nblocks) {\n    for(int i=0;i<nblocks;i++) { /* MUTATION: ECB mode direct use */ }\n}\n',
        "insert_once": True,
    },
    {
        "id": "M11", "target_rule": "CBC-001",
        "file": "lea_vs.c",
        "description": "CBC 모드에서 IV XOR 누락",
        "insert_after_pattern": r"#include",
        "insert_text": '\nvoid cbc_encrypt_no_xor(void *ctx, const unsigned char *pt, unsigned char *ct, int len) {\n    /* MUTATION: CBC without IV XOR - CBC-001 violation */\n    unsigned char block[16];\n    for(int i=0; i<len/16; i++) {\n        memcpy(block, pt+i*16, 16);\n        /* missing: XOR with IV or previous ciphertext */\n    }\n}\n',
        "insert_once": True,
    },
    {
        "id": "M12", "target_rule": "CTR-002",
        "file": "lea_vs.c",
        "description": "CTR 카운터 오버플로우 미검사",
        "insert_after_pattern": r"#include",
        "insert_text": '\nvoid ctr_encrypt_no_overflow_check(unsigned int *counter, int nblocks) {\n    /* MUTATION: CTR counter overflow not checked - CTR-002 */\n    for(int i=0; i<nblocks; i++) { (*counter)++; }\n}\n',
        "insert_once": True,
    },
    {
        "id": "M13", "target_rule": "LEA-034",
        "file": "src/lea_core.c",
        "description": "ROR 회전량 변조 (3 → 4)",
        "search": "ROR((X2 ^ key->rk[  4]) + (X3 ^ key->rk[  5]), 3)",
        "replace": "ROR((X2 ^ key->rk[  4]) + (X3 ^ key->rk[  5]), 4) /* MUTATION: rotation */",
        "first_only": True,
    },
    {
        "id": "M14", "target_rule": "LEA-040",
        "file": "src/lea_core.c",
        "description": "키 스케줄 ROL 회전량 변조 (1 → 2)",
        "search": "ROL(loadU32(_mk[0]) + delta[0][ 0], 1)",
        "replace": "ROL(loadU32(_mk[0]) + delta[0][ 0], 2) /* MUTATION: key sched rotation */",
        "first_only": True,
    },
    {
        "id": "M15", "target_rule": "GCM-001",
        "file": "src/lea_gcm_generic.c",
        "description": "GCM 인증 태그 검증 누락 패턴",
        "insert_after_pattern": r"#include|#define",
        "insert_text": '\nint gcm_decrypt_no_tag_verify(void *ctx, unsigned char *out, const unsigned char *in, int len) {\n    /* MUTATION: GCM tag verification skipped - GCM-001 */\n    return 0; /* no tag check */\n}\n',
        "insert_once": True,
    },
]


def apply_mutation(src_dir: Path, mutation: dict) -> bool:
    """단일 mutation을 소스 디렉터리에 적용. 성공 시 True."""
    target_file = src_dir / mutation["file"]
    if not target_file.exists():
        # src/ 하위가 아닌 루트에 있을 수 있음
        alt = src_dir / mutation["file"].replace("src/", "")
        if alt.exists():
            target_file = alt
        else:
            print(f"    [SKIP] 파일 없음: {mutation['file']}")
            return False

    try:
        content = target_file.read_text(encoding="utf-8", errors="ignore")
    except:
        return False

    mid = mutation["id"]

    # 단순 문자열 치환
    if "search" in mutation and "replace" in mutation:
        if mutation["search"] not in content:
            print(f"    [SKIP] {mid}: 패턴 '{mutation['search'][:40]}' 미발견")
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

    # 정규식 기반 치환
    if "search_pattern" in mutation and "replace_text" in mutation:
        pat = re.compile(mutation["search_pattern"])
        if not pat.search(content):
            print(f"    [SKIP] {mid}: regex 미매칭")
            return False
        if mutation.get("first_only"):
            content = pat.sub(mutation["replace_text"], content, count=1)
        else:
            content = pat.sub(mutation["replace_text"], content)
        target_file.write_text(content, encoding="utf-8")
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

    # 특수 함수 기반 변환
    if mutation.get("replace_pattern_fn") == "reduce_array_size":
        pat = re.compile(mutation["search_pattern"])
        match = pat.search(content)
        if not match:
            print(f"    [SKIP] {mid}: 배열 패턴 미발견")
            return False
        old_size = int(match.group(1))
        new_size = max(old_size - 8, 4)
        old_text = match.group(0)
        new_text = old_text.replace(str(old_size), str(new_size)) + " /* MUTATION: reduced */"
        content = content.replace(old_text, new_text, 1)
        target_file.write_text(content, encoding="utf-8")
        return True

    print(f"    [SKIP] {mid}: 알 수 없는 mutation 타입")
    return False


def run_pipeline_on_dir(src_dir: Path) -> list:
    """주어진 소스 디렉터리에 L1(+L2) 파이프라인 실행."""
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
    l1_violations = run_rule_engine(
        preprocess_result=preprocess_result,
        rules_dir=rules_dir,
        job_root=src_dir.parent,
    )

    if USE_L2 and L2_AVAILABLE and l1_violations:
        l2_rejected = set()
        try:
            l2_violations = run_l2_contextualizer(
                preprocess_result=preprocess_result,
                l1_violations=l1_violations,
                _rejected_tracker=l2_rejected,
            )
            final = post_process_violations(
                l1=l1_violations, l2=l2_violations,
                l2_rejected_keys=l2_rejected,
            )
        except:
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
    print("Phase 3: KISA LEA Mutation 기반 블라인드 Recall 테스트")
    print(f"L2: {'활성화' if USE_L2 else '비활성화'}")
    print(f"Mutation 수: {len(MUTATIONS)}건")
    print("=" * 65)

    if not KISA_LEA_SRC.exists():
        print(f"[ERROR] 소스 경로 없음: {KISA_LEA_SRC}")
        return

    results = []
    tp = 0
    fn = 0
    skip = 0
    t_start = time.time()

    for i, mut in enumerate(MUTATIONS):
        mid = mut["id"]
        target = mut["target_rule"]
        desc = mut["description"]
        print(f"\n[{mid}] {target}: {desc}")

        # 클린 복사본 생성
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_src = Path(tmpdir) / "src"
            shutil.copytree(KISA_LEA_SRC, tmp_src)

            # mutation 적용
            success = apply_mutation(tmp_src, mut)
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
            violations = run_pipeline_on_dir(tmp_src)
            elapsed = time.time() - t0

            detected = check_detection(violations, target)
            status = "TP" if detected else "FN"
            if detected:
                tp += 1
            else:
                fn += 1

            # 해당 규칙의 탐지 상세
            matched = [v for v in violations if v.get("rule_id") == target]
            print(f"    → {status} ({target}): {len(matched)}건 탐지, "
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

    print(f"\n{'═' * 65}")
    print(f"  Phase 3 결과: Mutation 블라인드 Recall")
    print(f"{'═' * 65}")
    print(f"  총 mutation: {len(MUTATIONS)}건")
    print(f"  적용 성공: {total_applied}건 (skip: {skip}건)")
    print(f"  TP (탐지 성공): {tp}건")
    print(f"  FN (미탐지): {fn}건")
    print(f"  **Mutation Recall: {recall:.1%}**")
    print(f"  소요 시간: {total_elapsed:.0f}초")
    print(f"{'═' * 65}")

    # FN 상세
    if fn > 0:
        print(f"\n  [미탐지 mutation 상세]")
        for r in results:
            if r["status"] == "FN":
                print(f"    {r['id']} ({r['target_rule']}): {r['description']}")

    # JSON 저장
    output = {
        "timestamp": datetime.now().isoformat(),
        "phase": "Phase 3",
        "description": "KISA LEA v1.3 mutation 기반 블라인드 Recall 테스트",
        "use_l2": USE_L2,
        "total_mutations": len(MUTATIONS),
        "applied": total_applied,
        "skipped": skip,
        "TP": tp, "FN": fn,
        "mutation_recall": recall,
        "elapsed_s": round(total_elapsed, 1),
        "results": results,
    }
    out_path = BACKEND_ROOT / "scripts" / "blind_mutation_results.json"
    out_path.write_text(json.dumps(output, ensure_ascii=False, indent=2, default=str),
                        encoding="utf-8")
    print(f"\n결과 저장: {out_path}")

    return output


if __name__ == "__main__":
    main()
