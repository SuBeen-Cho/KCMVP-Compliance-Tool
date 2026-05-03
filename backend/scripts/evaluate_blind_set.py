"""
블라인드 평가 세트 평가 스크립트
==================================
내부 참조 세트를 대상으로 규칙 엔진을 실행하여 탐지 성능을 측정.

탐지된 위반은 두 가지로 구분:
  (a) FP — 규칙 엔진의 과탐 (개선 대상)
  (b) 실제 개선 여지 — 인증 이후 강화 가능한 항목

Usage:
    cd backend
    python scripts/evaluate_blind_set.py [--no-l3]
"""

import io
import json
import shutil
import sys
import tempfile
import time
import zipfile
from collections import Counter
from datetime import datetime
from pathlib import Path

BACKEND_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(BACKEND_ROOT))

USE_L3 = "--no-l3" not in sys.argv

_BLIND_ZIP = BACKEND_ROOT.parent / "0_KCMVP.zip"

from app.services.rule_engine_service import run_rule_engine

try:
    from app.services.llm_service import run_l3_contextualizer
    from app.services.report_service import post_process_violations
    L3_AVAILABLE = True
except Exception:
    L3_AVAILABLE = False

if not L3_AVAILABLE:
    USE_L3 = False


def count_loc(src_dir: Path) -> int:
    total = 0
    for ext in ("*.c", "*.h"):
        for f in src_dir.rglob(ext):
            try:
                total += len(f.read_text(encoding="utf-8", errors="ignore").splitlines())
            except Exception:
                pass
    return total


def extract_smart_crypto(dest: Path) -> Path:
    """0_KCMVP.zip → smart-crypto-master.zip → src/ 재귀 해제 후 소스 루트 반환."""
    if not _BLIND_ZIP.exists():
        raise FileNotFoundError(f"블라인드 평가 ZIP 없음: {_BLIND_ZIP}")

    outer_bytes = _BLIND_ZIP.read_bytes()
    _recursive_unzip(outer_bytes, dest)

    # src/ 디렉터리가 있으면 그걸 소스 루트로, 없으면 최상위 사용
    src_dir = dest / "src"
    if src_dir.exists():
        return dest  # src/ + include/ 모두 포함한 루트 반환
    return dest


def _recursive_unzip(data: bytes, dest: Path, depth: int = 0) -> None:
    if depth > 5:
        return
    dest.mkdir(parents=True, exist_ok=True)
    dest_resolved = dest.resolve()
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for member in zf.namelist():
            path = Path(member)
            if path.is_absolute() or ".." in path.parts:
                continue
            target = (dest / path).resolve()
            try:
                target.relative_to(dest_resolved)
            except ValueError:
                continue
            if member.endswith("/"):
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                inner = zf.read(member)
                if member.lower().endswith(".zip") and inner[:4] == b"PK\x03\x04":
                    _recursive_unzip(inner, dest, depth + 1)
                else:
                    target.write_bytes(inner)


def collect_files(src_root: Path):
    """C/H 파일을 수집해 file_entries 목록 반환."""
    entries = []
    for ext in ("*.c", "*.h"):
        for f in sorted(src_root.rglob(ext)):
            # 빌드 아티팩트 폴더 제외
            if any(p in f.parts for p in ("CMakeFiles", "build", "cmake_install")):
                continue
            try:
                content = f.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                content = ""
            try:
                display = str(f.relative_to(src_root)).replace("\\", "/")
            except ValueError:
                display = f.name
            entries.append({
                "path": str(f),
                "display": display,
                "content": content,
                "ast": {},
            })
    return entries


def _safe_text(value, limit: int = 240) -> str:
    if value is None:
        return ""
    text = str(value).replace("\r", " ").replace("\n", " ").strip()
    return text[:limit]


def _violation_key(v) -> tuple:
    return (
        str(v.get("file") or "").strip(),
        str(v.get("rule_id") or "").strip(),
        v.get("line"),
    )


def _l3_status(v, rejected_keys: set) -> str:
    if not USE_L3:
        return "l3_disabled"
    if _violation_key(v) in rejected_keys:
        return "removed_by_l3"
    if v.get("l3_confirmed"):
        return "confirmed_by_l3"
    if v.get("l3_message") or v.get("l3_is_real_issue") is not None:
        return "kept_after_l3_review"
    return "kept_without_l3_review"


def _make_detail(v, rejected_keys: set) -> dict:
    rid = v.get("rule_id", "?")
    fname = v.get("file", "")
    fname_short = Path(fname).name if fname else "?"
    confidence = v.get("confidence")
    confidence_score = v.get("confidence_score")
    try:
        confidence_score = int(confidence_score) if confidence_score is not None else None
    except (TypeError, ValueError):
        confidence_score = None

    return {
        "rule_id": rid,
        "file": fname_short,
        "file_full": fname,
        "line": v.get("line", 0),
        "scope": v.get("scope"),
        "severity": v.get("severity", "?"),
        "pattern_type": v.get("pattern_type", "?"),
        "artifact_rule": bool(v.get("artifact_rule")),
        "confidence": confidence,
        "confidence_score": confidence_score,
        "l3_status": _l3_status(v, rejected_keys),
        "l3_confirmed": bool(v.get("l3_confirmed")),
        "l3_is_real_issue": v.get("l3_is_real_issue"),
        "needs_ai_review": bool(v.get("needs_ai_review")),
        "insufficient_context": bool(v.get("insufficient_context")),
        "message": _safe_text(v.get("message"), 160),
        "l3_message": _safe_text(v.get("l3_message"), 240),
        "suggestion": _safe_text(v.get("suggestion"), 240),
    }


def run_evaluation():
    print("=" * 65)
    print("블라인드 평가 세트 — 규칙 엔진 평가")
    print(f"L3 (Gemini): {'활성화' if USE_L3 else '비활성화'}")
    print("=" * 65)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        extract_dest = tmp / "blind_set"

        print("\n[압축 해제] 블라인드 평가 세트 소스 추출...")
        src_root = extract_smart_crypto(extract_dest)

        file_entries = collect_files(src_root)
        c_count = sum(1 for e in file_entries if e["display"].endswith(".c"))
        h_count = sum(1 for e in file_entries if e["display"].endswith(".h"))
        total_loc = count_loc(src_root)
        print(f"[정보] C 파일: {c_count}개, H 파일: {h_count}개, 총 LOC: {total_loc}")

        if not file_entries:
            print("[ERROR] 소스 파일을 찾을 수 없습니다.")
            return

        preprocess_result = {"files": file_entries}
        rules_dir = BACKEND_ROOT / "rules"

        # L1
        print(f"\n[L1] 규칙 엔진 실행 중...")
        t0 = time.time()
        l1_violations = run_rule_engine(
            preprocess_result=preprocess_result,
            rules_dir=rules_dir,
            job_root=tmp,
        )
        t_l1 = time.time() - t0
        print(f"  L1 완료: {len(l1_violations)}건 탐지, {t_l1:.1f}s")

        # L3
        l3_rejected_keys: set = set()
        if USE_L3 and L3_AVAILABLE and l1_violations:
            print(f"\n[L3] Gemini 재판정 중...")
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

    # 결과 분석
    print(f"\n{'═' * 65}")
    print("  평가 결과 (smart-crypto — KCMVP 인증 모듈)")
    print(f"{'═' * 65}")

    by_rule: Counter = Counter()
    by_file: Counter = Counter()
    by_severity: Counter = Counter()
    by_pattern: Counter = Counter()
    by_confidence: Counter = Counter()
    by_l3_status: Counter = Counter()
    details = []

    for v in final_violations:
        rid = v.get("rule_id", "?")
        fname = v.get("file", "")
        # display 경로 정리
        fname_short = Path(fname).name if fname else "?"
        sev = v.get("severity", "?")
        ptype = v.get("pattern_type", "?")
        by_rule[rid] += 1
        by_file[fname_short] += 1
        by_severity[sev] += 1
        by_pattern[ptype] += 1
        by_confidence[v.get("confidence") or "미분류"] += 1
        by_l3_status[_l3_status(v, l3_rejected_keys)] += 1
        details.append(_make_detail(v, l3_rejected_keys))

    removed_details = []
    if l3_rejected_keys:
        for v in l1_violations:
            if _violation_key(v) in l3_rejected_keys:
                removed_details.append(_make_detail(v, l3_rejected_keys))

    total = len(final_violations)
    per_kloc = total / (total_loc / 1000) if total_loc > 0 else 0.0

    print(f"  총 탐지: {total}건")
    print(f"  총 LOC: {total_loc}")
    print(f"  탐지율: {per_kloc:.1f}건/KLOC")
    print(f"{'─' * 65}")

    print(f"\n  [규칙별 탐지 분포] (상위 20)")
    for rid, cnt in by_rule.most_common(20):
        print(f"    {rid}: {cnt}건")

    print(f"\n  [파일별 탐지 분포] (상위 15)")
    for fname, cnt in by_file.most_common(15):
        print(f"    {fname}: {cnt}건")

    print(f"\n  [심각도별]")
    for sev, cnt in by_severity.most_common():
        print(f"    {sev}: {cnt}건")

    print(f"\n  [패턴타입별]")
    for pt, cnt in by_pattern.most_common():
        print(f"    {pt}: {cnt}건")

    print(f"\n  [신뢰도별]")
    for confidence, cnt in by_confidence.most_common():
        print(f"    {confidence}: {cnt}건")

    if USE_L3:
        print(f"\n  [L3 필터 효과]")
        print(f"    L1: {len(l1_violations)}건  →  최종: {total}건 (L3 제거: {len(l3_rejected_keys)}건)")
        for status, cnt in by_l3_status.most_common():
            print(f"    {status}: {cnt}건")

    print(f"\n{'═' * 65}")
    print("  [해석 가이드]")
    print("  탐지된 위반은 두 가지로 구분됩니다:")
    print("    (a) FP — 규칙 엔진의 과탐 (개선 대상)")
    print("    (b) 실제 개선 여지 — 강화 가능한 항목")
    print("  high 심각도 + regex/ast 패턴 위반을 우선 검토하세요.")
    print(f"{'═' * 65}")

    # JSON 저장
    ts = datetime.now().strftime("%Y%m%d_%H%M")
    out_path = BACKEND_ROOT / "scripts" / f"blind_eval_{ts}.json"
    result = {
        "timestamp": ts,
        "source": "blind_set",
        "total_loc": total_loc,
        "total_violations": total,
        "violations_per_kloc": round(per_kloc, 2),
        "l1_violations": len(l1_violations),
        "l3_removed": len(l3_rejected_keys),
        "by_rule": dict(by_rule.most_common()),
        "by_file": dict(by_file.most_common()),
        "by_severity": dict(by_severity),
        "by_pattern": dict(by_pattern),
        "by_confidence": dict(by_confidence),
        "by_l3_status": dict(by_l3_status),
        "details": details,
        "removed_details": removed_details,
    }
    out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n  결과 저장: {out_path.name}")


if __name__ == "__main__":
    run_evaluation()
