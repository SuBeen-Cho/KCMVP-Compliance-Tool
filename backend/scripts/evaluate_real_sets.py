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
    python scripts/evaluate_real_sets.py [--no-l3] [--no-rag]
"""

import argparse, sys, os, re, time, json, zipfile, tempfile, shutil, unicodedata, hashlib, uuid
from pathlib import Path
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Set, Tuple, Optional

BACKEND_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(BACKEND_ROOT))

USE_L3 = True
NO_RAG = False
os.environ["ABLATION_NO_RAG"] = "1" if NO_RAG else "0"

KCMVP_ROOT = BACKEND_ROOT.parent.parent  # KCMVP/
SET_BASE = KCMVP_ROOT / "스크립트" / "코드 - 설계서 세트"

from app.services.rule_engine_service import run_rule_engine
from app.services.preprocess_docs_service import run_doc_preprocess
from app.services.doc_rule_service import load_doc_rules, run_doc_rule_engine
from app.services.rag_service import run_l2_rag_context
from experiments.manifest import build_manifest
from app.services.llm.gemini_client import get_token_usage, reset_token_usage
from app.services.llm.request_ledger import (
    disable_request_ledger, enable_request_ledger, get_request_ledger_status,
    request_ledger_file_sha256, reset_request_ledger,
)

try:
    from app.services.llm_service import run_l3_contextualizer, run_doc_l3_contextualizer
    from app.services.report_service import post_process_violations
    L3_AVAILABLE = True
except Exception as exc:
    L3_AVAILABLE = False
    L3_IMPORT_ERROR = exc

else:
    L3_IMPORT_ERROR = None


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
    "LEA-052",       # LEA_KEY 구조체 명칭 강제
    "LEA-054",       # lea_locl.h 헤더 명칭 강제
    "LEA-055",       # lea_t_sse2 등 SIMD 파일명 강제
    "CTR-LEA-005",   # lea_ctr SIMD 함수명 강제
    # Phase 2-A 제거된 규칙 (GT 제외 — 제거/통합 처리)
    "LEA-012",       # 주석 요구 (low severity FP) — 제거
    "LEA-049",       # Variable Key KAT — LEA-062로 통합
    "LEA-050",       # Variable Text KAT — LEA-062로 통합
    "LEA-058",       # KAT 파일 명칭 — LEA-048 중복 제거
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
            # Preserve the archive-relative identity. Basenames are not unique in
            # real projects and would otherwise merge unrelated candidates.
            parts = Path(name).parts
            fname = Path(*parts[parts.index("src") + 1:]).as_posix() if "src" in parts else Path(name).as_posix()
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


_GT_ANNOTATION = re.compile(r'\[위반[:\s]*[A-Z]+-[A-Z]*-?\d+\]')


def sanitize_gt_annotations(content: str) -> str:
    """Remove answer-bearing comments while preserving source line numbers."""
    cleaned = []
    for line in content.splitlines(keepends=True):
        if _GT_ANNOTATION.search(line):
            newline = "\n" if line.endswith("\n") else ""
            if "//" in line:
                line = line[:line.index("//")].rstrip() + newline
            else:
                line = _GT_ANNOTATION.sub("", line)
                line = re.sub(r'/\*.*?\*/', '', line).rstrip() + newline
        cleaned.append(line)
    return "".join(cleaned)


def source_id(path: Path, source_root: Path) -> str:
    """Stable source identity used by GT, detections, and exported candidates."""
    relative = path.resolve().relative_to(source_root.resolve())
    # Archives conventionally place implementation files below src/, while
    # tests and benchmarks live beside it.  Keep one project-wide analysis
    # root but preserve the historical GT identity that omits the src/ prefix.
    if relative.parts and relative.parts[0] == "src":
        relative = Path(*relative.parts[1:])
    return relative.as_posix()


def resolved_source_id(raw_path: str, source_root: Path, known: Dict[str, str]) -> str:
    if not raw_path:
        return ""
    if raw_path in known:
        return known[raw_path]
    candidate = Path(raw_path)
    if "src" in candidate.parts:
        parts = candidate.parts
        return Path(*parts[parts.index("src") + 1:]).as_posix()
    try:
        return source_id(candidate, source_root)
    except (ValueError, OSError):
        # A foreign path is retained verbatim enough to avoid basename merging.
        return Path(raw_path).as_posix()


def normalized_child(directory: Path, filename: str) -> Path:
    """Resolve macOS NFD filenames without weakening exact artifact selection."""
    exact = directory / filename
    if exact.exists() or not directory.is_dir():
        return exact
    wanted = unicodedata.normalize("NFC", filename)
    matches = [p for p in directory.iterdir() if unicodedata.normalize("NFC", p.name) == wanted]
    if len(matches) > 1:
        raise RuntimeError(f"ambiguous normalized filename in {directory}: {filename}")
    return matches[0] if matches else exact


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

        # Analyse the complete project tree.  Restricting discovery to src/
        # silently excluded sibling test/ and benchmark/ sources, including
        # the KAT request/response rules that explicitly target those files.
        src_dir = tmp
        c_files = sorted(src_dir.rglob("*.c"))

        # Engines re-read file paths, so sanitize the physical analysis tree.
        for source_file in c_files:
            raw = source_file.read_text(encoding="utf-8", errors="ignore")
            source_file.write_text(sanitize_gt_annotations(raw), encoding="utf-8")

        file_entries = []
        source_ids = {}
        for f in c_files:
            try:
                content = f.read_text(encoding="utf-8", errors="ignore")
            except:
                content = ""
            stable_id = source_id(f, src_dir)
            source_ids[str(f)] = stable_id
            file_entries.append({
                "path": str(f), "display": stable_id,
                "content": content, "lines": content.splitlines(), "ast": {},
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

        # L2 must run in both conditions; --no-rag makes this injection empty.
        l1_violations = run_l2_rag_context(l1_violations)
        occurrence = defaultdict(int)
        l3_candidate_ids = []
        for violation in l1_violations:
            stable_source = resolved_source_id(str(violation.get("file", "")), src_dir, source_ids)
            rule_id = str(violation.get("rule_id", ""))
            line = int(violation.get("line") or 0)
            key = (stable_source, rule_id, line)
            occurrence[key] += 1
            candidate_id = f"{set_name}::{stable_source}::{rule_id}::{line}::{occurrence[key]}"
            violation["candidate_id"] = candidate_id
            l3_candidate_ids.append(candidate_id)
        pre_l3_candidate_keys = {
            (resolved_source_id(str(v.get('file', '')), src_dir, source_ids), v.get('rule_id', ''))
            for v in l1_violations
            if v.get("rule_id") and resolved_source_id(str(v.get("file", "")), src_dir, source_ids)
        }
        pre_l3_candidate_ids = sorted(f"{set_name}::{fname}::{rid}" for fname, rid in pre_l3_candidate_keys)

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
                raise RuntimeError(f"L3 failed; refusing to mix an L1-only fallback into an L3 run: {e}") from e
        else:
            final_violations = l1_violations
        t_l3 = time.time() - t1
        print(f"  L3: 최종 {len(final_violations)}건, 제거 {len(l3_rejected_keys)}건, {t_l3:.1f}s")

        # L3 필터링 정확도 계산
        l3_correct = 0  # GT 외 오탐 → 정확 제거
        l3_wrong = 0    # GT 내 → 오판 (FN 유발)
        for (rej_file, rej_rid, rej_line) in l3_rejected_keys:
            fname = resolved_source_id(str(rej_file), src_dir, source_ids)
            if (fname, rej_rid) in gt_rules:
                l3_wrong += 1
                l3_rejected_detail.append({"candidate_id": f"{set_name}::{fname}::{rej_rid}", "file": fname, "rule_id": rej_rid, "correct": False})
            else:
                l3_correct += 1
                l3_rejected_detail.append({"candidate_id": f"{set_name}::{fname}::{rej_rid}", "file": fname, "rule_id": rej_rid, "correct": True})

    # 탐지 결과 집계 (파일명, rule_id)
    detected = defaultdict(set)
    detected_detail = defaultdict(list)
    for v in final_violations:
        raw_file = str(v.get("file", ""))
        fname = resolved_source_id(raw_file, src_dir, source_ids)
        rid = v.get("rule_id", "")
        if fname and rid:
            detected[fname].add(rid)
            detected_detail[fname].append(v)

    # 혼동행렬 (GT 기준)
    TP = 0; FN = 0; FP_extra = 0
    tp_list = []; fn_list = []; fp_list = []

    for fname in sorted(set(code_gt) | set(detected)):
        expected_rids = {v["rule_id"] for v in code_gt.get(fname, [])}
        detected_rids = detected.get(fname, set())

        for rid in expected_rids:
            if rid in detected_rids:
                TP += 1
                tp_list.append({"candidate_id": f"{set_name}::{fname}::{rid}", "file": fname, "rule_id": rid})
            else:
                FN += 1
                fn_list.append({"candidate_id": f"{set_name}::{fname}::{rid}", "file": fname, "rule_id": rid})

        # GT에 없는 추가 탐지 (over-detection)
        extra = detected_rids - expected_rids
        for rid in extra:
            FP_extra += 1
            fp_list.append({"candidate_id": f"{set_name}::{fname}::{rid}", "file": fname, "rule_id": rid})

    total_gt = TP + FN
    recall = TP / total_gt if total_gt > 0 else 0.0
    precision = TP / (TP + FP_extra) if (TP + FP_extra) > 0 else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    final_candidate_ids = sorted({
        f"{set_name}::{fname}::{rid}" for fname, rids in detected.items() for rid in rids
    })
    final_candidate_keys = {(fname, rid) for fname, rids in detected.items() for rid in rids}
    unique_removed_keys = pre_l3_candidate_keys - final_candidate_keys
    unique_removed_ids = sorted(f"{set_name}::{fname}::{rid}" for fname, rid in unique_removed_keys)
    unique_author_gt_extra = sum(key not in gt_rules for key in unique_removed_keys)
    unique_author_gt_match = len(unique_removed_keys) - unique_author_gt_extra

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
        "pre_l3_candidate_ids": pre_l3_candidate_ids,
        "l3_request_candidate_ids": l3_candidate_ids,
        "final_candidate_ids": final_candidate_ids,
        "l3_unique_removed_ids": unique_removed_ids,
        "l3_unique_author_gt_extra_removed": unique_author_gt_extra,
        "l3_unique_author_gt_match_removed": unique_author_gt_match,
        "final_count": len(final_violations),
        "tp_list": tp_list, "fn_list": fn_list, "fp_list": fp_list,
        "timing": {"l1_s": round(t_l1, 1), "l3_s": round(t_l3, 1),
                    "total_s": round(t_l1 + t_l3, 1)},
        "detected": {k: sorted(v) for k, v in sorted(detected.items())},
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
                raise RuntimeError(f"DOC L3 failed; refusing to mix an L1-only fallback into an L3 run: {e}") from e
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
    total_unique_removed = sum(len(r.get("l3_unique_removed_ids", [])) for r in all_code_results)
    total_unique_author_gt_extra = sum(r.get("l3_unique_author_gt_extra_removed", 0) for r in all_code_results)
    total_unique_author_gt_match = sum(r.get("l3_unique_author_gt_match_removed", 0) for r in all_code_results)
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
    print(f"  코드 위반 탐지 성능 ({len(all_code_results)}세트 합산)")
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
        "l3_unique_removed": total_unique_removed,
        "l3_unique_author_gt_extra_removed": total_unique_author_gt_extra,
        "l3_unique_author_gt_match_removed": total_unique_author_gt_match,
        "doc_avg_per_set": doc_avg,
    }


# ═══════════════════════════════════════════════════════════════════
# 메인
# ═══════════════════════════════════════════════════════════════════

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate KCMVP code/design sets reproducibly")
    parser.add_argument("--no-l3", action="store_true", help="Run deterministic L1 only")
    parser.add_argument("--no-rag", action="store_true", help="Disable L2 retrieval/evidence")
    parser.add_argument("--code-only", action="store_true", help="Evaluate code only; skip document preprocessing and L3")
    parser.add_argument("--sets", default="1-7", help="Comma-separated numbers/ranges, e.g. 1,3-5")
    parser.add_argument("--output", type=Path, help="Result JSON path (overrides EVALUATION_OUTPUT)")
    parser.add_argument(
        "--request-ledger", type=Path,
        help="Opt in to non-sensitive LLM request telemetry at this JSONL path",
    )
    return parser.parse_args(argv)


def parse_set_selection(value: str) -> List[int]:
    selected: Set[int] = set()
    for token in value.split(","):
        token = token.strip()
        if not token:
            raise ValueError("empty set selector")
        if "-" in token:
            start_text, end_text = token.split("-", 1)
            start, end = int(start_text), int(end_text)
            if start > end:
                raise ValueError(f"descending set range: {token}")
            selected.update(range(start, end + 1))
        else:
            selected.add(int(token))
    if not selected or min(selected) < 1:
        raise ValueError("set numbers must be positive")
    return sorted(selected)


def main(argv: Optional[List[str]] = None):
    global USE_L3, NO_RAG
    args = parse_args(argv)
    output_override = os.environ.get("EVALUATION_OUTPUT")
    json_path = args.output or (Path(output_override) if output_override else BACKEND_ROOT / "scripts" / "evaluation_results.json")
    if args.request_ledger is not None and args.request_ledger.resolve() == json_path.resolve():
        raise ValueError("--request-ledger must differ from the evaluation result path")
    USE_L3 = not args.no_l3
    NO_RAG = args.no_rag
    os.environ["ABLATION_NO_RAG"] = "1" if NO_RAG else "0"
    selected_sets = parse_set_selection(args.sets)
    if USE_L3 and not L3_AVAILABLE:
        raise RuntimeError(f"L3 was requested but could not be imported: {L3_IMPORT_ERROR}")

    print("=" * 65)
    print("KCMVP 실제 코드-설계서 세트 성능 평가")
    print(f"L3 Gemini: {'활성화' if USE_L3 else '비활성화'}")
    print(f"RAG evidence: {'비활성화 (paired ablation)' if NO_RAG else '활성화'}")
    print(f"세트 경로: {SET_BASE}")
    print("=" * 65)

    expected_inputs = []
    for i in selected_sets:
        set_dir = SET_BASE / f"세트 {i}"
        expected_inputs.extend(
            p for p in (
                set_dir / "kcmvp_combined.zip",
                *((set_dir / "kcmvp_violations_design.pdf", normalized_child(set_dir, "정답지_위반목록.md")) if not args.code_only else ()),
            )
            if p.is_file()
        )
    manifest_start = build_manifest(BACKEND_ROOT.parent, expected_inputs)
    ledger_run_id = uuid.uuid4().hex
    ledger_snapshot_id = hashlib.sha256(
        json.dumps(manifest_start, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()
    if args.request_ledger is not None:
        reset_request_ledger()
        enable_request_ledger(
            args.request_ledger, run_id=ledger_run_id,
            snapshot_id=ledger_snapshot_id, truncate=True,
        )
    t_start = time.perf_counter()
    reset_token_usage()
    all_code_results = []
    all_doc_results = []

    skipped_sets = []
    failed_sets = []
    for i in selected_sets:
        set_dir = SET_BASE / f"세트 {i}"
        set_name = f"세트 {i}"

        zip_path = set_dir / "kcmvp_combined.zip"
        pdf_path = set_dir / "kcmvp_violations_design.pdf"
        gt_path = normalized_child(set_dir, "정답지_위반목록.md")

        if not zip_path.exists():
            print(f"\n[SKIP] {set_name}: ZIP 없음")
            skipped_sets.append({"set_name": set_name, "reason": "missing_code_zip"})
            continue

        # 코드 평가
        try:
            code_result = evaluate_code_set(zip_path, set_name)
        except Exception as exc:
            failed_sets.append({
                "set_name": set_name,
                "stage": "code_pipeline",
                "error_type": type(exc).__name__,
                "reason": str(exc),
            })
            print(f"\n[ERROR] {set_name}: {type(exc).__name__}: {exc}")
            # Stop after the first provider/pipeline failure to avoid repeated
            # billing and misleading mixed-condition results.
            break
        all_code_results.append(code_result)

        if args.code_only:
            continue

        # 설계서 평가
        design_gt = parse_design_gt(gt_path) if gt_path.exists() else []
        if pdf_path.exists():
            doc_result = evaluate_design_set(pdf_path, set_name, design_gt)
            all_doc_results.append(doc_result)
            if "error" in doc_result:
                failed_sets.append({"set_name": set_name, "reason": doc_result["error"]})

    total_elapsed = time.perf_counter() - t_start
    print(f"\n총 소요 시간: {total_elapsed:.1f}초")

    # 논문 표 7 형식 출력
    summary = print_paper_table(all_code_results, all_doc_results)

    # JSON 결과 저장
    manifest_end = build_manifest(BACKEND_ROOT.parent, expected_inputs)
    identity_checks = {
        "workspace": manifest_start["code"]["workspace_sha256"] == manifest_end["code"]["workspace_sha256"],
        "inputs_and_artifacts": manifest_start["artifacts"] == manifest_end["artifacts"],
        "environment": manifest_start["environment"] == manifest_end["environment"],
        "models": manifest_start["models"] == manifest_end["models"],
    }
    identity_stable = all(identity_checks.values())
    token_usage = get_token_usage()
    complete = len(all_code_results) == len(selected_sets) and not failed_sets
    if not identity_stable:
        run_status = "invalid_workspace_changed"
    elif not complete:
        run_status = "experimental_partial"
    elif manifest_end["code"]["dirty"]:
        run_status = "experimental_dirty"
    else:
        run_status = "experimental_unvalidated"
    ledger_status = get_request_ledger_status() if args.request_ledger is not None else {
        "scope": "code_l3_experiment_requests_only", "status": "disabled"
    }
    if args.request_ledger is not None:
        ledger_status["jsonl_sha256"] = request_ledger_file_sha256()
    results = {
        "schema_version": "1.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "use_l3": USE_L3,
        "ablation": {"no_rag": NO_RAG},
        "scope": {"code_only": args.code_only},
        "requested_sets": selected_sets,
        "skipped_sets": skipped_sets,
        "failed_sets": failed_sets,
        "run_status": run_status,
        "canonical_status": run_status,
        "manifest": {
            "start": manifest_start,
            "end": manifest_end,
            "experiment": {
                "use_l3": USE_L3,
                "no_rag": NO_RAG,
                "code_only": args.code_only,
                "requested_sets": selected_sets,
            },
            "identity_checks": identity_checks,
            "identity_stable": identity_stable,
        },
        "usage": {
            "provider_calls": token_usage.get("calls", 0),
            "input_tokens": token_usage.get("input", 0),
            "output_tokens": token_usage.get("output", 0),
            "usage_status": token_usage.get("usage_status", "unavailable"),
            "pricing_snapshot": None,
            "estimated_cost_usd": None,
            "cost_status": "not_computed_without_versioned_pricing",
        },
        "request_ledger": ledger_status,
        "total_elapsed_s": round(total_elapsed, 1),
        "code_results": all_code_results,
        "doc_results": all_doc_results,
        "summary": summary,
    }
    json_path.parent.mkdir(parents=True, exist_ok=True)
    # The ledger is scoped to this completed experiment only.  Disable it before
    # any later report-writing code can accidentally append out-of-scope calls.
    disable_request_ledger()
    temp_json = json_path.with_name(f".{json_path.name}.{os.getpid()}.tmp")
    temp_json.write_text(json.dumps(results, ensure_ascii=False, indent=2, default=str), encoding='utf-8')
    os.replace(temp_json, json_path)
    print(f"\n결과 JSON 저장: {json_path}")
    return results


if __name__ == "__main__":
    main()
