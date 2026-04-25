"""
QLoRA 파인튜닝용 학습 데이터 생성 스크립트.

기존 분석 결과(violations.json + patches/)에서 instruction-following 형식의
학습 데이터를 추출해 JSONL 파일로 저장.

출력 형식 (Alpaca instruction format):
  {
    "instruction": "KCMVP 암호모듈 보안 전문가로서 위반을 판정하라.",
    "input": "파일: ... 라인: ... 코드:\\n```c\\n...\\n```",
    "output": "{\"is_real_issue\": true, \"description\": \"...\", \"suggestion\": \"...\"}"
  }

실행:
  cd backend
  venv/bin/python3 scripts/gen_training_data.py
  venv/bin/python3 scripts/gen_training_data.py --output data/train.jsonl
  venv/bin/python3 scripts/gen_training_data.py --include-patches  # 패치 데이터 포함
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

from app.config import settings


# ─────────────────────────────────────────────────────────────────
# 학습 데이터 생성기
# ─────────────────────────────────────────────────────────────────

# L3 판정 판단 기준 (llm_service.py의 PROMPT_TEMPLATES와 동기화)
_PROMPT_TEMPLATES: Dict[str, str] = {
    "COM-001": (
        "잔존정보 제거 관점: 키/IV/라운드키/중간 연산 버퍼가 사용 후 "
        "memset_s, SecureZeroMemory, explicit_bzero 등 최적화 방지 함수로 제로화되었는지 판단하라."
    ),
    "COM-002": (
        "에러 처리 관점: 암호 연산 실패 시 음수(-1)를 반환하고, "
        "호출자가 반환값을 검사하는지 판단하라."
    ),
    "COM-003": (
        "하드코딩 키/IV 관점: 이 상수 배열이 실제 암호키 또는 IV인지, "
        "아니면 S-box/lookup table/공개 알고리즘 상수/테스트벡터인지 판단하라."
    ),
    "COM-004": (
        "난수 생성 관점: rand(), srand(), random(), drand48() 등 비암호학적 PRNG가 "
        "암호 연산(키·IV·Nonce 생성)에 사용되는지 판단하라."
    ),
    "COM-005": (
        "API 호출 순서 관점: lea_online_init → lea_online_update → lea_online_final "
        "순서가 보장되는지 판단하라."
    ),
    "DEFAULT": "KCMVP 암호모듈 보안 관점에서 위반 여부를 판단하라.",
}

_L3_INSTRUCTION = (
    "당신은 KCMVP 암호모듈 보안 전문 리뷰어입니다. "
    "아래 코드 스니펫이 실제 보안 위반인지 판정하라. "
    "반드시 JSON 형식으로만 출력하라: "
    "{\"is_real_issue\": true 또는 false, \"description\": \"한글 설명\", \"suggestion\": \"수정 방향\"}"
)

_PATCH_INSTRUCTION = (
    "당신은 KCMVP 암호모듈 보안 전문가입니다. "
    "아래 위반 코드를 수정하여 KCMVP 규격에 맞는 올바른 구현을 제시하십시오. "
    "## Before / ## After / ## 수정 이유 형식의 마크다운으로 출력하라."
)


def _get_template(rule_id: str) -> str:
    if rule_id in _PROMPT_TEMPLATES:
        return _PROMPT_TEMPLATES[rule_id]
    prefix = "-".join(rule_id.split("-")[:2]) if "-" in rule_id else rule_id
    return _PROMPT_TEMPLATES.get(prefix, _PROMPT_TEMPLATES["DEFAULT"])


def _load_violations(job_dir: Path) -> List[Dict[str, Any]]:
    vfile = job_dir / "violations.json"
    if not vfile.exists():
        return []
    try:
        return json.loads(vfile.read_text(encoding="utf-8"))
    except Exception:
        return []


def _load_patch_files(job_dir: Path) -> List[Dict[str, str]]:
    """patches/ 디렉터리의 .md 파일을 읽어 {rule_id, file, line, content} 반환."""
    patches_dir = job_dir / "patches"
    if not patches_dir.exists():
        return []
    result = []
    for md_path in patches_dir.glob("*.md"):
        # 파일명 형식: {rule_id}-{safe_file}-{line}.md
        parts = md_path.stem.split("-")
        rule_id = "-".join(parts[:2]) if len(parts) >= 2 else md_path.stem
        content = md_path.read_text(encoding="utf-8")
        result.append({
            "rule_id": rule_id,
            "filename": md_path.name,
            "content": content,
        })
    return result


def _load_preprocess(job_dir: Path) -> Dict[str, Any]:
    # preprocess_result.json 우선, code_preprocess.json fallback
    for name in ("preprocess_result.json", "code_preprocess.json"):
        pfile = job_dir / name
        if pfile.exists():
            try:
                return json.loads(pfile.read_text(encoding="utf-8"))
            except Exception:
                return {}
    return {}


def _get_snippet(preprocess: Dict[str, Any], file_path: str, line: int, window: int = 15) -> str:
    """preprocess 결과에서 file_path:line 주변 코드 추출."""
    if not line or not file_path:
        return ""
    for fi in preprocess.get("files", []):
        fp = fi.get("path") or ""
        if fp == file_path or fp.endswith(file_path) or file_path.endswith(fp):
            lines = fi.get("lines") or []
            if not lines:
                return ""
            start = max(0, line - window - 1)
            end = min(len(lines), line + window)
            return "\n".join(f"{start + i + 1}: {l}" for i, l in enumerate(lines[start:end]))
    return ""


def _build_l3_sample(v: Dict[str, Any], snippet: str) -> Optional[Dict[str, str]]:
    """단일 위반 → L3 판정 학습 샘플 생성."""
    if not snippet:
        return None

    rule_id = (v.get("rule_id") or "UNKNOWN").lstrip("L3-")
    file_path = v.get("file") or ""
    line = v.get("line") or 0
    l1_msg = v.get("message") or ""
    template = _get_template(rule_id)
    source = v.get("source") or "L1"

    # L3 판정 결과 (is_real_issue는 source와 l3_confirmed 기반)
    is_real = source in ("L1+L3",) or bool(v.get("l3_confirmed"))
    output_obj = {
        "is_real_issue": is_real,
        "description": v.get("l3_message") or l1_msg,
        "suggestion": v.get("suggestion") or "",
    }

    return {
        "instruction": _L3_INSTRUCTION,
        "input": (
            f"파일: {file_path}\n"
            f"라인: {line}\n"
            f"rule_id: {rule_id}\n"
            f"판정 기준: {template}\n"
            f"L1 메시지: {l1_msg}\n\n"
            f"코드:\n```c\n{snippet}\n```"
        ),
        "output": json.dumps(output_obj, ensure_ascii=False),
    }


def _build_patch_sample(
    v: Dict[str, Any], snippet: str, patch_content: Optional[str]
) -> Optional[Dict[str, str]]:
    """위반 + 패치 → 패치 생성 학습 샘플 생성."""
    if not snippet or not patch_content:
        return None

    file_path = v.get("file") or ""
    line = v.get("line") or 0
    violation_msg = v.get("message") or ""
    evidence = v.get("evidence") or ""

    evidence_section = f"\n참고 가이드라인:\n{evidence[:500]}\n" if evidence else ""

    return {
        "instruction": _PATCH_INSTRUCTION,
        "input": (
            f"파일: {file_path}\n"
            f"라인: {line}\n"
            f"위반 내용: {violation_msg}\n"
            f"{evidence_section}\n"
            f"위반 코드:\n```c\n{snippet}\n```"
        ),
        "output": patch_content,
    }


def generate_samples(
    jobs_root: Path,
    include_patches: bool = False,
) -> List[Dict[str, str]]:
    """
    storage/jobs/ 하위 모든 job에서 학습 샘플 추출.

    Parameters
    ----------
    jobs_root     : storage/jobs/ 디렉터리
    include_patches : True 시 패치 생성 샘플도 포함

    Returns
    -------
    list[dict] : instruction/input/output 트리플 리스트
    """
    samples: List[Dict[str, str]] = []
    seen: set = set()

    job_dirs = sorted(jobs_root.iterdir()) if jobs_root.exists() else []
    print(f"[GenData] job 디렉터리 {len(job_dirs)}개 탐색 중...")

    for job_dir in job_dirs:
        if not job_dir.is_dir():
            continue

        violations = _load_violations(job_dir)
        preprocess = _load_preprocess(job_dir)
        patch_files = _load_patch_files(job_dir) if include_patches else []

        # 패치 파일 인덱스: rule_id → content (첫 번째 매칭)
        patch_index: Dict[str, str] = {}
        for pf in patch_files:
            rid = pf["rule_id"]
            if rid not in patch_index:
                patch_index[rid] = pf["content"]

        for v in violations:
            file_path = v.get("file") or ""
            line = int(v.get("line") or 0)
            rule_id = (v.get("rule_id") or "").lstrip("L3-")
            pattern_type = v.get("pattern_type") or "regex"

            # missing 타입은 스니펫 없으므로 스킵; None은 regex로 취급
            if not pattern_type:
                pattern_type = "regex"
            if pattern_type == "missing" or not line:
                continue

            snippet = _get_snippet(preprocess, file_path, line)
            if not snippet:
                continue

            # 중복 방지: (file, line, rule_id)
            dedup_key = f"{file_path}:{line}:{rule_id}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            # L3 판정 샘플
            l3_sample = _build_l3_sample(v, snippet)
            if l3_sample:
                samples.append(l3_sample)

            # 패치 샘플 (옵션)
            if include_patches and rule_id in patch_index:
                patch_sample = _build_patch_sample(v, snippet, patch_index[rule_id])
                if patch_sample:
                    samples.append(patch_sample)

    return samples


def main() -> int:
    parser = argparse.ArgumentParser(description="QLoRA 학습 데이터 생성")
    parser.add_argument(
        "--output",
        default="data/train.jsonl",
        help="출력 JSONL 파일 경로 (기본: data/train.jsonl)",
    )
    parser.add_argument(
        "--include-patches",
        action="store_true",
        help="패치 생성 학습 샘플 포함",
    )
    parser.add_argument(
        "--jobs-root",
        default=None,
        help="job 루트 디렉터리 (기본: STORAGE_ROOT/jobs)",
    )
    args = parser.parse_args()

    jobs_root = (
        Path(args.jobs_root) if args.jobs_root
        else BACKEND / settings.STORAGE_ROOT / settings.JOB_DATA_DIR
    )

    samples = generate_samples(jobs_root, include_patches=args.include_patches)

    if not samples:
        print("[GenData] 학습 샘플 없음. 먼저 분석 job을 실행하세요.")
        print(f"  jobs 경로: {jobs_root}")
        return 1

    out_path = BACKEND / args.output
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        for s in samples:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")

    print(f"[GenData] 완료: {len(samples)}개 샘플 → {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
