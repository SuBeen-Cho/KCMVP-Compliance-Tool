"""
로컬 PDF 설계서 전처리 진단 스크립트.

목표
- backend/testdata/*.pdf 를 job/docs/design/ 아래로 복사한 뒤
  run_doc_preprocess 를 실행해서:
  - 각 PDF별 text 길이
  - 섹션 개수 / 섹션 제목 샘플
  - 표 개수
를 요약 출력하고, 전체 결과를 JSON으로 저장한다.

사용법
  cd backend
  python scripts/test_doc_preprocess_local.py
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Any, List

BACKEND = Path(__file__).resolve().parent.parent
TESTDATA = BACKEND / "testdata"
JOB_ROOT = BACKEND / "storage" / "jobs" / "doc_preprocess_local"

import sys

sys.path.insert(0, str(BACKEND))

from app.services.preprocess_docs_service import run_doc_preprocess  # type: ignore  # noqa


def _prepare_job_root() -> Path:
    """backend/testdata/*.pdf 를 JOB_ROOT/docs/design/ 로 복사한다."""
    if JOB_ROOT.is_dir():
        # 이전 실행 잔여물 삭제는 과감히 생략(덮어쓰기)하고, 폴더만 재사용
        pass
    JOB_ROOT.mkdir(parents=True, exist_ok=True)

    docs_design = JOB_ROOT / "docs" / "design"
    docs_design.mkdir(parents=True, exist_ok=True)

    pdfs: List[Path] = []
    for p in TESTDATA.iterdir():
        if p.is_file() and p.suffix.lower() == ".pdf":
            pdfs.append(p)

    for src in pdfs:
        dst = docs_design / src.name
        if not dst.exists():
            dst.write_bytes(src.read_bytes())

    print(f"JOB_ROOT: {JOB_ROOT}")
    print("design PDFs:")
    for p in sorted(pdfs):
        print(" -", p.name)

    return JOB_ROOT


def main() -> None:
    root = _prepare_job_root()
    result: Dict[str, Any] = run_doc_preprocess(root)

    sections: List[Dict[str, Any]] = result.get("sections") or []
    errors: List[Dict[str, Any]] = result.get("errors") or []

    print("\n=== run_doc_preprocess 결과 요약 ===")
    print("sections:", len(sections), "errors:", len(errors))

    # 파일별로 섹션/텍스트/표 수를 요약
    by_file: Dict[str, Dict[str, Any]] = {}
    for s in sections:
        file_key = s.get("file") or ""
        if not file_key:
            continue
        info = by_file.setdefault(
            file_key.split("#", 1)[0],
            {"sections": 0, "titles": [], "total_text_len": 0, "tables": 0},
        )
        info["sections"] += 1
        title = (s.get("title") or "").strip()
        if title and len(info["titles"]) < 5:
            info["titles"].append(title)
        text = s.get("text") or ""
        info["total_text_len"] += len(text)
        tables = s.get("tables") or []
        if tables:
            info["tables"] += len(tables)

    print("\n=== PDF별 섹션/텍스트/표 요약 ===")
    for file_key, info in sorted(by_file.items()):
        print(f"- {file_key}")
        print(f"  섹션 수: {info['sections']}, 텍스트 길이 합계: {info['total_text_len']}, 표 수: {info['tables']}")
        if info["titles"]:
            print("  섹션 제목 샘플:")
            for t in info["titles"]:
                print("    •", t)

    debug_path = JOB_ROOT / "doc_preprocess_local_result.json"
    debug_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n전체 결과 JSON 저장: {debug_path}")


if __name__ == "__main__":
    main()

