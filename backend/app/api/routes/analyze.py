"""
분석 API.
- POST /api/analyze: 업로드 또는 GitHub URL → job_id
- GET /api/analyze/{job_id}: 상태·진행률
- GET /api/analyze/{job_id}/report: 보고서
- GET /api/analyze/{job_id}/patches: 패치 목록·본문
"""
import asyncio
import json
import unicodedata
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date
from pathlib import Path
from fastapi import APIRouter, UploadFile, File, Form, HTTPException, Query
from fastapi.responses import PlainTextResponse, FileResponse
from typing import Optional, List

from app.services.upload_service import (
    create_job_from_upload,
    create_job_from_github,
    get_job_root,
    attach_docs_zip_to_job,
)
from app.services.preprocess_service import run_preprocess
from app.services.preprocess_docs_service import run_doc_preprocess
from app.services.symbol_graph_service import build_symbol_graph
from app.services.rule_engine_service import run_rule_engine
from app.services.doc_rule_service import load_doc_rules, run_doc_rule_engine
from app.services.llm_service import run_l2_contextualizer, generate_patch_for_violation, generate_doc_patch_for_violation, generate_ai_summary
from app.services.rag_service import attach_evidence
from app.services.report_service import (
    post_process_violations, save_patch, build_summary,
    write_report_markdown, write_report_pdf,
)
from app.services.code_slicer import slice_code
from app.services.traceability_service import run_traceability_checks, build_code_index

router = APIRouter()

# backend/rules 경로 (app/api/routes/analyze.py 기준 상위 4단계가 backend)
RULES_DIR = Path(__file__).resolve().parent.parent.parent.parent / "rules"


def _load_trc_rules(rules_dir: Path) -> list:
    """traceability/traceability.yaml 에서 TRC 룰 로드."""
    import yaml
    trc_path = rules_dir / "traceability" / "traceability.yaml"
    if not trc_path.exists():
        return []
    try:
        with open(trc_path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return data.get("rules", []) if isinstance(data, dict) else []
    except Exception as e:
        print(f"[TRC] 룰 로드 실패: {e}")
        return []


@router.post("")
async def create_analyze_job(
    source: Optional[str] = None,  # GitHub URL 또는 "owner/repo"
    file: Optional[UploadFile] = File(None, description="코드 ZIP 파일"),
    design_doc: Optional[UploadFile] = File(
        None, description="기본/상세 설계서 PDF (예: design_main.pdf)"
    ),
    config_doc: Optional[UploadFile] = File(
        None, description="형상관리 문서 PDF (예: config_mgmt.pdf)"
    ),
    test_doc: Optional[UploadFile] = File(
        None, description="시험서 PDF (예: test_report.pdf)"
    ),
    algorithm: Optional[str] = Form(None),  # LEA, ARIA, AES 등
    mode: Optional[str] = Form(None),       # CBC, CTR, GCM 등
):
    """
    분석 작업 생성.
    - source: GitHub URL 또는 owner/repo
    - file: 코드 ZIP 업로드 (source 없을 때 필수)
    - design_doc: 설계서 PDF (선택)
    - config_doc: 형상관리 문서 PDF (선택, 권장)
    - test_doc: 시험서 PDF (선택)
    - algorithm, mode: 적용할 룰셋 필터
    """
    try:
        # 1) 코드 소스 수집 (ZIP 또는 GitHub)
        if file is not None:
            # ZIP 업로드 경로
            content = await file.read()
            job_id = create_job_from_upload(content, file.filename or "upload.zip")
        else:
            # GitHub 경로 (source 사용)
            if not source:
                raise HTTPException(
                    status_code=400, detail="ZIP file required (file) or provide GitHub source"
                )
            try:
                job_id = create_job_from_github(source)
            except ValueError as ve:
                raise HTTPException(status_code=400, detail=str(ve))
            except RuntimeError as re:
                raise HTTPException(status_code=500, detail=str(re))

        root = get_job_root(job_id)

        # 2) 개별 문서 PDF(design/config/test)가 있으면 job/docs/<type>/ 하위에 저장
        async def _save_pdf(upload: Optional[UploadFile], doc_type: str, required_keyword_list):
            if upload is None:
                return
            raw_name = (upload.filename or "").strip()
            # macOS 등에서 한글 파일명이 분해(NFD)형으로 들어오는 경우를 대비해 정규화
            filename = unicodedata.normalize("NFC", raw_name)
            name_lower = filename.lower()
            if not name_lower.endswith(".pdf"):
                raise HTTPException(
                    status_code=400,
                    detail=f"{doc_type} 문서는 PDF(.pdf)만 업로드할 수 있습니다: {filename}",
                )
            # 이름에 해당 문서 종류 키워드가 포함되어 있는지 검사
            if not any(kw in name_lower for kw in required_keyword_list):
                raise HTTPException(
                    status_code=400,
                    detail=f"{doc_type} 문서 파일명에 문서 종류 키워드가 포함되어 있어야 합니다: {filename}",
                )
            content = await upload.read()
            # 실제 저장은 upload_service 유틸을 사용
            from app.services.upload_service import save_single_doc_to_job

            save_single_doc_to_job(job_id=job_id, file_content=content, filename=filename, doc_type=doc_type)

        # 설계서: design / 형상관리: scm / 시험서: test
        # 파일명 예시: "설계서.pdf", "형상관리문서.pdf", "시험서.pdf", "암호모듈+구현+안내서.pdf" 등
        # - 설계서는 실제 현장에서 "안내서", "guide" 등의 이름으로도 많이 쓰이므로 해당 키워드도 허용한다.
        await _save_pdf(design_doc, "design", ["design", "설계", "설계서", "안내서", "guide"])
        await _save_pdf(config_doc, "scm", ["config", "형상", "형상관리", "형상관리문서", "scm"])
        await _save_pdf(test_doc, "test", ["test", "시험", "시험서"])

        # 분석 메타 저장 (보고서 헤더용)
        (root / "job_meta.json").write_text(
            json.dumps({"algorithm": algorithm, "mode": mode}, ensure_ascii=False),
            encoding="utf-8",
        )

        # 3~8) 파이프라인 전체를 스레드풀에서 실행
        # (모든 단계가 동기 블로킹 → asyncio.to_thread로 이벤트 루프 보호)
        result = await asyncio.to_thread(
            _run_pipeline_sync, root, algorithm, mode
        )
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def _write_status(root: Path, step: str, progress: int) -> None:
    """진행률 status.json 기록 — GET /{job_id} 폴링용."""
    try:
        (root / "status.json").write_text(
            json.dumps({"step": step, "progress": progress, "status": "running"},
                       ensure_ascii=False),
            encoding="utf-8",
        )
    except Exception:
        pass


def _run_pipeline_sync(root: Path, algorithm: Optional[str], mode: Optional[str]) -> dict:
    """동기 분석 파이프라인 — asyncio.to_thread() 안에서 실행."""
    from collections import defaultdict as _defaultdict
    from app.services.llm_service import run_doc_l2_contextualizer

    # 3) 코드 전처리
    _write_status(root, "preprocess", 15)
    preprocess_result = run_preprocess(root)
    (root / "preprocess_result.json").write_text(
        json.dumps(preprocess_result, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    # 4) 심볼 그래프 (libclang 향상 경로 우선, fallback → pycparser)
    _write_status(root, "symbol_graph", 30)
    symbol_graph = build_symbol_graph(preprocess_result, src_root=root)
    (root / "symbol_graph.json").write_text(
        json.dumps(symbol_graph, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    # 5) L1 룰 엔진
    _write_status(root, "rule_engine", 45)
    violations_l1 = run_rule_engine(
        preprocess_result,
        RULES_DIR,
        job_root=root,
        algorithms=[algorithm] if algorithm else None,
        modes=[mode] if mode else None,
        symbol_graph=symbol_graph,
    )

    # 6) L2 LLM
    _write_status(root, "l2_llm", 60)
    l2_rejected_keys: set = set()
    violations_l2 = run_l2_contextualizer(
        preprocess_result=preprocess_result,
        l1_violations=violations_l1,
        rules_meta={"algorithm": algorithm, "mode": mode},
        _rejected_tracker=l2_rejected_keys,
        symbol_graph=symbol_graph,  # Phase 1: Structured Evidence
    )
    merged_violations = post_process_violations(
        violations_l1, violations_l2, l2_rejected_keys=l2_rejected_keys
    )
    final_violations = attach_evidence(merged_violations, top_k=2)

    (root / "violations.json").write_text(
        json.dumps(final_violations, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    # 6-d) 패치 생성 (병렬 처리: max 5 동시 호출, Gemini RPM 한도 고려)
    _write_status(root, "patches", 72)
    _MAX_PATCH_TOTAL = 20
    _MAX_PATCH_PER_CAT = 3
    _PATCH_MAX_WORKERS = 5

    def _patch_priority(v):
        conf_rank = 0 if (v.get("confidence") == "확정") else 1
        sev_rank  = 0 if (v.get("severity") or "").lower() == "high" else (
                    1 if (v.get("severity") or "").lower() == "medium" else 2)
        return (conf_rank, sev_rank)

    # 1단계: 패치 대상 선정 (순차 — 스니펫 추출은 dict 조회라 빠름)
    _patch_tasks: list = []
    _cat_counts: dict = _defaultdict(int)
    for v in sorted(final_violations, key=_patch_priority):
        if len(_patch_tasks) >= _MAX_PATCH_TOTAL:
            break
        sev = (v.get("severity") or "").lower()
        if sev not in ("high", "medium"):
            continue
        _rule_id = v.get("rule_id") or "UNKNOWN"
        _cat = _rule_id.split("-")[0]
        if _cat_counts[_cat] >= _MAX_PATCH_PER_CAT:
            continue
        _file = v.get("file") or ""
        _line = v.get("line") or 0
        _msg  = v.get("message") or ""
        _evidence = v.get("evidence") or ""
        _snippet = ""
        for fi in preprocess_result.get("files", []):
            fp = fi.get("path") or ""
            if fp == _file or fp.endswith(_file) or _file.endswith(fp):
                lines = fi.get("lines")
                if lines and _line:
                    _snippet = slice_code(lines, _line, v.get("pattern_type") or "regex") or ""
                break
        _patch_tasks.append((_rule_id, _file, _line, _snippet, _msg, _evidence))
        _cat_counts[_cat] += 1

    # 2단계: LLM 호출 병렬화
    with ThreadPoolExecutor(max_workers=_PATCH_MAX_WORKERS) as _executor:
        _futures = {
            _executor.submit(
                generate_patch_for_violation,
                file_path=_file, line=_line, snippet=_snippet,
                violation_message=_msg, rule_id=_rule_id, evidence=_evidence,
            ): (_rule_id, _file, _line)
            for (_rule_id, _file, _line, _snippet, _msg, _evidence) in _patch_tasks
        }
        for _future in as_completed(_futures):
            _rule_id, _file, _line = _futures[_future]
            try:
                patch_md = _future.result()
            except Exception:
                patch_md = f"## {_file}:{_line}\n\n_(패치 생성 실패)_"
            save_patch(root, _rule_id, _file, _line, patch_md)

    # 7) 문서 전처리 + DOC 룰
    _write_status(root, "doc_preprocess", 82)
    doc_preprocess = run_doc_preprocess(root)
    (root / "doc_preprocess_result.json").write_text(
        json.dumps(doc_preprocess, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    doc_rules = load_doc_rules(RULES_DIR)
    violations_doc = run_doc_rule_engine(doc_preprocess, doc_rules)
    violations_doc = run_doc_l2_contextualizer(violations_doc, doc_preprocess)
    violations_doc = attach_evidence(violations_doc, top_k=2)

    # 문서 패치 생성 (병렬)
    _doc_patch_tasks: list = []
    for v in violations_doc:
        if len(_doc_patch_tasks) >= 10:
            break
        if (v.get("severity") or "").lower() != "high":
            continue
        _rule_id = v.get("rule_id") or "UNKNOWN"
        _msg = v.get("message") or ""
        _doc_type = v.get("doc_type") or "design"
        _evidence = v.get("evidence") or ""
        _doc_patch_tasks.append((_rule_id, _msg, _doc_type, _evidence))

    with ThreadPoolExecutor(max_workers=_PATCH_MAX_WORKERS) as _doc_executor:
        _doc_futures = {
            _doc_executor.submit(
                generate_doc_patch_for_violation,
                rule_id=_rule_id, violation_message=_msg,
                doc_type=_doc_type, evidence=_evidence,
            ): (_rule_id, _doc_type)
            for (_rule_id, _msg, _doc_type, _evidence) in _doc_patch_tasks
        }
        for _future in as_completed(_doc_futures):
            _rule_id, _doc_type = _doc_futures[_future]
            try:
                doc_patch_md = _future.result()
            except Exception:
                doc_patch_md = f"## {_rule_id}\n\n_(문서 패치 생성 실패)_"
            save_patch(root, _rule_id, f"doc_{_doc_type}", 0, doc_patch_md)

    # 8) TRC
    _write_status(root, "trc", 92)
    trc_rules = _load_trc_rules(RULES_DIR)
    violations_trc: list = []
    if trc_rules:
        design_sections = [s for s in doc_preprocess.get("sections", [])
                           if (s.get("doc_type") or "").lower() == "design"]
        test_sections   = [s for s in doc_preprocess.get("sections", [])
                           if (s.get("doc_type") or "").lower() == "test"]
        code_index = build_code_index(preprocess_result)
        violations_trc = run_traceability_checks(
            design_doc={"sections": design_sections},
            code_index=code_index,
            test_doc={"sections": test_sections},
            rules=trc_rules,
            symbol_graph=symbol_graph,  # TRC-004: API 시그니처 매핑
        )

    all_violations = [*final_violations, *violations_doc, *violations_trc]
    (root / "violations.json").write_text(
        json.dumps(all_violations, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    file_count = len(preprocess_result.get("files", []))
    return {
        "job_id": str(root.name),
        "status": "completed",
        "preprocess": {
            "file_count": file_count,
            "errors_count": len(preprocess_result.get("errors", [])),
        },
        "violations": all_violations,
        "violations_count": len(all_violations),
    }


@router.get("/{job_id}")
def get_analyze_status(job_id: str):
    """분석 상태 및 진행률. status.json(단계별) → violations.json → fallback 순으로 반환."""
    root = get_job_root(job_id).resolve()
    if not root.exists():
        raise HTTPException(status_code=404, detail="Job not found")

    violations_file = root / "violations.json"

    # 완료 확인 (violations.json 존재 = 파이프라인 전체 완료)
    if violations_file.is_file():
        return {
            "job_id": job_id,
            "status": "completed",
            "progress": 100,
            "current_step": "report",
        }

    # 진행 중: status.json 에서 현재 단계 읽기
    status_file = root / "status.json"
    if status_file.is_file():
        try:
            data = json.loads(status_file.read_text(encoding="utf-8"))
            return {
                "job_id": job_id,
                "status": data.get("status", "running"),
                "progress": data.get("progress", 10),
                "current_step": data.get("step", ""),
            }
        except Exception:
            pass

    # fallback: 아직 status.json 없음 (업로드 직후)
    return {
        "job_id": job_id,
        "status": "running",
        "progress": 10,
        "current_step": "upload",
    }


@router.get("/{job_id}/report")
def get_report(job_id: str):
    """최종 분석 보고서 (JSON).

    - violations.json을 읽어 위반 목록/요약 반환
    - preprocess_result.json에서 코드 파일 경로 리스트를 함께 반환 (프론트 파일 트리 용도)
    - docs/ 및 doc_preprocess_result.json 정보를 바탕으로 문서 파일 메타데이터와 상태를 함께 반환
    """
    root = get_job_root(job_id).resolve()
    report_path = root / "violations.json"
    if not root.exists() or not report_path.is_file():
        raise HTTPException(status_code=404, detail="Report not ready or job not found")

    try:
        raw = report_path.read_text(encoding="utf-8")
        violations = json.loads(raw)
    except (json.JSONDecodeError, OSError) as e:
        raise HTTPException(status_code=500, detail=f"Failed to read report: {e}")

    # (file, line, rule_id) 기준 중복 제거 — rule_id만으로 dedup하면 TRC-001 등 다건 위반이 1건으로 축소됨
    _seen: set = set()
    _deduped = []
    for v in violations:
        rid = (v.get("rule_id") or "").strip()
        file_ = (v.get("file") or "").strip()
        line_ = v.get("line")
        key = (rid, file_, line_)
        if key in _seen:
            continue
        _seen.add(key)
        _deduped.append(v)
    violations = _deduped

    # confidence 필드 없는 항목 보완 (이전 violations.json 하위 호환)
    from app.services.report_service import _confidence as _conf
    for v in violations:
        if "confidence" not in v:
            v["confidence"] = _conf(v)

    # 요약 정보 (confidence 기반)
    summary = build_summary(violations)

    # 전처리 결과에서 전체 코드 파일 경로 수집 (위반이 없는 파일도 포함)
    files: list[str] = []
    preprocess_path = root / "preprocess_result.json"
    if preprocess_path.is_file():
        try:
            pre_raw = preprocess_path.read_text(encoding="utf-8")
            pre = json.loads(pre_raw)
            for item in pre.get("files", []):
                path = item.get("path")
                if not isinstance(path, str):
                    continue
                try:
                    p = Path(path)
                    if p.is_absolute():
                        rel = p.resolve().relative_to(root)
                    else:
                        rel = (root / path).resolve().relative_to(root)
                    files.append(str(rel).replace("\\", "/"))
                except Exception:
                    files.append(path)
        except (json.JSONDecodeError, OSError):
            # 파일 트리는 품질 저하일 뿐 치명적이지 않으므로 조용히 무시
            files = []

    # docs/ 디렉터리에서 문서 파일 목록 수집 (설계서/형상관리/시험서/매뉴얼 구분)
    docs_root = (root / "docs").resolve()
    docs = {"design": [], "scm": [], "test": [], "manual": []}
    if docs_root.is_dir():
        for doc_type in list(docs.keys()):
            type_root = (docs_root / doc_type).resolve()
            if not type_root.is_dir():
                continue
            for fp in sorted(type_root.rglob("*")):
                if not fp.is_file():
                    continue
                try:
                    rel = fp.resolve().relative_to(root)
                    docs[doc_type].append(str(rel).replace("\\", "/"))
                except Exception:
                    docs[doc_type].append(str(fp))

    # doc_preprocess_result.json 을 바탕으로 문서 분석 가능 여부 상태 생성
    doc_status = {
        "design": "not_provided",
        "config_mgmt": "not_provided",
        "test": "not_provided",
        "manual": "not_provided",
    }
    doc_pre_path = root / "doc_preprocess_result.json"
    if doc_pre_path.is_file():
        try:
            doc_raw = doc_pre_path.read_text(encoding="utf-8")
            doc_pre = json.loads(doc_raw)
            for section in doc_pre.get("sections", []):
                dt = (section.get("doc_type") or "").lower()
                if dt == "design":
                    doc_status["design"] = "ok"
                elif dt in ("scm", "config", "config_mgmt"):
                    doc_status["config_mgmt"] = "ok"
                elif dt == "test":
                    doc_status["test"] = "ok"
                elif dt == "manual":
                    doc_status["manual"] = "ok"
        except (json.JSONDecodeError, OSError):
            # 문서 전처리 결과가 깨져 있어도 코드 분석은 계속 사용할 수 있도록 조용히 무시
            pass

    # meta 정보 수집 (보고서 헤더용)
    meta: dict = {"date": str(date.today()), "file_count": len(files)}
    job_meta_path = root / "job_meta.json"
    if job_meta_path.is_file():
        try:
            jm = json.loads(job_meta_path.read_text(encoding="utf-8"))
            meta.update({
                "algorithm": jm.get("algorithm"),
                "mode":      jm.get("mode"),
            })
        except Exception:
            pass

    # AI 종합 요약 생성
    ai_summary = None
    try:
        ai_summary = generate_ai_summary(violations, summary, meta)
        if ai_summary:
            print("[Report] AI 종합 요약 생성 완료")
            # PDF 재생성 시 사용할 수 있도록 파일로 저장
            try:
                (root / "ai_summary.txt").write_text(ai_summary, encoding="utf-8")
            except Exception:
                pass
    except Exception as e:
        print(f"[Report] AI 요약 생성 실패: {e}")

    # 마크다운 보고서 생성/갱신
    try:
        report_obj = {"violations": violations, "summary": summary, "meta": meta, "ai_summary": ai_summary}
        write_report_markdown(root, report_obj)
    except Exception as e:
        print(f"[Report] markdown 생성 실패: {e}")

    return {
        "job_id": job_id,
        "summary": summary,
        "violations": violations,
        "files": files,
        "docs": docs,
        "doc_status": doc_status,
        "meta": meta,
        "ai_summary": ai_summary,
    }


@router.get("/{job_id}/report.pdf")
def get_report_pdf(job_id: str):
    """
    PDF 보고서 다운로드.

    - 이미 생성된 report.pdf 가 있으면 즉시 반환.
    - 없으면 violations.json 을 읽어 PDF 를 즉석 생성 후 반환.
    """
    root = get_job_root(job_id).resolve()
    if not root.exists():
        raise HTTPException(status_code=404, detail="Job not found")

    pdf_path = root / "report.pdf"

    # 기존 PDF가 없거나 violations.json이 더 최신이면 재생성
    violations_path = root / "violations.json"
    if not pdf_path.exists() or (
        violations_path.exists()
        and violations_path.stat().st_mtime > pdf_path.stat().st_mtime
    ):
        if not violations_path.is_file():
            raise HTTPException(status_code=404, detail="Report not ready")
        try:
            violations = json.loads(violations_path.read_text(encoding="utf-8"))
            from app.services.report_service import build_summary, _confidence as _conf
            for v in violations:
                if "confidence" not in v:
                    v["confidence"] = _conf(v)
            summary = build_summary(violations)
            meta: dict = {}
            job_meta_path = root / "job_meta.json"
            if job_meta_path.is_file():
                try:
                    meta = json.loads(job_meta_path.read_text(encoding="utf-8"))
                except Exception:
                    pass
            from datetime import date as _date
            meta.setdefault("date", str(_date.today()))
            # ai_summary 파일이 있으면 포함
            ai_summary_text = ""
            ai_summary_path = root / "ai_summary.txt"
            if ai_summary_path.is_file():
                try:
                    ai_summary_text = ai_summary_path.read_text(encoding="utf-8")
                except Exception:
                    pass
            report_obj = {"violations": violations, "summary": summary, "meta": meta, "ai_summary": ai_summary_text}
            write_report_pdf(root, report_obj)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"PDF 생성 실패: {e}")

    if not pdf_path.is_file():
        raise HTTPException(status_code=500, detail="PDF 파일 생성에 실패했습니다")

    return FileResponse(
        path=str(pdf_path),
        media_type="application/pdf",
        filename=f"kcmvp_report_{job_id}.pdf",
    )


@router.get("/{job_id}/file")
def get_file(
    job_id: str,
    path: str = Query(..., description="job 루트 기준 상대 파일 경로"),
):
    """
    단일 소스 파일 내용 반환.
    - path: job 루트 기준 상대 경로 (report.files 또는 violations.file에 있는 값)
    """
    root = get_job_root(job_id).resolve()
    if not root.exists():
        raise HTTPException(status_code=404, detail="Job not found")

    if not path:
        raise HTTPException(status_code=400, detail="path query parameter is required")

    # 상대 경로만 허용하고, job 루트 밖으로 나가는 경로는 차단
    target = (root / path).resolve()
    try:
        if not target.is_file() or not target.is_relative_to(root):
            raise HTTPException(status_code=404, detail="File not found")
    except AttributeError:
        # Python < 3.9 호환 (is_relative_to 미지원 시 수동 검사)
        try:
            target.relative_to(root)
        except ValueError:
            raise HTTPException(status_code=404, detail="File not found")
        if not target.is_file():
            raise HTTPException(status_code=404, detail="File not found")

    try:
        content = target.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        raise HTTPException(status_code=500, detail=f"Failed to read file: {e}")

    return {"job_id": job_id, "path": path, "content": content}


@router.get("/{job_id}/patches")
def get_patches(job_id: str):
    """패치 파일 목록 및 본문. job 폴더의 patches/ 하위 .md 파일을 읽어 반환."""
    root = get_job_root(job_id).resolve()
    if not root.exists():
        raise HTTPException(status_code=404, detail="Job not found")

    patches_dir = root / "patches"
    if not patches_dir.is_dir():
        return {"job_id": job_id, "patches": []}

    patches = []
    for path in sorted(patches_dir.glob("*.md")):
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
            patches.append({"path": path.name, "content": content})
        except OSError:
            continue

    return {"job_id": job_id, "patches": patches}


@router.get("/{job_id}/files")
def list_files(job_id: str) -> dict:
    """
    분석 대상 파일 목록.
    - preprocess_result.json 의 files[].path 를 사용해 상대 경로 리스트를 생성한다.
    - UI 의 파일 트리에서 사용.
    """
    root = get_job_root(job_id).resolve()
    if not root.exists():
        raise HTTPException(status_code=404, detail="Job not found")

    preprocess_path = root / "preprocess_result.json"
    if not preprocess_path.is_file():
        raise HTTPException(status_code=404, detail="Preprocess result not found")

    try:
        raw = preprocess_path.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (json.JSONDecodeError, OSError) as e:
        raise HTTPException(status_code=500, detail=f"Failed to read preprocess result: {e}")

    files: List[str] = []
    for f in data.get("files", []):
        path_str = f.get("path")
        if not path_str:
            continue
        p = Path(path_str)
        # job 루트 하위 상대 경로로 정규화
        try:
            rel = p.resolve().relative_to(root)
        except Exception:
            # 이미 상대 경로이거나 다른 형식인 경우 그대로 사용
            rel = p
        files.append(str(rel))

    # 중복 제거 및 정렬
    uniq_files = sorted({*files})
    return {"job_id": job_id, "files": uniq_files}


@router.get("/{job_id}/ast")
def get_file_ast(
    job_id: str,
    path: str = Query(..., description="job 루트 기준 상대 파일 경로"),
):
    """
    단일 파일에 대한 전처리 AST 반환.
    - preprocess_result.json 의 files[].path 와 일치하는 항목의 ast 객체 반환.
    - UI에서 "전체 파일 분석 AST 보기"용.
    """
    root = get_job_root(job_id).resolve()
    if not root.exists():
        raise HTTPException(status_code=404, detail="Job not found")

    preprocess_path = root / "preprocess_result.json"
    if not preprocess_path.is_file():
        raise HTTPException(status_code=404, detail="Preprocess result not found")

    try:
        raw = preprocess_path.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (json.JSONDecodeError, OSError) as e:
        raise HTTPException(status_code=500, detail=f"Failed to read preprocess result: {e}")

    # path 정규화 (슬래시 통일)
    path_norm = path.replace("\\", "/").strip()
    if not path_norm:
        raise HTTPException(status_code=400, detail="path is required")

    for f in data.get("files", []):
        p = (f.get("path") or "").replace("\\", "/")
        if p == path_norm or p.endswith("/" + path_norm):
            return {"job_id": job_id, "path": path_norm, "ast": f.get("ast") or {}}

    # 상대 경로로 저장된 항목과 비교 (job 루트 기준)
    for f in data.get("files", []):
        p = f.get("path") or ""
        try:
            rel = Path(p).resolve().relative_to(root)
            if str(rel).replace("\\", "/") == path_norm:
                return {"job_id": job_id, "path": path_norm, "ast": f.get("ast") or {}}
        except Exception:
            if p.replace("\\", "/") == path_norm:
                return {"job_id": job_id, "path": path_norm, "ast": f.get("ast") or {}}

    raise HTTPException(status_code=404, detail=f"No AST found for path: {path_norm}")


@router.get("/{job_id}/symbol-graph")
def get_symbol_graph(job_id: str):
    """
    파일 전체 흐름(심볼 연결 그래프) 반환.
    - definitions: 함수별 정의 위치
    - calls: 호출 목록 (caller_file, caller_line, callee_name)
    - call_graph: 호출 + 정의 파일 연결 (defined_in, def_line)
    - files_with_clearing_call: 제거 호출을 직접 포함한 파일 목록
    """
    root = get_job_root(job_id).resolve()
    if not root.exists():
        raise HTTPException(status_code=404, detail="Job not found")

    path = root / "symbol_graph.json"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Symbol graph not found (run analysis first)")

    try:
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (json.JSONDecodeError, OSError) as e:
        raise HTTPException(status_code=500, detail=f"Failed to read symbol graph: {e}")

    return {"job_id": job_id, **data}


@router.get("/{job_id}/docs")
def get_doc_preprocess(job_id: str):
    """
    문서 전처리 결과(doc_preprocess_result.json)를 그대로 반환.
    - sections[].text 에 텍스트 기반 PDF에서 추출한 한국어/영문 본문이 포함된다.
    """
    root = get_job_root(job_id).resolve()
    if not root.exists():
        raise HTTPException(status_code=404, detail="Job not found")

    doc_pre_path = root / "doc_preprocess_result.json"
    if not doc_pre_path.is_file():
        raise HTTPException(status_code=404, detail="Doc preprocess result not found")

    try:
        raw = doc_pre_path.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (json.JSONDecodeError, OSError) as e:
        raise HTTPException(status_code=500, detail=f"Failed to read doc preprocess: {e}")

    return {"job_id": job_id, **data}


@router.get("/{job_id}/file/raw")
def get_file_content(job_id: str, path: str = Query(..., description="job 루트 기준 상대 파일 경로")):
    """
    단일 파일 원본 코드 반환.
    - path: 예) "src/main.c", "include/lea.h"
    - 안전을 위해 job 루트 밖 경로는 차단.
    """
    root = get_job_root(job_id).resolve()
    if not root.exists():
        raise HTTPException(status_code=404, detail="Job not found")

    target = (root / path).resolve()
    try:
        # 디렉터리 트래버설 방지: 항상 job 루트 하위만 허용
        target.relative_to(root)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid file path")

    if not target.is_file():
        raise HTTPException(status_code=404, detail="File not found")

    try:
        content = target.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        raise HTTPException(status_code=500, detail=f"Failed to read file: {e}")

    return PlainTextResponse(content)
