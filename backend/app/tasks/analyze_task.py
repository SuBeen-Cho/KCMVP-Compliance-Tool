"""
Celery 태스크: 비동기 분석 파이프라인.
- create_analyze_job 호출 후 이 태스크가 실행되어 전처리 → L1 → L2 → L3 → 패치 → 보고서 생성.
"""
# from celery import Celery
# from app.config import settings
# from app.services.upload_service import get_job_root
# from app.services.preprocess_service import run_preprocess
# from app.services.rule_engine_service import run_rule_engine
# from app.services.llm_service import run_l2_contextualizer, generate_patch_for_violation
# from app.services.rag_service import extract_evidence_for_violation
# from app.services.report_service import build_summary, write_report_json, write_report_markdown, save_patch

# celery_app = Celery("kcmvp", broker=settings.CELERY_BROKER_URL)

# @celery_app.task(bind=True)
# def run_analysis_pipeline(self, job_id: str, algorithm: str = None, mode: str = None):
#     root = get_job_root(job_id)
#     # 1) 전처리
#     # 2) L1
#     # 3) L2
#     # 4) L3 (근거)
#     # 5) 패치 생성
#     # 6) 보고서 저장
#     return {"job_id": job_id, "status": "completed"}
