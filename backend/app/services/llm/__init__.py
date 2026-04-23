"""
LLM 서비스 패키지 — llm_service.py를 SRP 원칙에 따라 분리.

서브 모듈:
  prompt_templates   — 룰별 L2/DOC 프롬프트 템플릿 + 고위험 규칙 목록
  gemini_client      — Gemini/OpenAI/Local LLM 호출 + JSON 파싱 + 재시도
  candidate_selector — L2 대상 선정 (버킷 방식 + L1.5 이름 필터)
  code_context       — 코드 절삭 (symbol_graph 연동)
  prompt_builder     — 단일/배치/재판정 프롬프트 빌더 + 구조화 증거
  l2_judge           — 메인 L2 실행 (run_l2_contextualizer)
  doc_judge          — DOC L2 판정 (run_doc_l2_contextualizer)
  patch_generator    — 코드/문서 패치 생성
  summary_generator  — AI 종합 평가 요약
"""
