#!/usr/bin/env python3
"""
AI(L3) 매칭 설정 확인: API 키·모델·프로바이더가 올바르게 로드되는지,
실제 Gemini 호출이 되는지 검사합니다.

실행: backend/ 에서
  python scripts/check_ai_config.py
또는 프로젝트 루트에서
  cd backend && python scripts/check_ai_config.py
"""
import sys
from pathlib import Path

# backend가 path에 있도록
_backend = Path(__file__).resolve().parent.parent
if str(_backend) not in sys.path:
    sys.path.insert(0, str(_backend))

def main():
    print("=== AI(L3) 설정 확인 ===\n")

    # 1) 설정 로드
    try:
        from app.config import settings
    except Exception as e:
        print(f"[실패] 설정 로드 오류: {e}")
        print("  → backend/ 디렉터리에서 실행했는지 확인하세요.")
        return 1

    provider = (settings.L3_PROVIDER or "").strip().lower()
    key = (settings.GOOGLE_API_KEY or "").strip()
    model = (settings.GEMINI_L3_MODEL or "").strip()

    print("1. 환경 변수 로드 (backend/.env)")
    print(f"   L3_PROVIDER    = {repr(provider)}")
    print(f"   GEMINI_L3_MODEL = {repr(model)}")
    if key:
        print(f"   GOOGLE_API_KEY = (설정됨, 길이 {len(key)}자)")
    else:
        print("   GOOGLE_API_KEY = (비어 있음)")

    # 2) Gemini 사용 시 키·모델 검사
    if provider == "gemini":
        if not key:
            print("\n[실패] L3_PROVIDER=gemini 인데 GOOGLE_API_KEY가 비어 있습니다.")
            print("  → backend/.env 에 GOOGLE_API_KEY=발급받은키 를 넣으세요.")
            return 1
        if not model:
            print("\n[실패] GEMINI_L3_MODEL이 비어 있습니다.")
            return 1
        print("\n2. Gemini 설정: 키·모델명 모두 있음 (형식 OK)")
    elif provider == "local":
        print("\n2. L3_PROVIDER=local → 로컬 LLM 사용. 키/모델 검사 생략.")
        return 0
    else:
        print(f"\n2. L3_PROVIDER={provider} → Gemini/local 외 설정. 필요 시 .env에서 gemini 또는 local 로 변경.")
        return 0

    # 3) 실제 API 호출 테스트
    print("\n3. Gemini API 호출 테스트 (짧은 질문 1회)")
    try:
        import google.genai as genai
        client = genai.Client(api_key=key)
        response = client.models.generate_content(
            model=model,
            contents="한 줄로 '연동 성공'이라고만 답하세요.",
        )
        text = getattr(response, "text", None)
        if text and isinstance(text, str):
            print(f"   응답: {text.strip()[:80]}")
            print("   [OK] API 키·모델 이름 모두 정상 동작합니다.")
            return 0
        # 응답에 텍스트가 없는 경우 (블록 등)
        cands = getattr(response, "candidates", None) or []
        if cands:
            finish = getattr(cands[0], "finish_reason", None)
            print(f"   [경고] 응답 텍스트 없음. finish_reason={finish}")
        else:
            print("   [경고] 응답에 candidates 없음.")
    except Exception as e:
        err = str(e)
        print(f"   [실패] {err}")
        if "404" in err or "not found" in err.lower():
            print("   → 모델 ID가 잘못되었을 수 있습니다. 현재: " + model)
            print("   → 공식 문서: https://ai.google.dev/gemini-api/docs/models/gemini-2.5-flash-lite")
        if "403" in err or "API key" in err.lower() or "invalid" in err.lower():
            print("   → API 키가 만료되었거나 권한이 없을 수 있습니다. aistudio.google.com 에서 확인.")
        if "429" in err or "RESOURCE_EXHAUSTED" in err or "quota" in err.lower():
            print("   → 일일 할당량(quota) 초과일 수 있습니다. 내일 다시 시도하거나 유료 플랜 확인.")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
