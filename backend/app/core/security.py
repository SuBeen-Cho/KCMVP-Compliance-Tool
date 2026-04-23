"""
보안·유틸 (해시, job_id 생성 등).
- 실제 구현 시: job_id는 UUID4 또는 nanoid 사용.
"""
import uuid


def generate_job_id() -> str:
    """분석 작업 고유 ID 생성."""
    return str(uuid.uuid4())
