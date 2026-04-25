"""
분석 Job 모델.
- DB 사용 시 SQLAlchemy 모델로 확장.
- 현재는 Pydantic 스키마와 일치하는 딕셔너리/Redis 저장 형태 가정.
"""
from typing import Optional, List
from enum import Enum


class JobStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


# 예시 필드 (실제는 schemas 또는 ORM 모델로)
# job_id: str
# status: JobStatus
# progress: int  # 0..100
# current_step: str  # upload | preprocess | l1 | l3 | l3 | patch | report
# source_type: str  # github | upload
# source_ref: str   # URL or file path
# algorithm: Optional[str]
# mode: Optional[str]
# created_at: datetime
# error_message: Optional[str]
