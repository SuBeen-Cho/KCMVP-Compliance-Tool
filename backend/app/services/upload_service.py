"""
UploadService: 소스 수집.
- GitHub 클론 또는 ZIP 업로드 해제 → job 전용 디렉토리 생성.
"""
import io
import subprocess
import zipfile
from pathlib import Path
from typing import Optional

from app.config import settings
from app.core.security import generate_job_id


def get_job_root(job_id: str) -> Path:
    """job_id에 해당하는 스토리지 루트 경로."""
    return Path(settings.STORAGE_ROOT) / settings.JOB_DATA_DIR / job_id


def create_job_from_upload(file_content: bytes, filename: str) -> str:
    """
    업로드된 ZIP을 저장하고 압축 해제.
    - file_content: ZIP 파일의 바이트 내용 (웹에서 업로드한 파일)
    - filename: 원본 파일명 (확장자 확인용)
    - job_id 전용 폴더를 만든 뒤, 그 안에 ZIP 내용을 풀어 넣습니다.
    Returns: job_id
    """
    job_id = generate_job_id()
    root = get_job_root(job_id)
    root.mkdir(parents=True, exist_ok=True)

    # ZIP 압축 해제: file_content(바이트) → job 루트(root) 안에 코드 파일들 생성
    _extract_zip_into_root(file_content=file_content, root=root)

    return job_id


def create_job_from_github(repo_url: str, branch: Optional[str] = None) -> str:
    """
    GitHub 저장소 클론.
    Returns: job_id
    """
    repo_url = (repo_url or "").strip()
    if not repo_url:
        raise ValueError("GitHub repo URL or owner/repo is required")

    # 간단한 정규화: http/https/git URL이면 그대로 사용, 아니면 owner/repo 형식으로 가정
    if repo_url.startswith(("http://", "https://", "git@")):
        clone_url = repo_url
    else:
        # "owner/repo" 또는 "repo" 형식 처리
        if "/" in repo_url:
            clone_url = f"https://github.com/{repo_url}.git"
        else:
            # 소유자가 없으면 모호하므로 에러 처리
            raise ValueError("Invalid GitHub repo identifier. Use full URL or owner/repo format.")

    job_id = generate_job_id()
    root = get_job_root(job_id)
    root.mkdir(parents=True, exist_ok=True)

    # git clone 실행 (얕은 클론)
    cmd = ["git", "clone", "--depth", "1"]
    if branch:
        cmd += ["--branch", branch]
    cmd += [clone_url, str(root)]

    try:
        subprocess.run(cmd, check=True, cwd=str(root.parent))
    except subprocess.CalledProcessError as exc:
        # 실패 시 job 디렉터리 정리
        try:
            if root.exists():
                for child in root.rglob("*"):
                    if child.is_file():
                        child.unlink(missing_ok=True)
                for child in sorted(root.rglob("*"), reverse=True):
                    if child.is_dir():
                        child.rmdir()
                root.rmdir()
        except OSError:
            # 정리 실패는 치명적이지 않으므로 무시
            pass
        raise RuntimeError(f"git clone failed: {exc}") from exc

    return job_id


def _extract_zip_into_root(file_content: bytes, root: Path) -> None:
    """
    공통 ZIP 해제 유틸리티.
    - file_content: ZIP 파일 바이트
    - root: 압축을 풀 최상위 디렉터리
    """
    root_resolved = root.resolve()
    with zipfile.ZipFile(io.BytesIO(file_content), "r") as zf:
        for member in zf.namelist():
            # 경로 조작(../ 등) 방지: root 밖으로 나가는 경로는 건너뜀
            path = Path(member)
            if path.is_absolute() or ".." in path.parts:
                continue
            target = (root / path).resolve()
            try:
                if not target.is_relative_to(root_resolved):
                    continue
            except AttributeError:
                # Python < 3.9 호환: is_relative_to 미지원 시 수동 검사
                try:
                    target.relative_to(root_resolved)
                except ValueError:
                    continue
            if member.endswith("/"):
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(zf.read(member))


def attach_docs_zip_to_job(job_id: str, file_content: bytes, filename: str) -> None:
    """
    기존 job_id에 대해 별도로 업로드된 문서 ZIP을 docs/ 하위에 해제한다.
    - job 루트가 없으면 예외는 발생시키지 않고 조용히 return (상위에서 처리).
    - filename은 현재는 확장자 체크 정도에만 사용 가능하며, 구조에는 영향 주지 않음.
    """
    root = get_job_root(job_id)
    if not root.exists():
        return

    docs_root = root / "docs"
    docs_root.mkdir(parents=True, exist_ok=True)
    _extract_zip_into_root(file_content=file_content, root=docs_root)


def save_single_doc_to_job(job_id: str, file_content: bytes, filename: str, doc_type: str) -> None:
    """
    단일 문서 파일을 job/docs/{doc_type}/ 하위에 저장한다.
    - doc_type: "design" | "scm" | "test" | "manual" 등
    """
    root = get_job_root(job_id)
    if not root.exists():
        return

    # docs/<doc_type>/ 디렉터리 생성
    safe_type = (doc_type or "unknown").strip().lower()
    docs_root = (root / "docs" / safe_type).resolve()
    docs_root.mkdir(parents=True, exist_ok=True)

    # 파일 이름은 그대로 사용하되, 간단히 경로 조작 방지
    name = (filename or "").strip() or f"{safe_type}.pdf"
    path = Path(name).name  # 디렉터리 제거
    target = docs_root / path
    target.write_bytes(file_content)
