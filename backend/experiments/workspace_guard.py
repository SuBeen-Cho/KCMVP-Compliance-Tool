"""Fail closed before an experiment writes outside this Git workspace."""

from __future__ import annotations

from pathlib import Path
import subprocess


BACKEND_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = BACKEND_ROOT.parent
PRIVATE_ROOT = Path("/private/tmp")


class WorkspaceBoundaryError(ValueError):
    pass


def verify_repository_identity() -> Path:
    result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"], cwd=REPOSITORY_ROOT,
        check=True, capture_output=True, text=True,
    )
    discovered = Path(result.stdout.strip()).resolve(strict=True)
    expected = REPOSITORY_ROOT.resolve(strict=True)
    if discovered != expected:
        raise WorkspaceBoundaryError("module path and Git repository root disagree")
    return expected


def guarded_output_path(path: Path, *, private: bool = False) -> Path:
    """Permit repository outputs and, when explicit, private /private/tmp data."""
    repository = verify_repository_identity()
    candidate = path.expanduser()
    if not candidate.is_absolute():
        candidate = repository / candidate
    parent = candidate.parent.resolve(strict=True)  # also detects symlink escape
    resolved = parent / candidate.name
    roots = [repository]
    if private:
        roots.append(PRIVATE_ROOT.resolve(strict=True))
    if not any(resolved == root or root in resolved.parents for root in roots):
        raise WorkspaceBoundaryError("artifact output is outside the approved workspace")
    return resolved
