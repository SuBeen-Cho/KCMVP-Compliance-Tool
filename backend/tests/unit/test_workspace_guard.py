from pathlib import Path

import pytest

from experiments.workspace_guard import (
    REPOSITORY_ROOT, WorkspaceBoundaryError, guarded_output_path,
    verify_repository_identity,
)


def test_repository_identity_comes_from_module_and_git() -> None:
    assert verify_repository_identity() == REPOSITORY_ROOT.resolve()


def test_public_output_cannot_reach_sibling_workspace(tmp_path: Path) -> None:
    allowed = REPOSITORY_ROOT / "backend/evaluation/guard-test.json"
    assert guarded_output_path(allowed) == allowed
    with pytest.raises(WorkspaceBoundaryError):
        guarded_output_path(tmp_path / "outside.json")


def test_private_output_is_explicitly_limited() -> None:
    allowed = Path("/private/tmp/kcmvp-guard-test.json")
    assert guarded_output_path(allowed, private=True) == allowed


def test_symlink_parent_cannot_escape(tmp_path: Path) -> None:
    link = REPOSITORY_ROOT / "backend/evaluation/.guard-escape-link"
    try:
        link.symlink_to(tmp_path, target_is_directory=True)
        with pytest.raises(WorkspaceBoundaryError):
            guarded_output_path(link / "escape.json")
    finally:
        link.unlink(missing_ok=True)
