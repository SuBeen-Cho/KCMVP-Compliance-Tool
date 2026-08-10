"""Capture code, environment, configuration, and artifact identity for a run."""
from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

try:
    from .inventory import build_rule_inventory, sha256_file
except ImportError:  # Support: python backend/experiments/manifest.py
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from experiments.inventory import build_rule_inventory, sha256_file

try:
    from app.config import settings
except ImportError:  # direct-script compatibility
    settings = None


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=repo, check=True, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    return result.stdout.strip()


def _git_bytes(repo: Path, *args: str) -> bytes:
    return subprocess.run(
        ["git", *args], cwd=repo, check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    ).stdout


def _tree_hash(paths: Iterable[Path], root: Path) -> str:
    digest = hashlib.sha256()
    selected = sorted({p for p in paths if p.is_file()})
    if not selected:
        raise ValueError("cannot hash an empty artifact set")
    for path in selected:
        if path.is_symlink():
            raise ValueError(f"symlink is not allowed in an artifact set: {path}")
        resolved = path.resolve()
        relative = resolved.relative_to(root.resolve())
        digest.update(relative.as_posix().encode())
        digest.update(b"\0")
        digest.update(bytes.fromhex(sha256_file(path)))
    return digest.hexdigest()


def build_manifest(repo: Path, inputs: Iterable[Path] = ()) -> dict[str, Any]:
    backend = repo / "backend"
    status_lines = _git(repo, "status", "--porcelain").splitlines()
    tracked_diff = _git_bytes(repo, "diff", "--binary", "HEAD")
    untracked = _git(repo, "ls-files", "--others", "--exclude-standard").splitlines()
    source_suffixes = {".py", ".md", ".json", ".yaml", ".yml", ".toml", ".cfg", ".ini", ".lock", ".sh"}
    safe_untracked = [repo / path for path in untracked if (repo / path).suffix in source_suffixes]
    untracked_hash = _tree_hash(safe_untracked, repo) if safe_untracked else hashlib.sha256(b"").hexdigest()
    workspace_digest = hashlib.sha256(tracked_diff + bytes.fromhex(untracked_hash)).hexdigest()
    prompt_files = list((backend / "app/services/llm").glob("*.py"))
    guideline_files = list((backend / "guidelines").glob("*.md"))
    mapping_files = list((backend / "mapping").glob("*.json"))
    input_items = []
    for index, path in enumerate(inputs, 1):
        if not path.is_file():
            raise FileNotFoundError(path)
        input_items.append({"artifact_id": f"input_{index:03d}", "size": path.stat().st_size, "sha256": sha256_file(path)})
    freeze = subprocess.run(
        [sys.executable, "-m", "pip", "freeze", "--all"], check=True,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    ).stdout
    rule_inventory = build_rule_inventory(backend / "rules")
    return {
        "schema_version": "1.0",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "code": {
            "commit": _git(repo, "rev-parse", "HEAD"),
            "branch": _git(repo, "branch", "--show-current"),
            "dirty": bool(status_lines),
            "changed_entry_count": len(status_lines),
            "tracked_diff_sha256": hashlib.sha256(tracked_diff).hexdigest(),
            "untracked_source_sha256": untracked_hash,
            "workspace_sha256": workspace_digest,
        },
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "requirements_sha256": sha256_file(backend / "requirements.txt"),
            "pip_freeze_sha256": hashlib.sha256(freeze.encode()).hexdigest(),
        },
        "models": {
            "l3_provider": settings.L3_PROVIDER if settings else os.getenv("L3_PROVIDER", "gemini"),
            "gemini_l3_model": settings.GEMINI_L3_MODEL if settings else os.getenv("GEMINI_L3_MODEL", "gemini-2.5-flash-lite"),
            "temperature": 0,
            "seed": 42,
        },
        "artifacts": {
            "inputs": input_items,
            "rules": rule_inventory,
            "rules_tree_sha256": _tree_hash(list((backend / "rules").rglob("*.yaml")), repo),
            "prompts_sha256": _tree_hash(prompt_files, repo),
            "guidelines_sha256": _tree_hash(guideline_files, repo),
            "mapping_sha256": _tree_hash(mapping_files, repo),
            "rag": {
                "use_chroma": settings.RAG_USE_CHROMA if settings else os.getenv("RAG_USE_CHROMA", "false").lower() == "true",
                "embedding_model": settings.RAG_EMBEDDING_MODEL if settings else os.getenv("RAG_EMBEDDING_MODEL", "BAAI/bge-m3"),
                "top_k": settings.RAG_TOP_K if settings else int(os.getenv("RAG_TOP_K", "5")),
            },
        },
    }


def main() -> None:
    repo = Path(__file__).resolve().parents[2]
    print(json.dumps(build_manifest(repo), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
