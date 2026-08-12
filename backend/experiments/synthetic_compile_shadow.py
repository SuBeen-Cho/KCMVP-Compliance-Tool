"""Measure syntax availability under an explicitly synthetic compile profile."""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
import time
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

from experiments.workspace_guard import guarded_output_path


SOURCE_SUFFIXES = {".c", ".cc", ".cpp"}


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _safe_members(archive: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    result = []
    for item in archive.infolist():
        path = PurePosixPath(item.filename)
        if item.is_dir():
            continue
        if path.is_absolute() or ".." in path.parts or not path.parts:
            raise ValueError("unsafe_archive_member")
        result.append(item)
    return result


def evaluate(archives: list[Path], *, compiler: str = "clang") -> dict[str, Any]:
    if len(archives) != 7:
        raise ValueError("seven_archives_required")
    resolved_compiler = shutil.which(compiler)
    if not resolved_compiler:
        raise RuntimeError("compiler_unavailable")
    compiler_path = Path(resolved_compiler).resolve(strict=True)
    compiler_version = subprocess.run(
        [str(compiler_path), "--version"], check=True, capture_output=True, text=True,
    ).stdout.splitlines()[0]
    rows = []
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="kcmvp-synthetic-compile-") as temporary:
        root = Path(temporary)
        for set_number, archive_path in enumerate(archives, 1):
            set_root = root / f"set-{set_number}"
            set_root.mkdir()
            with zipfile.ZipFile(archive_path) as archive:
                members = _safe_members(archive)
                for item in members:
                    target = set_root.joinpath(*PurePosixPath(item.filename).parts)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(archive.read(item))
            sources = sorted(p for p in set_root.rglob("*") if p.is_file() and p.suffix.lower() in SOURCE_SUFFIXES)
            passed = 0
            reason_counts: dict[str, int] = {}
            latencies = []
            for source in sources:
                command = [str(compiler_path), "-fsyntax-only", "-std=c11", "-Wno-everything", "-I", str(set_root / "include"), str(source)]
                call_started = time.perf_counter()
                completed = subprocess.run(command, cwd=set_root, capture_output=True, text=True, timeout=30, check=False)
                latencies.append((time.perf_counter() - call_started) * 1000)
                if completed.returncode == 0:
                    passed += 1
                else:
                    stderr = completed.stderr.lower()
                    reason = "missing_include_or_declaration" if ("file not found" in stderr or "undeclared" in stderr or "unknown type" in stderr) else "syntax_or_profile_mismatch"
                    reason_counts[reason] = reason_counts.get(reason, 0) + 1
            rows.append({
                "set": set_number,
                "archive_sha256": _sha256(archive_path.read_bytes()),
                "translation_units": len(sources),
                "syntax_pass": passed,
                "syntax_fail": len(sources) - passed,
                "pass_rate": passed / len(sources) if sources else None,
                "failure_classes": reason_counts,
                "latency_ms_total": round(sum(latencies), 3),
            })
    total = sum(row["translation_units"] for row in rows)
    passed = sum(row["syntax_pass"] for row in rows)
    return {
        "schema_version": "1.0",
        "evaluation": "synthetic_compile_shadow",
        "profile": {"language": "c11", "include_policy": "archive_root/include_only", "warnings": "suppressed"},
        "compiler": {"binary_sha256": _sha256(compiler_path.read_bytes()), "version": compiler_version},
        "sets": rows,
        "aggregate": {"sets": 7, "translation_units": total, "syntax_pass": passed, "syntax_fail": total - passed,
                      "pass_rate": passed / total if total else None, "elapsed_ms": round((time.perf_counter() - started) * 1000, 3)},
        "authenticated_compile_context_coverage": 0.0,
        "semantic_authorization": 0,
        "api_calls": 0,
        "claim_limit": "Synthetic syntax shadow only; not the original build, program semantics, or final performance.",
    }


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("archives", nargs=7, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    output = guarded_output_path(args.output)
    output.write_text(json.dumps(evaluate(args.archives), sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    main()
