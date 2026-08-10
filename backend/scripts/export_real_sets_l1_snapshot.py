#!/usr/bin/env python3
"""Create one label-free frozen L1 snapshot from the real evaluation ZIP sets.

This command never runs RAG or L3 and therefore requires no API credential.
Answer-bearing annotations are removed before the rule engine sees the sources.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath
import stat
import sys
import tempfile
import zipfile
import re
from typing import Any, Callable

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

from app.services.rule_engine_service import run_rule_engine  # noqa: E402
from experiments.l1_snapshot import (  # noqa: E402
    SnapshotError, atomic_write_snapshot, build_snapshot, validate_snapshot,
)
from experiments.manifest import build_manifest  # noqa: E402
from scripts.evaluate_real_sets import sanitize_gt_annotations  # noqa: E402

DEFAULT_SET_BASE = BACKEND.parent.parent / "스크립트" / "코드 - 설계서 세트"
SOURCE_SUFFIXES = {".c", ".h", ".cc", ".cpp", ".hpp"}
MAX_SOURCE_BYTES = 10 * 1024 * 1024
MAX_ARCHIVE_SOURCE_BYTES = 100 * 1024 * 1024
Engine = Callable[..., list[dict[str, Any]]]


_ANSWER_HINT = re.compile(
    r"(?:\[위반|\b(?:위반|정답|TP|FP|FN|true[ _-]?positive|false[ _-]?positive|"
    r"false[ _-]?negative|ground[ _-]?truth|expected[ _-]?(?:label|verdict)|"
    r"verdict|answer)\b)",
    re.IGNORECASE,
)


def _strip_answer_comments_preserve_lines(text: str) -> str:
    """Remove only answer-bearing C comments while retaining code and line numbers."""
    def block(match: re.Match[str]) -> str:
        raw = match.group(0)
        return "\n" * raw.count("\n") if _ANSWER_HINT.search(raw) else raw

    text = re.sub(r"/\*.*?\*/", block, text, flags=re.DOTALL)
    return re.sub(
        r"//[^\n]*",
        lambda match: "" if _ANSWER_HINT.search(match.group(0)) else match.group(0),
        text,
    )


def _safe_archive_sources(archive: Path, destination: Path) -> list[Path]:
    written = []
    seen_logical: set[str] = set()
    total_bytes = 0
    with zipfile.ZipFile(archive) as handle:
        for info in sorted(handle.infolist(), key=lambda item: item.filename):
            logical = PurePosixPath(info.filename)
            mode = info.external_attr >> 16
            if (
                logical.is_absolute() or ".." in logical.parts or not logical.parts
                or stat.S_ISLNK(mode)
            ):
                raise SnapshotError("ZIP contains an unsafe source entry")
            if info.is_dir() or logical.suffix.lower() not in SOURCE_SUFFIXES:
                continue
            logical_id = logical.as_posix()
            if logical_id in seen_logical:
                raise SnapshotError("ZIP contains a duplicate source entry")
            seen_logical.add(logical_id)
            if info.flag_bits & 0x1:
                raise SnapshotError("ZIP contains an encrypted source entry")
            if info.file_size > MAX_SOURCE_BYTES:
                raise SnapshotError("ZIP source exceeds the per-file size limit")
            total_bytes += info.file_size
            if total_bytes > MAX_ARCHIVE_SOURCE_BYTES:
                raise SnapshotError("ZIP sources exceed the aggregate size limit")
            raw = handle.read(info)
            try:
                text = raw.decode("utf-8-sig")
            except UnicodeDecodeError:
                try:
                    # Several preserved real sets contain Korean CP949 comments.
                    # Decode them explicitly instead of the old lossy errors=ignore path.
                    text = raw.decode("cp949")
                except UnicodeDecodeError as exc:
                    raise SnapshotError("ZIP source is neither UTF-8 nor CP949") from exc
            target = destination.joinpath(*logical.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            sanitized = sanitize_gt_annotations(text)
            target.write_text(_strip_answer_comments_preserve_lines(sanitized), encoding="utf-8")
            written.append(target)
    if not written:
        raise SnapshotError("ZIP contains no supported source files")
    return written


def export_snapshot(
    set_base: Path, set_numbers: list[int], output: Path, *, engine: Engine = run_rule_engine,
) -> dict[str, Any]:
    if not set_numbers or any(isinstance(item, bool) or item < 1 for item in set_numbers):
        raise SnapshotError("set numbers must be positive integers")
    if len(set_numbers) != len(set(set_numbers)):
        raise SnapshotError("set numbers must not repeat")
    archives = []
    for number in set_numbers:
        archive = set_base / f"세트 {number}" / "kcmvp_combined.zip"
        if not archive.is_file():
            raise SnapshotError(f"set {number} code ZIP is missing")
        archives.append((number, archive))

    with tempfile.TemporaryDirectory(prefix="kcmvp-frozen-l1-") as temporary:
        source_root = Path(temporary) / "sources"
        all_candidates = []
        for number, archive in archives:
            set_root = source_root / f"set-{number}"
            files = _safe_archive_sources(archive, set_root)
            entries = []
            physical_to_logical = {}
            for path in sorted(files):
                logical = path.relative_to(source_root).as_posix()
                set_logical = path.relative_to(set_root).as_posix()
                content = path.read_text(encoding="utf-8")
                physical_to_logical[str(path)] = logical
                # The rule engine normally returns the stable display path, not
                # the temporary physical path.
                physical_to_logical[set_logical] = logical
                entries.append({
                    "path": str(path), "display": set_logical, "content": content,
                    "lines": content.splitlines(), "ast": {},
                })
            candidates = engine(
                preprocess_result={"files": entries}, rules_dir=BACKEND / "rules", job_root=set_root,
            )
            for candidate in candidates:
                frozen = dict(candidate)
                raw_file = str(frozen.get("file", ""))
                if raw_file not in physical_to_logical:
                    raise SnapshotError("L1 candidate references a source outside its set")
                frozen["file"] = physical_to_logical[raw_file]
                # Rule descriptions can literally call a pattern a "violation".
                # They are not observations from L1 and would disclose the intended
                # class to L3, so omit them from the frozen experimental payload.
                frozen.pop("ai_context", None)
                all_candidates.append(frozen)

        manifest = build_manifest(BACKEND.parent, [archive for _, archive in archives])
        snapshot = build_snapshot(
            source_root, all_candidates,
            set_id="real-sets-" + "-".join(str(item) for item in set_numbers),
            provenance={
                "git_commit": manifest["code"]["commit"],
                "workspace_sha256": manifest["code"]["workspace_sha256"],
                "rules_sha256": manifest["artifacts"]["rules_tree_sha256"],
                "prompts_sha256": manifest["artifacts"]["prompts_sha256"],
            },
        )
        atomic_write_snapshot(output, snapshot)
    return validate_snapshot(snapshot)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sets", default="1,2,3,4,5,6,7")
    parser.add_argument("--set-base", type=Path, default=DEFAULT_SET_BASE)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        set_numbers = [int(item.strip()) for item in args.sets.split(",") if item.strip()]
    except ValueError as exc:
        raise SnapshotError("sets must be comma-separated integers") from exc
    report = export_snapshot(args.set_base, set_numbers, args.output)
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (SnapshotError, OSError, zipfile.BadZipFile) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        raise SystemExit(2)
