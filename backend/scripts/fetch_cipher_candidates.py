#!/usr/bin/env python3
"""Fetch and verify locked AES/SEED evaluation candidates outside the repository."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import urllib.request


BACKEND_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOCK = BACKEND_ROOT / "evaluation" / "candidates" / "sources.lock.json"
DEFAULT_CACHE = Path(tempfile.gettempdir()) / "kcmvp-cipher-candidates"
LICENSE_NAMES = ("LICENSE", "LICENSE.txt", "LICENSE.md", "COPYING", "COPYING.txt")
SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".h", ".hpp"}


class VerificationError(RuntimeError):
    """A candidate does not match its immutable lock metadata."""


def _run(*args: str, cwd: Path | None = None) -> str:
    result = subprocess.run(
        args, cwd=cwd, check=False, text=True, capture_output=True
    )
    if result.returncode:
        raise VerificationError(result.stderr.strip() or "command failed")
    return result.stdout.strip()


def load_lock(path: Path = DEFAULT_LOCK) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema_version") != 1 or not data.get("sources"):
        raise VerificationError("unsupported or empty source lock")
    for source in data["sources"]:
        required = {"id", "upstream", "tag", "commit", "algorithms", "license"}
        missing = sorted(required - source.keys())
        if missing:
            raise VerificationError(f"{source.get('id', '<unknown>')}: missing {missing}")
        if len(source["commit"]) != 40:
            raise VerificationError(f"{source['id']}: commit must be a full SHA-1")
    return data


def verify_remote_ref(source: dict) -> dict:
    tag_ref = f"refs/tags/{source['tag']}"
    output = _run("git", "ls-remote", source["upstream"], tag_ref, f"{tag_ref}^{{}}")
    refs = {ref: sha for sha, ref in (line.split() for line in output.splitlines())}
    tag_sha = refs.get(tag_ref)
    resolved = refs.get(f"{tag_ref}^{{}}", tag_sha)
    if resolved != source["commit"]:
        raise VerificationError(
            f"{source['id']}: tag resolves to {resolved}, expected {source['commit']}"
        )
    expected_tag_object = source.get("tag_object")
    if expected_tag_object and tag_sha != expected_tag_object:
        raise VerificationError(
            f"{source['id']}: tag object is {tag_sha}, expected {expected_tag_object}"
        )
    return {"tag_object": tag_sha, "commit": resolved}


def ensure_external_cache(cache: Path, repository: Path = BACKEND_ROOT.parent) -> Path:
    cache = cache.expanduser().resolve()
    repository = repository.resolve()
    if cache == repository or repository in cache.parents:
        raise VerificationError("candidate cache must be outside the Git repository")
    cache.mkdir(parents=True, exist_ok=True)
    return cache


def fetch_git(source: dict, cache: Path) -> Path:
    target = cache / source["id"]
    if target.exists() and not (target / ".git").is_dir():
        raise VerificationError(f"{target} exists but is not a Git checkout")
    if not target.exists():
        _run("git", "clone", "--filter=blob:none", "--no-checkout", source["upstream"], str(target))
    else:
        _run("git", "remote", "set-url", "origin", source["upstream"], cwd=target)
    _run("git", "fetch", "--force", "--depth=1", "origin", source["commit"], cwd=target)
    _run("git", "checkout", "--detach", "--force", source["commit"], cwd=target)
    actual = _run("git", "rev-parse", "HEAD", cwd=target)
    if actual != source["commit"]:
        raise VerificationError(f"{source['id']}: checkout is {actual}, expected {source['commit']}")
    return target


def verify_archive(source: dict, cache: Path) -> Path:
    url = source.get("official_archive")
    expected = source.get("archive_sha256")
    if not url or not expected:
        raise VerificationError(f"{source['id']}: archive URL and SHA-256 are both required")
    target = cache / (source["id"] + Path(url).suffix)
    with urllib.request.urlopen(url, timeout=60) as response, target.open("wb") as output:
        shutil.copyfileobj(response, output)
    actual = hashlib.sha256(target.read_bytes()).hexdigest()
    if actual != expected:
        target.unlink(missing_ok=True)
        raise VerificationError(f"{source['id']}: archive SHA-256 mismatch ({actual})")
    return target


def inventory_checkout(source: dict, checkout: Path) -> dict:
    licenses = [
        str(path.relative_to(checkout))
        for name in LICENSE_NAMES
        for path in checkout.glob(name)
        if path.is_file()
    ]
    if not licenses:
        raise VerificationError(f"{source['id']}: no top-level license file found")

    terms = tuple(algorithm.lower() for algorithm in source["algorithms"])
    matched = []
    for path in checkout.rglob("*"):
        if path.is_file() and path.suffix.lower() in SOURCE_SUFFIXES:
            relative = str(path.relative_to(checkout))
            if any(term in relative.lower() for term in terms):
                matched.append(relative)
    return {
        "id": source["id"],
        "commit": _run("git", "rev-parse", "HEAD", cwd=checkout),
        "license_files": sorted(set(licenses)),
        "algorithm_source_paths": sorted(matched),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    parser.add_argument("--cache", type=Path, default=DEFAULT_CACHE)
    parser.add_argument("--source", action="append", help="candidate id; repeatable")
    parser.add_argument("--verify-remote-only", action="store_true")
    parser.add_argument("--verify-archive", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    lock = load_lock(args.lock)
    selected = [s for s in lock["sources"] if not args.source or s["id"] in args.source]
    unknown = set(args.source or ()) - {s["id"] for s in selected}
    if unknown:
        raise VerificationError(f"unknown candidate ids: {sorted(unknown)}")
    cache = ensure_external_cache(args.cache)
    report = {"schema_version": 1, "lock": str(args.lock.resolve()), "sources": []}
    for source in selected:
        entry = {"id": source["id"], "remote": verify_remote_ref(source)}
        if args.verify_archive:
            entry["archive"] = str(verify_archive(source, cache))
        if not args.verify_remote_only:
            checkout = fetch_git(source, cache)
            entry["inventory"] = inventory_checkout(source, checkout)
        report["sources"].append(entry)

    encoded = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
