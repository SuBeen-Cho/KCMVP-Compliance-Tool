"""Best-effort telemetry for *code L3 experiment* requests only.

This is deliberately not an application-wide LLM audit log.  Document judging,
report summaries and patch generation are outside its stated scope.  It stores
only hashes and non-sensitive request metadata; telemetry failure must never
change an L3 decision or mask the provider exception.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
from threading import Lock
from typing import Any, Iterable, Optional


_lock = Lock()
_enabled = False
_output_path: Optional[Path] = None
_records: list[dict[str, Any]] = []
_run_id: Optional[str] = None
_snapshot_id: Optional[str] = None
_sequence = 0
_write_errors: list[str] = []


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _safe_error(exc: BaseException) -> str:
    """Return a stable error class without leaking paths or exception text."""
    return type(exc).__name__


def enable_request_ledger(
    output_path: Optional[Path] = None, *, run_id: Optional[str] = None,
    snapshot_id: Optional[str] = None, truncate: bool = True,
) -> None:
    """Enable a new code-L3 experiment run.

    A file-backed run defaults to truncation so records from separate experiments
    cannot be silently mixed.  Creation is best effort and uses owner-only mode.
    """
    global _enabled, _output_path, _run_id, _snapshot_id, _sequence
    with _lock:
        _enabled = True
        _output_path = Path(output_path) if output_path is not None else None
        _run_id, _snapshot_id, _sequence = run_id, snapshot_id, 0
        _records.clear()
        _write_errors.clear()
        if _output_path is not None:
            try:
                _output_path.parent.mkdir(parents=True, exist_ok=True)
                flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if truncate else os.O_APPEND)
                fd = os.open(_output_path, flags, 0o600)
                os.close(fd)
                os.chmod(_output_path, 0o600)
            except OSError as exc:
                _write_errors.append(_safe_error(exc))


def disable_request_ledger() -> None:
    global _enabled, _output_path
    with _lock:
        _enabled = False
        _output_path = None


def reset_request_ledger() -> None:
    global _sequence
    with _lock:
        _records.clear()
        _write_errors.clear()
        _sequence = 0


def get_request_ledger() -> list[dict[str, Any]]:
    with _lock:
        return copy.deepcopy(_records)


def get_request_ledger_status() -> dict[str, Any]:
    with _lock:
        return {
            "scope": "code_l3_experiment_requests_only",
            "run_id": _run_id,
            "snapshot_id": _snapshot_id,
            "record_count": len(_records),
            "write_status": "ok" if not _write_errors else "degraded",
            "write_error_classes": list(_write_errors),
        }


def request_ledger_file_sha256() -> Optional[str]:
    with _lock:
        path = _output_path
    if path is None or not path.is_file():
        return None
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def record_request(
    *, candidate_ids: Optional[Iterable[str]], phase: str, prompt: str,
    response: Optional[str], attempt: int, status: str, input_tokens: int,
    output_tokens: int, provider: str, model: str,
    usage_status: str = "available",
) -> None:
    global _sequence
    # All state, including enable/path transitions and sequence allocation, is
    # protected by the same lock.  Disk errors are captured, never propagated.
    with _lock:
        if not _enabled:
            return
        _sequence += 1
        record = {
            "schema_version": 2,
            "scope": "code_l3_experiment_requests_only",
            "run_id": _run_id,
            "snapshot_id": _snapshot_id,
            "sequence": _sequence,
            # Preserve request order and repeated occurrences. Full hashes avoid
            # unnecessary truncation collisions while keeping paths out of JSONL.
            "candidate_ids": [_sha256(str(value)) for value in candidate_ids or []],
            "phase": str(phase),
            "prompt_sha256": _sha256(prompt),
            "response_sha256": _sha256(response) if response is not None else None,
            "attempt": int(attempt),
            "status": str(status),
            "input_tokens": max(0, int(input_tokens)),
            "output_tokens": max(0, int(output_tokens)),
            "usage_status": str(usage_status),
            "provider": str(provider),
            # Avoid serializing a local filesystem path as a model identifier.
            "model": Path(str(model)).name if provider == "local" else str(model),
        }
        _records.append(record)
        if _output_path is not None:
            try:
                encoded = (json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
                fd = os.open(_output_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
                try:
                    pending = memoryview(encoded)
                    while pending:
                        written = os.write(fd, pending)
                        if written <= 0:
                            raise OSError("short ledger write")
                        pending = pending[written:]
                    os.fsync(fd)
                finally:
                    os.close(fd)
            except OSError as exc:
                _write_errors.append(_safe_error(exc))
