import json
import hashlib
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from app.services.llm import gemini_client
from app.services.llm.request_ledger import (
    disable_request_ledger,
    enable_request_ledger,
    get_request_ledger,
    get_request_ledger_status,
    record_request,
    reset_request_ledger,
)


@pytest.fixture(autouse=True)
def clean_ledger():
    disable_request_ledger()
    reset_request_ledger()
    yield
    disable_request_ledger()
    reset_request_ledger()


def test_ledger_is_opt_in():
    record_request(
        candidate_ids=["candidate"], phase="test", prompt="prompt", response="response",
        attempt=1, status="ok", input_tokens=1, output_tokens=1,
        provider="gemini", model="model",
    )
    assert get_request_ledger() == []


def test_jsonl_contains_only_hashes_and_non_sensitive_metadata(tmp_path):
    path = tmp_path / "ledger.jsonl"
    enable_request_ledger(path)
    secret_prompt = "source.c API_KEY=secret prompt body"
    secret_response = "private response body"
    record_request(
        candidate_ids=["set::source.c::AES-001"], phase="l3_isolated",
        prompt=secret_prompt, response=secret_response, attempt=1, status="ok",
        input_tokens=12, output_tokens=4, provider="gemini", model="gemini-test",
    )

    encoded = path.read_text(encoding="utf-8")
    assert secret_prompt not in encoded
    assert secret_response not in encoded
    assert "source.c" not in encoded
    record = json.loads(encoded)
    assert len(record["candidate_ids"][0]) == 64
    assert len(record["prompt_sha256"]) == 64
    assert len(record["response_sha256"]) == 64
    assert record["phase"] == "l3_isolated"


def test_retry_records_each_attempt_without_changing_result(monkeypatch):
    enable_request_ledger()
    calls = iter([
        gemini_client.GeminiTransientError("temporary"),
        '{"is_real_issue": true}',
    ])

    def fake_call(*args, **kwargs):
        value = next(calls)
        if isinstance(value, Exception):
            raise value
        return value

    monkeypatch.setattr(gemini_client, "_call_llm", fake_call)
    monkeypatch.setattr(gemini_client.time, "sleep", lambda _: None)
    result = gemini_client._call_gemini_with_retry(
        "sensitive prompt", candidate_ids=["candidate-1"], phase="l3_rejudge"
    )

    assert result == {"is_real_issue": True}
    records = get_request_ledger()
    assert [record["attempt"] for record in records] == [1, 2]
    assert records[0]["status"] == "error:GeminiTransientError"
    assert records[1]["status"] == "response_received"
    assert all(record["phase"] == "l3_rejudge" for record in records)


def test_preserves_candidate_order_duplicates_and_returns_deep_copy():
    enable_request_ledger(run_id="run", snapshot_id="snapshot")
    record_request(
        candidate_ids=["b", "a", "b"], phase="l3_batch", prompt="p", response="r",
        attempt=1, status="ok", input_tokens=0, output_tokens=0,
        provider="gemini", model="model",
    )
    first = get_request_ledger()
    assert first[0]["candidate_ids"] == [
        hashlib.sha256(value.encode()).hexdigest() for value in ("b", "a", "b")
    ]
    assert first[0]["run_id"] == "run"
    assert first[0]["snapshot_id"] == "snapshot"
    first[0]["candidate_ids"].clear()
    assert len(get_request_ledger()[0]["candidate_ids"]) == 3


def test_existing_file_is_truncated_and_owner_only(tmp_path):
    path = tmp_path / "ledger.jsonl"
    path.write_text("old secret\n", encoding="utf-8")
    enable_request_ledger(path, run_id="new-run")
    assert path.read_text(encoding="utf-8") == ""
    assert (path.stat().st_mode & 0o777) == 0o600


def test_disk_failure_is_best_effort_and_does_not_drop_memory_record(tmp_path, monkeypatch):
    path = tmp_path / "ledger.jsonl"
    enable_request_ledger(path)
    real_open = os.open

    def fail_append(target, flags, mode=0o777):
        if flags & os.O_APPEND:
            raise PermissionError("sensitive path detail")
        return real_open(target, flags, mode)

    monkeypatch.setattr("app.services.llm.request_ledger.os.open", fail_append)
    record_request(
        candidate_ids=["id"], phase="l3_batch", prompt="p", response="r",
        attempt=1, status="ok", input_tokens=1, output_tokens=1,
        provider="gemini", model="model",
    )
    assert len(get_request_ledger()) == 1
    status = get_request_ledger_status()
    assert status["write_status"] == "degraded"
    assert status["write_error_classes"] == ["PermissionError"]


def test_doc_style_call_without_candidate_is_out_of_scope(monkeypatch):
    enable_request_ledger()
    monkeypatch.setattr(gemini_client, "_call_llm", lambda *a, **k: '{"ok": true}')
    assert gemini_client._call_gemini_with_retry("p") == {"ok": True}
    assert get_request_ledger() == []


def test_fallback_records_actual_provider_and_unavailable_non_gemini_usage(monkeypatch):
    enable_request_ledger()
    monkeypatch.setattr(gemini_client, "L3_PROVIDER", "openai")
    monkeypatch.setenv("LLM_ALLOW_PROVIDER_FALLBACK", "1")
    monkeypatch.setattr(gemini_client, "_call_openai", lambda *a, **k: None)
    monkeypatch.setattr(gemini_client, "_call_gemini", lambda *a, **k: '{"ok": true}')
    assert gemini_client._call_gemini_with_retry("p", candidate_ids=["id"]) == {"ok": True}
    record = get_request_ledger()[0]
    assert record["provider"] == "gemini"
    assert record["model"] == gemini_client.GEMINI_L3_MODEL
    assert record["usage_status"] == "available"


def test_non_gemini_usage_is_explicitly_unavailable(monkeypatch):
    enable_request_ledger()
    monkeypatch.setattr(gemini_client, "L3_PROVIDER", "openai")
    monkeypatch.setattr(gemini_client, "_call_openai", lambda *a, **k: '{"ok": true}')
    assert gemini_client._call_gemini_with_retry("p", candidate_ids=["id"]) == {"ok": True}
    record = get_request_ledger()[0]
    assert record["provider"] == "openai"
    assert record["usage_status"] == "unavailable"
    assert record["input_tokens"] == record["output_tokens"] == 0


def test_gcfs_fallback_has_distinct_phase_and_monotonic_attempt(monkeypatch):
    enable_request_ledger()
    calls = iter([gemini_client._Gemini503Error("temporary"), '{"ok": true}'])

    def fake_call(*args, **kwargs):
        value = next(calls)
        if isinstance(value, Exception):
            raise value
        return value

    monkeypatch.setattr(gemini_client, "_call_llm", fake_call)
    monkeypatch.setattr(gemini_client, "_strip_gcfs_from_prompt", lambda _: "stripped")
    assert gemini_client._call_gemini_with_retry(
        "original", candidate_ids=["id"], phase="l3_batch"
    ) == {"ok": True}
    records = get_request_ledger()
    assert [record["attempt"] for record in records] == [1, 2]
    assert [record["phase"] for record in records] == ["l3_batch", "l3_batch:gcfs_removed"]


def test_measured_code_l3_calls_are_serialized(monkeypatch):
    enable_request_ledger()
    state = {"active": 0, "maximum": 0}
    guard = threading.Lock()

    def fake_call(*args, **kwargs):
        with guard:
            state["active"] += 1
            state["maximum"] = max(state["maximum"], state["active"])
        time.sleep(0.01)
        with guard:
            state["active"] -= 1
        return '{"ok": true}'

    monkeypatch.setattr(gemini_client, "_call_llm", fake_call)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(
            lambda n: gemini_client._call_gemini_with_retry("p", candidate_ids=[str(n)]),
            range(4),
        ))
    assert all(result == {"ok": True} for result in results)
    assert state["maximum"] == 1
    assert [record["sequence"] for record in get_request_ledger()] == [1, 2, 3, 4]
