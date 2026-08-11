"""Opt-in Gemini labeling runner for an already validated public blind packet."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import signal
import time
from typing import Any, Callable

from experiments.labeling import LABELS, LabelingError, validate_label_document, validate_packet


MODEL = "gemini-2.5-flash-lite"
PROMPT_VERSION = "blind-occurrence-v2-concise"

RESPONSE_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "required": ["label", "confidence", "requirement_applicability", "evidence", "rationale",
                 "source_citations"],
    "properties": {
        "label": {"type": "string", "enum": list(LABELS)},
        "confidence": {"type": "integer", "minimum": 0, "maximum": 100},
        "requirement_applicability": {"type": "string",
                                      "enum": ["applicable", "not_applicable", "uncertain"]},
        "evidence": {"type": "string", "maxLength": 300},
        "rationale": {"type": "string", "maxLength": 300},
        "source_citations": {"type": "array", "minItems": 1, "maxItems": 3, "items": {
            "type": "object", "additionalProperties": False,
            "required": ["source_id", "line_start", "line_end"],
            "properties": {"source_id": {"type": "string"}, "line_start": {"type": "integer"},
                           "line_end": {"type": "integer"}},
        }},
    },
}


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def build_prompt(item: dict[str, Any]) -> str:
    """Build a self-contained prompt containing exactly one public-packet occurrence."""
    disclosed = {
        "candidate_id": item["candidate_id"], "rule_id": item["rule_id"],
        "requirement": item["requirement"], "source": item["source"],
    }
    return f"""You are an independent blind cryptographic-code annotator.
Judge ONLY the single occurrence below. Do not infer a hidden answer from names or metadata.
Allowed labels: violation, non_violation, insufficient_context, not_applicable.
- Use insufficient_context whenever code needed for a sound decision is withheld or outside the disclosed window.
- not_applicable means the stated requirement does not apply to this occurrence.
- Cite only the disclosed source_id and a line interval within line_start..line_end.
- Treat confidence as judgment confidence, not a calibrated probability.
- Keep evidence and rationale under 300 characters each.
Return one JSON object only, with exactly these fields:
label, confidence (integer 0..100), requirement_applicability
(applicable|not_applicable|uncertain), evidence, rationale,
source_citations (non-empty array of source_id,line_start,line_end objects).
The not_applicable label and applicability value must agree.

PUBLIC OCCURRENCE:
{json.dumps(disclosed, ensure_ascii=False, sort_keys=True)}"""


def _annotation(item: dict[str, Any], value: dict[str, Any]) -> dict[str, Any]:
    required = {"label", "confidence", "requirement_applicability", "evidence", "rationale",
                "source_citations"}
    if not isinstance(value, dict) or set(value) != required:
        raise LabelingError("Gemini response does not match annotation fields")
    row = {"candidate_id": item["candidate_id"], **value}
    # Reuse the closed document validator below for all semantic/range checks.
    return row


def _document(packet: dict[str, Any], annotations: list[dict[str, Any]], annotator_id: str) -> dict:
    core = {
        "schema_version": "1.0", "packet_id": packet["packet_id"],
        "annotator": {"annotator_id": annotator_id, "annotator_type": "ai",
                      "model": {"provider": "Google", "name": MODEL,
                                "version": PROMPT_VERSION}},
        "created_at": datetime.now(timezone.utc).isoformat(), "annotations": annotations,
    }
    return {"label_batch_id": sha256_bytes(canonical(core)), **core}


def _usage(response: Any) -> tuple[int | None, int | None]:
    usage = getattr(response, "usage_metadata", None)
    if usage is None:
        return None, None
    return (getattr(usage, "prompt_token_count", None),
            getattr(usage, "candidates_token_count", None))


class RequestDeadlineError(TimeoutError):
    pass


def _deadline_handler(_signum: int, _frame: Any) -> None:
    raise RequestDeadlineError("Gemini request exceeded the experiment deadline")


def run(*, packet: dict[str, Any], client: Any, annotator_id: str, reverse: bool,
        ledger_path: Path, checkpoint_path: Path, max_retries: int = 3,
        sleep: Callable[[float], None] = time.sleep,
        request_timeout_seconds: int = 60) -> dict[str, Any]:
    """Label packet occurrences independently and resume using a private local checkpoint."""
    validate_packet(packet)
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
    completed: dict[str, dict] = {}
    if checkpoint_path.exists():
        saved = json.loads(checkpoint_path.read_text(encoding="utf-8"))
        if saved.get("packet_id") != packet["packet_id"] or saved.get("annotator_id") != annotator_id:
            raise LabelingError("checkpoint identity mismatch")
        completed = {row["candidate_id"]: row for row in saved.get("annotations", [])}
    ordered = list(reversed(packet["items"])) if reverse else list(packet["items"])
    for item in ordered:
        cid = item["candidate_id"]
        if cid in completed:
            continue
        prompt = build_prompt(item)
        prompt_hash = sha256_bytes(prompt.encode("utf-8"))
        last_error: Exception | None = None
        for retry in range(max_retries + 1):
            started = time.monotonic()
            status = "error"
            response_hash = None
            input_tokens = output_tokens = None
            try:
                previous_handler = signal.signal(signal.SIGALRM, _deadline_handler)
                signal.alarm(request_timeout_seconds)
                response = client.models.generate_content(
                    model=MODEL, contents=prompt,
                    config={"response_mime_type": "application/json", "temperature": 0,
                            "response_json_schema": RESPONSE_SCHEMA, "max_output_tokens": 2048,
                            "thinking_config": {"thinking_budget": 0}},
                )
                response_text = response.text
                response_hash = sha256_bytes(response_text.encode("utf-8"))
                input_tokens, output_tokens = _usage(response)
                row = _annotation(item, json.loads(response_text))
                # Validate the row immediately by making a one-row structural surrogate below.
                if row["label"] not in LABELS:
                    raise LabelingError("unsupported Gemini label")
                completed[cid] = row
                status = "ok"
                checkpoint_path.write_text(json.dumps({
                    "packet_id": packet["packet_id"], "annotator_id": annotator_id,
                    "annotations": list(completed.values()),
                }, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
            except Exception as exc:  # ledger must capture every attempted request
                last_error = exc
            finally:
                signal.alarm(0)
                if "previous_handler" in locals():
                    signal.signal(signal.SIGALRM, previous_handler)
            ledger = {
                "candidate_id_hash": sha256_bytes(cid.encode()), "prompt_sha256": prompt_hash,
                "response_sha256": response_hash, "model": MODEL, "prompt_version": PROMPT_VERSION,
                "input_tokens": input_tokens, "output_tokens": output_tokens, "status": status,
                "retry": retry, "latency_ms": round((time.monotonic() - started) * 1000, 3),
            }
            with ledger_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(ledger, sort_keys=True) + "\n")
            if status == "ok":
                break
            if retry < max_retries:
                sleep(min(8.0, 2.0 ** retry))
        else:
            raise RuntimeError(f"Gemini labeling failed after retries for candidate hash "
                               f"{sha256_bytes(cid.encode())}") from last_error
    by_id = completed
    document = _document(packet, [by_id[item["candidate_id"]] for item in packet["items"]], annotator_id)
    validate_label_document(packet, document)
    return document
