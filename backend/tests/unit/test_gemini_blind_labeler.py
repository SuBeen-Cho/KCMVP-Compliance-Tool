import json
from types import SimpleNamespace

from experiments.gemini_blind_labeler import build_prompt, run
from experiments.labeling import build_packet, validate_label_document


def packet():
    items = [{"candidate_id": "candidate_1", "group_id": "cluster_1", "rule_id": "R-1",
              "requirement": {"text": "must check", "citations": [{"source": "guide", "locator": "1"}]},
              "source": {"source_id": "src_1.c", "line_start": 10, "line_end": 11,
                         "code": "000010: x();", "context": "Occurrence-level source window"}}]
    import hashlib
    from experiments.labeling import _hash
    audit = {"passed": True, "checks": {"neutral": True}, "audited_items_sha256": _hash(items)}
    return build_packet(snapshot_id="s", prepared_by="test", randomization_id="r",
                        items=items, blind_audit_report=audit)


class Models:
    def __init__(self): self.prompts = []
    def generate_content(self, **kwargs):
        self.prompts.append(kwargs["contents"])
        text = json.dumps({"label": "insufficient_context", "confidence": 80,
                           "requirement_applicability": "uncertain", "evidence": "window only",
                           "rationale": "callee is withheld", "source_citations": [
                               {"source_id": "src_1.c", "line_start": 10, "line_end": 11}]})
        return SimpleNamespace(text=text, usage_metadata=SimpleNamespace(
            prompt_token_count=12, candidates_token_count=8))


def test_prompt_contains_one_item_and_no_outcome():
    value = build_prompt(packet()["items"][0])
    assert "candidate_1" in value
    assert "ground_truth" not in value


def test_run_writes_hash_only_ledger_and_valid_document(tmp_path):
    value = packet(); models = Models(); client = SimpleNamespace(models=models)
    ledger = tmp_path / "ledger.jsonl"
    result = run(packet=value, client=client, annotator_id="gemini-a", reverse=False,
                 ledger_path=ledger, checkpoint_path=tmp_path / "checkpoint.json")
    validate_label_document(value, result)
    record = json.loads(ledger.read_text())
    assert record["status"] == "ok"
    assert record["input_tokens"] == 12
    assert "prompt" not in record and "response" not in record
    assert "window only" not in ledger.read_text()
