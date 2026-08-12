import json

import pytest

from experiments.evidence_retrieval_eval import evaluate, evaluate_mapping_integrity, load_ground_truth


def _unit(uid, source="source-ok", status="verified"):
    text = "official requirement span"
    return {
        "unit_id": uid, "source_id": source, "collection": "official_source",
        "authority": "KISA", "authority_tier": "standard", "role": "requirement",
        "status": status, "version": "1", "effective_date": "2024-03-01",
        "locator": {"page": 1, "block": 1}, "text": text,
        "text_sha256": __import__("hashlib").sha256(text.encode()).hexdigest(),
        "applicability": {}, "source_sha256": "a" * 64,
    }


def _gt():
    return {"schema_version": "1.0", "collection": "evidence_query_ground_truth", "scope": "human_reviewed_semantic_seed", "queries": [{
        "query_id": "q1", "rule_id": "X-001", "query": "requirement",
        "relevant_unit_ids": ["good"], "allowed_source_ids": ["source-ok"],
    }]}


def test_closed_ground_truth_schema(tmp_path):
    bad = _gt()
    bad["queries"][0]["leak"] = True
    path = tmp_path / "gt.json"
    path.write_text(json.dumps(bad), encoding="utf-8")
    with pytest.raises(ValueError, match="open query schema"):
        load_ground_truth(path)


def test_four_conditions_measure_retrieval_and_fail_closed_verifier(monkeypatch):
    monkeypatch.setattr(
        "app.services.rag_grounding._verified_rule_binding",
        lambda rule_id: {"unit_ids": frozenset({"good"}), "source_id": "source-ok", "source_sha256": "a" * 64},
    )
    good, bad = _unit("good"), _unit("bad", "source-wrong")
    monkeypatch.setattr(
        "app.services.rag_service._load_verified_official_units",
        lambda rule_id: [good],
    )
    result = evaluate(_gt(), {"good": good, "bad": bad}, [good, bad], repeats=2,
                      search=lambda *a, **k: [good])
    summary = result["summary"]
    assert summary["relevant"]["recall_at_k"] == 1
    assert summary["relevant"]["citation_verified"] == 1
    assert summary["oracle"]["citation_verified"] == 1
    assert summary["irrelevant"]["wrong_authority_rate"] == 1
    assert summary["irrelevant"]["citation_verified"] == 0
    assert summary["irrelevant"]["abstained"] == 1
    assert summary["irrelevant"]["citation_verifier_correct"] == 1
    assert summary["conflicting"]["abstained"] == 1
    assert summary["conflicting"]["citation_verifier_correct"] == 1


def test_bundle_recall_differs_from_recall_at_k(monkeypatch):
    units = [_unit("a"), _unit("b"), _unit("bad", "wrong")]
    gt = _gt()
    gt["queries"][0]["relevant_unit_ids"] = ["a", "b"]
    monkeypatch.setattr(
        "app.services.rag_grounding._verified_rule_binding",
        lambda rule_id: {"unit_ids": frozenset({"a", "b"}), "source_id": "source-ok", "source_sha256": "a" * 64},
    )
    result = evaluate(gt, {u["unit_id"]: u for u in units}, units, top_k=1,
                      search=lambda *a, **k: units[:2])
    row = next(r for r in result["rows"] if r["condition"] == "relevant")
    assert row["recall_at_k"] == .5
    assert row["bundle_recall"] == 1


def test_mapping_integrity_covers_verified_and_unverified(tmp_path):
    good = _unit("good")
    audit = {"rules": {
        "X-001": {"status": "verified", "evidence_unit_ids": ["good"], "source_locator": {"source_id": "source-ok"}},
        "X-002": {"status": "review_required"},
    }}
    path = tmp_path / "audit.json"
    path.write_text(json.dumps(audit), encoding="utf-8")
    def search(rule_id, **kwargs):
        return [good] if rule_id == "X-001" else []
    result = evaluate_mapping_integrity(path, {"good": good}, repeats=2, search=search)
    assert result["verified_rule_count"] == 1
    assert result["unverified_rule_count"] == 1
    assert result["exact_unit_set_rate"] == 1
    assert result["source_binding_rate"] == 1
    assert result["mean_bundle_recall"] == 1
    assert result["fail_closed_unverified_rate"] == 1
