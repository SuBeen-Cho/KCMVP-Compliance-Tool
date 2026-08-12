import hashlib
import json
from pathlib import Path

import pytest

from experiments import lea001_current_head_eval as target


def _snapshot(path: Path) -> None:
    content = "void f(void) {}\n"
    path.write_text(json.dumps({
        "sources": [{"source_id": "opaque", "content": content,
                     "sha256": hashlib.sha256(content.encode()).hexdigest(),
                     "bytes": len(content.encode()), "lines": len(content.splitlines())}],
    }), encoding="utf-8")


def test_exact_current_population_fails_closed_without_manifest(tmp_path, monkeypatch):
    path = tmp_path / "snapshot.json"
    _snapshot(path)
    selected = [(f"c{i}", {"rule_id": "LEA-001" if i < 2 else "OTHER",
                            "source_id": "opaque"}) for i in range(41)]
    monkeypatch.setattr(target, "select_exact_ai_ready", lambda _snapshot: selected)
    result = target.evaluate(path)
    assert result["population"] == {"exact_ai_ready": 41, "lea001": 2}
    assert result["complete_source_resolution"] == {"resolved": 2, "unresolved": 0}
    assert result["trusted_preprocessing"] == {"usable": 0, "unavailable_or_unverified": 2}
    assert result["structural_complete"] == 0
    assert result["fact_states"] == {"unknown": 2}
    assert result["reasons"] == {"trusted_preprocessing_manifest_unavailable": 2}
    assert result["production_authorized"] == 0


def test_rejects_source_hash_mismatch(tmp_path, monkeypatch):
    path = tmp_path / "snapshot.json"
    _snapshot(path)
    data = json.loads(path.read_text())
    data["sources"][0]["sha256"] = "0" * 64
    path.write_text(json.dumps(data))
    monkeypatch.setattr(target, "select_exact_ai_ready", lambda _snapshot: [
        (f"c{i}", {"rule_id": "OTHER", "source_id": "opaque"}) for i in range(41)
    ])
    with pytest.raises(ValueError, match="source_content_hash_mismatch"):
        target.evaluate(path)


def test_rejects_non_exact_ai_ready_universe(tmp_path, monkeypatch):
    path = tmp_path / "snapshot.json"
    _snapshot(path)
    monkeypatch.setattr(target, "select_exact_ai_ready", lambda _snapshot: [])
    with pytest.raises(ValueError, match="expected exact AI-ready universe"):
        target.evaluate(path)
