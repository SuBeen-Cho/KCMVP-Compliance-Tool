import hashlib
import json

from app.services import rag_service


def _write_index(path, unit_ids, source_id, source_sha):
    units = []
    for number, unit_id in enumerate(unit_ids, 1):
        text = f"공식 규범 근거 {number}"
        units.append({
            "unit_id": unit_id, "source_id": source_id,
            "collection": "official_source", "authority": "KISA",
            "authority_tier": "normative_guidance", "version": "test",
            "effective_date": "2026-01-01",
            "locator": {"page": number, "block": 1, "section": "test", "table": None, "footnote": None},
            "structural_type": "paragraph", "role": "requirement",
            "applicability": {"mode": ["GCM"]},
            "text_sha256": hashlib.sha256(text.encode()).hexdigest(),
            "text_length": len(text), "text": text,
        })
    path.write_text(json.dumps({
        "schema_version": "1.0", "collection": "official_source",
        "source_manifest_sha256": "0" * 64,
        "sources": [{"source_id": source_id, "title": "test", "authority": "KISA", "authority_tier": "normative_guidance", "version": "test", "effective_date": "2026-01-01", "sha256": source_sha, "page_unit_count": len(units)}],
        "units": units,
    }), encoding="utf-8")


def test_verified_rule_loads_only_mapped_official_units(tmp_path, monkeypatch):
    audit = json.loads(rag_service._EVIDENCE_AUDIT.read_text(encoding="utf-8"))
    row = audit["rules"]["GCM-002"]
    index = tmp_path / "official.json"
    _write_index(index, row["evidence_unit_ids"], row["source_locator"]["source_id"], row["source_sha256"])
    monkeypatch.setenv("KCMVP_OFFICIAL_EVIDENCE_INDEX", str(index))
    rag_service._official_index_cache.clear()
    chunks = rag_service.search_evidence("GCM-002", top_k=10)
    assert [chunk["unit_id"] for chunk in chunks] == row["evidence_unit_ids"]
    assert all(chunk["collection"] == "official_source" for chunk in chunks)
    assert all(chunk["status"] == "verified" for chunk in chunks)
    assert rag_service.search_evidence("CTR-001") == []


def test_submission_rule_loads_its_exact_official_guide_units(tmp_path, monkeypatch):
    audit = json.loads(rag_service._EVIDENCE_AUDIT.read_text(encoding="utf-8"))
    row = audit["rules"]["DOC-001"]
    index = tmp_path / "official.json"
    _write_index(index, row["evidence_unit_ids"], row["source_locator"]["source_id"], row["source_sha256"])
    monkeypatch.setenv("KCMVP_OFFICIAL_EVIDENCE_INDEX", str(index))
    rag_service._official_index_cache.clear()

    chunks = rag_service.search_evidence("DOC-001")

    assert [chunk["unit_id"] for chunk in chunks] == row["evidence_unit_ids"]
    assert all(chunk["status"] == "verified" for chunk in chunks)


def test_official_runtime_fails_closed_on_text_hash_drift(tmp_path, monkeypatch):
    audit = json.loads(rag_service._EVIDENCE_AUDIT.read_text(encoding="utf-8"))
    row = audit["rules"]["GCM-002"]
    index = tmp_path / "official.json"
    _write_index(index, row["evidence_unit_ids"], row["source_locator"]["source_id"], row["source_sha256"])
    payload = json.loads(index.read_text(encoding="utf-8"))
    payload["units"][0]["text"] = "tampered"
    index.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setenv("KCMVP_OFFICIAL_EVIDENCE_INDEX", str(index))
    rag_service._official_index_cache.clear()
    assert rag_service.search_evidence("GCM-002") == []


def test_public_nonverbatim_index_cannot_be_used_at_runtime(tmp_path, monkeypatch):
    index = tmp_path / "public.json"
    index.write_text(json.dumps({
        "schema_version": "1.0", "collection": "official_source",
        "source_manifest_sha256": "0" * 64, "sources": [], "units": [],
    }), encoding="utf-8")
    monkeypatch.setenv("KCMVP_OFFICIAL_EVIDENCE_INDEX", str(index))
    rag_service._official_index_cache.clear()
    assert rag_service.search_evidence("GCM-002") == []
