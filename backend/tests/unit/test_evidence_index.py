import hashlib
import json
import stat
from pathlib import Path

import pytest

from experiments.evidence_index import _is_boilerplate, _resolve_unicode_path, atomic_write_json, build_indexes, load_registry, normalize_text, validate_index, validate_verified_rule_mappings


def _source():
    return {"source_id": "s", "title": "source", "authority": "KCMVP", "authority_tier": "standard", "version": "1", "effective_date": None, "sha256": "1" * 64, "unit_count": 1}


def _index(unit):
    public_unit = {k: v for k, v in unit.items() if k != "text"}
    digest = hashlib.sha256(json.dumps([public_unit], ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"schema_version": "1.0", "collection": "official_source", "extractor": {"engine": "PyMuPDF", "version": "test"}, "source_manifest_sha256": "0" * 64, "units_manifest_sha256": digest, "sources": [_source()], "units": [unit]}


def test_registry_is_closed_and_separates_collections():
    backend = Path(__file__).resolve().parents[2]
    registry = load_registry(backend / "rag/official_sources.json")
    assert registry["collection"] == "official_source"
    assert registry["commentary_collection"] == "author_commentary"
    assert len(registry["sources"]) == 7
    assert len({s["source_id"] for s in registry["sources"]}) == 7


def test_repeated_copyright_footer_is_not_an_evidence_unit():
    assert _is_boilerplate("무단 전재, 재배포, 복사 및 상업적 활용 금지")
    assert _is_boilerplate("19 Copyright 2024. 국가보안기술연구소. All rights reserved.")
    assert not _is_boilerplate("검증대상 운영모드에서 Zero-padding을 사용할 수 없다.")


def test_registry_rejects_unknown_fields(tmp_path):
    source = {"schema_version": "1.0", "collection": "official_source", "commentary_collection": "author_commentary", "sources": [{"source_id": "x", "unexpected": 1}]}
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(source), encoding="utf-8")
    with pytest.raises(ValueError, match="closed source schema"):
        load_registry(path)


def test_validate_rejects_tampered_text_hash():
    text = normalize_text("  hello\nworld ")
    unit = {"unit_id": "s:p0001:b001", "source_id": "s", "collection": "official_source", "authority": "a", "authority_tier": "standard", "version": "1", "effective_date": None, "locator": {"page": 1, "block": 1, "section": None, "table": None, "footnote": None}, "structural_type": "paragraph", "role": "definition", "applicability": {"scope": ["x"]}, "text_sha256": "0" * 64, "text_length": len(text), "text": text}
    index = _index(unit)
    with pytest.raises(ValueError, match="text hash mismatch"):
        validate_index(index, require_text=True)


def test_atomic_private_output_permissions(tmp_path):
    path = tmp_path / "private.json"
    atomic_write_json(path, {"ok": True}, private=True)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_validate_rejects_wrong_text_length():
    text = "hello"
    unit = {"unit_id": "s:p0001:b001", "source_id": "s", "collection": "official_source", "authority": "a", "authority_tier": "standard", "version": "1", "effective_date": None, "locator": {"page": 1, "block": 1, "section": None, "table": None, "footnote": None}, "structural_type": "paragraph", "role": "definition", "applicability": {"scope": ["x"]}, "text_sha256": hashlib.sha256(text.encode()).hexdigest(), "text_length": 999, "text": text}
    index = _index(unit)
    with pytest.raises(ValueError, match="text hash mismatch"):
        validate_index(index, require_text=True)


def test_local_official_pdfs_build_deterministically(tmp_path):
    backend = Path(__file__).resolve().parents[2]
    workspace = backend.parent
    registry = backend / "rag/official_sources.json"
    public_a, private_a = build_indexes(workspace, registry)
    public_b, private_b = build_indexes(workspace, registry)
    assert public_a == public_b
    assert private_a == private_b
    assert len(public_a["sources"]) == 7
    assert len(public_a["units"]) > 100
    assert all("text" not in unit for unit in public_a["units"])
    assert all("text" in unit for unit in private_a["units"])
    audit = json.loads((backend / "mapping/rule_evidence_audit.json").read_text(encoding="utf-8"))
    validate_verified_rule_mappings(public_a, audit)
    assert sum(row["status"] == "verified" for row in audit["rules"].values()) == 50
    assert hashlib.sha256(json.dumps(public_a, sort_keys=True).encode()).hexdigest() == hashlib.sha256(json.dumps(public_b, sort_keys=True).encode()).hexdigest()


def test_public_index_rejects_unit_id_locator_disagreement():
    unit = {"unit_id": "s:p0002:b001", "source_id": "s", "collection": "official_source", "authority": "KCMVP", "authority_tier": "standard", "version": "1", "effective_date": None, "locator": {"page": 1, "block": 1, "section": None, "table": None, "footnote": None}, "structural_type": "paragraph", "role": "definition", "applicability": {"scope": ["x"]}, "text_sha256": "2" * 64, "text_length": 5}
    index = _index(unit)
    with pytest.raises(ValueError, match="unit id and locator disagree"):
        validate_index(index, require_text=False)


def test_verified_mapping_rejects_locator_disagreement():
    unit = {"unit_id": "s:p0001:b001", "source_id": "s", "collection": "official_source", "authority": "KCMVP", "authority_tier": "standard", "version": "1", "effective_date": None, "locator": {"page": 1, "block": 1, "section": None, "table": None, "footnote": None}, "structural_type": "paragraph", "role": "definition", "applicability": {"scope": ["x"]}, "text_sha256": "2" * 64, "text_length": 5}
    index = _index(unit)
    audit = {"rules": {"R-1": {"status": "verified", "source_locator": {"source_id": "s", "page": 2, "block": 1}, "source_sha256": "1" * 64, "evidence_unit_ids": ["s:p0001:b001"]}}}
    with pytest.raises(ValueError, match="verified locator disagrees"):
        validate_verified_rule_mappings(index, audit)


def test_verified_mapping_accepts_multiple_blocks_on_one_page():
    first = {"unit_id": "s:p0001:b001", "source_id": "s", "collection": "official_source", "authority": "KCMVP", "authority_tier": "standard", "version": "1", "effective_date": None, "locator": {"page": 1, "block": 1, "section": None, "table": None, "footnote": None}, "structural_type": "paragraph", "role": "definition", "applicability": {"scope": ["x"]}, "text_sha256": "2" * 64, "text_length": 5}
    second = dict(first, unit_id="s:p0001:b002", locator={**first["locator"], "block": 2}, text_sha256="3" * 64)
    public = [first, second]
    digest = hashlib.sha256(json.dumps(public, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    index = {"schema_version": "1.0", "collection": "official_source", "extractor": {"engine": "PyMuPDF", "version": "test"}, "source_manifest_sha256": "0" * 64, "units_manifest_sha256": digest, "sources": [{**_source(), "unit_count": 2}], "units": public}
    audit = {"rules": {"R-1": {"status": "verified", "source_locator": {"source_id": "s", "pages": [1], "blocks": [1, 2]}, "source_sha256": "1" * 64, "evidence_unit_ids": ["s:p0001:b001", "s:p0001:b002"]}}}
    validate_verified_rule_mappings(index, audit)


def test_source_resolver_rejects_symlink_escape(tmp_path):
    outside = tmp_path.parent / "outside.pdf"
    outside.write_bytes(b"not a secret")
    (tmp_path / "escape.pdf").symlink_to(outside)
    with pytest.raises(ValueError, match="symlinks"):
        _resolve_unicode_path(tmp_path, "escape.pdf")
