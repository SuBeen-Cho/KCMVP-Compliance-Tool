"""Deterministic, offline evidence-unit indexing for approved local PDFs.

The committed index is deliberately non-verbatim: it contains identity,
locators, structural metadata, and hashes.  An ignored local index may contain
the extracted text used by retrieval.  Both are derived from the same units.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
import unicodedata
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION = "1.0"
ALLOWED_COLLECTIONS = {"official_source", "author_commentary"}
ALLOWED_AUTHORITY_TIERS = {
    "normative_guidance", "standard", "reference_implementation_manual",
    "research_reference", "normative_test_interface",
}
ALLOWED_STRUCTURAL_TYPES = {"paragraph", "table", "footnote"}
ALLOWED_ROLES = {
    "requirement", "submission_requirement", "definition", "exception",
    "reference_example", "rationale", "test_procedure", "table", "footnote",
}
HEADING = re.compile(r"^(?:\d+(?:\.\d+){0,4}[.)]?|[IVX]+[.)]|[A-Z]\.)\s+\S|^\S.{0,60}(?:\uc7a5|\uc808)$")
FOOTNOTE = re.compile(r"^(?:\*+|\u203b|\uc8fc\s*\d*|note\s*\d*)\s*[:.)]?", re.I)
EXCEPTION = re.compile(r"(?:\uc608\uc678|\ub2e4\ub9cc|\uc81c\uc678|except|unless)", re.I)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def normalize_text(value: str) -> str:
    value = unicodedata.normalize("NFC", value).replace("\u00ad", "")
    return re.sub(r"\s+", " ", value).strip()


def _resolve_unicode_path(root: Path, relative: str) -> Path:
    if Path(relative).is_absolute():
        raise ValueError(f"source path must be relative: {relative!r}")
    target_parts = [unicodedata.normalize("NFC", p) for p in Path(relative).parts]
    cursor = root
    for wanted in target_parts:
        if wanted in {"", ".", ".."}:
            raise ValueError(f"source path traversal is forbidden: {relative!r}")
        matches = [p for p in cursor.iterdir() if unicodedata.normalize("NFC", p.name) == wanted]
        if len(matches) != 1:
            raise FileNotFoundError(f"source path component is absent or ambiguous: {relative!r}")
        cursor = matches[0]
        if cursor.is_symlink():
            raise ValueError(f"source path may not contain symlinks: {relative!r}")
    if not cursor.is_file() or cursor.suffix.lower() != ".pdf" or not cursor.resolve().is_relative_to(root.resolve()):
        raise ValueError(f"source must be a PDF inside the workspace: {relative!r}")
    return cursor


def load_registry(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported source registry schema")
    if data.get("collection") != "official_source" or data.get("commentary_collection") != "author_commentary":
        raise ValueError("official and author-commentary collections must be explicitly separated")
    sources = data.get("sources")
    if not isinstance(sources, list) or not sources:
        raise ValueError("source registry must be non-empty")
    ids: set[str] = set()
    for source in sources:
        required = {"source_id", "relative_path", "title", "authority", "authority_tier", "version", "effective_date", "expected_sha256", "default_role", "applicability"}
        if set(source) != required:
            raise ValueError(f"closed source schema mismatch: {source.get('source_id')}")
        if source["source_id"] in ids:
            raise ValueError(f"duplicate source_id: {source['source_id']}")
        ids.add(source["source_id"])
        if source["default_role"] not in ALLOWED_ROLES:
            raise ValueError(f"invalid default role: {source['default_role']}")
        if source["authority_tier"] not in ALLOWED_AUTHORITY_TIERS:
            raise ValueError(f"invalid authority tier: {source['source_id']}")
        for field in ("source_id", "relative_path", "title", "authority", "version"):
            if not isinstance(source[field], str) or not source[field].strip():
                raise ValueError(f"invalid source field {field}: {source['source_id']}")
        if not re.fullmatch(r"[0-9a-f]{64}", source["expected_sha256"]):
            raise ValueError(f"invalid source digest: {source['source_id']}")
        if not isinstance(source["applicability"], dict) or not source["applicability"]:
            raise ValueError(f"missing applicability: {source['source_id']}")
    return data


def _role(text: str, default: str, structural_type: str) -> str:
    if structural_type == "table":
        return "table"
    if structural_type == "footnote":
        return "footnote"
    if EXCEPTION.search(text):
        return "exception"
    return default


def _iter_pdf_units(path: Path, source: dict[str, Any]) -> Iterable[dict[str, Any]]:
    try:
        import fitz  # type: ignore[import]
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("PyMuPDF is required to build the evidence index") from exc
    with fitz.open(path) as document:
        section: str | None = None
        for page_number, page in enumerate(document, 1):
            blocks = page.get_text("blocks", sort=True)
            for block_number, block in enumerate(blocks, 1):
                text = normalize_text(str(block[4]))
                if not text:
                    continue
                lines = [normalize_text(line) for line in str(block[4]).splitlines() if normalize_text(line)]
                first = lines[0] if lines else text
                if HEADING.search(first) and len(first) <= 100:
                    section = first
                structural_type = "paragraph"
                if FOOTNOTE.search(first):
                    structural_type = "footnote"
                elif len(lines) >= 3 and sum(bool(re.search(r"\s{2,}|\t", line)) for line in str(block[4]).splitlines()) >= 2:
                    structural_type = "table"
                yield {
                    "unit_id": f"{source['source_id']}:p{page_number:04d}:b{block_number:03d}",
                    "source_id": source["source_id"],
                    "collection": "official_source",
                    "authority": source["authority"],
                    "authority_tier": source["authority_tier"],
                    "version": source["version"],
                    "effective_date": source["effective_date"],
                    "locator": {"page": page_number, "block": block_number, "section": section, "table": block_number if structural_type == "table" else None, "footnote": block_number if structural_type == "footnote" else None},
                    "structural_type": structural_type,
                    "role": _role(text, source["default_role"], structural_type),
                    "applicability": source["applicability"],
                    "text_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                    "text_length": len(text),
                    "text": text,
                }


def validate_index(index: dict[str, Any], *, require_text: bool) -> None:
    if set(index) != {"schema_version", "collection", "extractor", "source_manifest_sha256", "units_manifest_sha256", "sources", "units"}:
        raise ValueError("closed evidence-index schema mismatch")
    if index["schema_version"] != SCHEMA_VERSION or index["collection"] not in ALLOWED_COLLECTIONS:
        raise ValueError("invalid evidence-index header")
    if set(index["extractor"]) != {"engine", "version"} or index["extractor"]["engine"] != "PyMuPDF" or not index["extractor"]["version"]:
        raise ValueError("invalid extractor metadata")
    if not re.fullmatch(r"[0-9a-f]{64}", str(index["source_manifest_sha256"])):
        raise ValueError("invalid source manifest digest")
    if not re.fullmatch(r"[0-9a-f]{64}", str(index["units_manifest_sha256"])):
        raise ValueError("invalid units manifest digest")
    source_required = {
        "source_id", "title", "authority", "authority_tier", "version",
        "effective_date", "sha256", "unit_count",
    }
    source_ids: set[str] = set()
    for source in index["sources"]:
        if set(source) != source_required:
            raise ValueError(f"closed indexed-source schema mismatch: {source.get('source_id')}")
        source_id = source.get("source_id")
        if not isinstance(source_id, str) or not source_id or source_id in source_ids:
            raise ValueError(f"invalid or duplicate indexed source: {source_id}")
        if source.get("authority_tier") not in ALLOWED_AUTHORITY_TIERS:
            raise ValueError(f"invalid indexed authority tier: {source_id}")
        if not re.fullmatch(r"[0-9a-f]{64}", str(source.get("sha256"))):
            raise ValueError(f"invalid indexed source digest: {source_id}")
        if not isinstance(source.get("unit_count"), int) or source["unit_count"] <= 0:
            raise ValueError(f"invalid indexed unit count: {source_id}")
        source_ids.add(source_id)
    unit_ids: set[str] = set()
    source_unit_counts = {source_id: 0 for source_id in source_ids}
    for unit in index["units"]:
        required = {"unit_id", "source_id", "collection", "authority", "authority_tier", "version", "effective_date", "locator", "structural_type", "role", "applicability", "text_sha256", "text_length"}
        if require_text:
            required.add("text")
        if set(unit) != required:
            raise ValueError(f"closed evidence-unit schema mismatch: {unit.get('unit_id')}")
        if unit["source_id"] not in source_ids or unit["unit_id"] in unit_ids:
            raise ValueError(f"orphan or duplicate evidence unit: {unit['unit_id']}")
        unit_ids.add(unit["unit_id"])
        source_unit_counts[unit["source_id"]] += 1
        if unit["collection"] != index["collection"] or unit["role"] not in ALLOWED_ROLES:
            raise ValueError(f"invalid collection or role: {unit['unit_id']}")
        if unit["authority_tier"] not in ALLOWED_AUTHORITY_TIERS:
            raise ValueError(f"invalid authority tier: {unit['unit_id']}")
        if unit["structural_type"] not in ALLOWED_STRUCTURAL_TYPES:
            raise ValueError(f"invalid structural type: {unit['unit_id']}")
        locator = unit.get("locator")
        if not isinstance(locator, dict) or set(locator) != {"page", "block", "section", "table", "footnote"}:
            raise ValueError(f"invalid locator schema: {unit['unit_id']}")
        page, block = locator.get("page"), locator.get("block")
        expected_id = f"{unit['source_id']}:p{page:04d}:b{block:03d}" if isinstance(page, int) and isinstance(block, int) else ""
        if not isinstance(page, int) or page <= 0:
            raise ValueError(f"invalid locator page: {unit['unit_id']}")
        if not isinstance(block, int) or block <= 0:
            raise ValueError(f"invalid locator block: {unit['unit_id']}")
        if unit["unit_id"] != expected_id:
            raise ValueError(f"unit id and locator disagree: {unit['unit_id']}")
        if locator["table"] not in {None, block} or locator["footnote"] not in {None, block}:
            raise ValueError(f"non-atomic table or footnote locator: {unit['unit_id']}")
        if unit["structural_type"] == "table" and locator["table"] != block:
            raise ValueError(f"table locator missing: {unit['unit_id']}")
        if unit["structural_type"] == "footnote" and locator["footnote"] != block:
            raise ValueError(f"footnote locator missing: {unit['unit_id']}")
        if not re.fullmatch(r"[0-9a-f]{64}", str(unit.get("text_sha256"))):
            raise ValueError(f"invalid text digest: {unit['unit_id']}")
        if not isinstance(unit.get("text_length"), int) or unit["text_length"] <= 0:
            raise ValueError(f"invalid text length: {unit['unit_id']}")
        if require_text:
            normalized = normalize_text(unit["text"])
            if (normalized != unit["text"] or len(normalized) != unit["text_length"]
                    or hashlib.sha256(normalized.encode()).hexdigest() != unit["text_sha256"]):
                raise ValueError(f"text hash mismatch: {unit['unit_id']}")
    declared_counts = {source["source_id"]: source["unit_count"] for source in index["sources"]}
    if source_unit_counts != declared_counts:
        raise ValueError("indexed source unit counts disagree with units")
    public_units = [{k: v for k, v in unit.items() if k != "text"} for unit in index["units"]]
    units_digest = hashlib.sha256(
        json.dumps(public_units, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if units_digest != index["units_manifest_sha256"]:
        raise ValueError("units manifest digest mismatch")


def load_index(path: Path, *, require_text: bool = True) -> dict[str, Any]:
    """Load an index and reject partial, stale-schema, or tampered units."""
    index = json.loads(path.read_text(encoding="utf-8"))
    validate_index(index, require_text=require_text)
    return index


def validate_verified_rule_mappings(index: dict[str, Any], audit: dict[str, Any]) -> None:
    """Prove that every mapping marked verified resolves in this exact index."""
    validate_index(index, require_text=bool(index.get("units") and "text" in index["units"][0]))
    units = {unit["unit_id"]: unit for unit in index["units"]}
    sources = {source["source_id"]: source for source in index["sources"]}
    for rule_id, row in audit.get("rules", {}).items():
        if row.get("status") != "verified":
            continue
        locator = row.get("source_locator") or {}
        source_id = locator.get("source_id")
        if source_id not in sources or sources[source_id]["sha256"] != row.get("source_sha256"):
            raise ValueError(f"{rule_id}: verified source is absent or hash-mismatched")
        referenced = row.get("evidence_unit_ids") or []
        if not referenced or any(unit_id not in units for unit_id in referenced):
            raise ValueError(f"{rule_id}: verified evidence unit is absent")
        if any(units[unit_id]["source_id"] != source_id for unit_id in referenced):
            raise ValueError(f"{rule_id}: evidence unit belongs to another source")
        referenced_units = [units[unit_id] for unit_id in referenced]
        pages = locator.get("pages")
        blocks = locator.get("blocks")
        if "page" in locator or "block" in locator:
            if len(referenced_units) != 1 or locator.get("page") != referenced_units[0]["locator"]["page"] or locator.get("block") != referenced_units[0]["locator"]["block"]:
                raise ValueError(f"{rule_id}: verified locator disagrees with evidence unit")
        elif pages is not None:
            if not isinstance(pages, list) or not pages or any(unit["locator"]["page"] not in pages for unit in referenced_units):
                raise ValueError(f"{rule_id}: verified pages disagree with evidence units")
            if blocks is not None:
                if not isinstance(blocks, list) or len(blocks) != len(pages):
                    raise ValueError(f"{rule_id}: verified page/block coordinates are ambiguous")
                allowed = set(zip(pages, blocks))
                if any((unit["locator"]["page"], unit["locator"]["block"]) not in allowed for unit in referenced_units):
                    raise ValueError(f"{rule_id}: verified coordinates disagree with evidence units")


def build_indexes(workspace: Path, registry_path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        import fitz  # type: ignore[import]
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("PyMuPDF is required to build the evidence index") from exc
    registry = load_registry(registry_path)
    sources: list[dict[str, Any]] = []
    units: list[dict[str, Any]] = []
    for declared in registry["sources"]:
        path = _resolve_unicode_path(workspace, declared["relative_path"])
        actual = sha256_file(path)
        if actual != declared["expected_sha256"]:
            raise ValueError(f"source hash drift: {declared['source_id']}: {actual}")
        extracted = list(_iter_pdf_units(path, declared))
        if not extracted:
            raise ValueError(f"no extractable evidence: {declared['source_id']}")
        sources.append({
            "source_id": declared["source_id"], "title": declared["title"],
            "authority": declared["authority"], "authority_tier": declared["authority_tier"],
            "version": declared["version"], "effective_date": declared["effective_date"],
            "sha256": actual, "unit_count": len(extracted),
        })
        units.extend(extracted)
    public_units = [{k: v for k, v in unit.items() if k != "text"} for unit in units]
    units_manifest_sha256 = hashlib.sha256(
        json.dumps(public_units, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    base = {"schema_version": SCHEMA_VERSION, "collection": "official_source", "extractor": {"engine": "PyMuPDF", "version": str(fitz.VersionBind)}, "source_manifest_sha256": hashlib.sha256(registry_path.read_bytes()).hexdigest(), "units_manifest_sha256": units_manifest_sha256, "sources": sources}
    private = {**base, "units": units}
    public = {**base, "units": public_units}
    validate_index(private, require_text=True)
    validate_index(public, require_text=False)
    return public, private


def atomic_write_json(path: Path, value: dict[str, Any], *, private: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        if private:
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def main() -> None:
    backend = Path(__file__).resolve().parents[1]
    repo = backend.parent
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry", type=Path, default=backend / "rag/official_sources.json")
    parser.add_argument("--public-output", type=Path, required=True)
    parser.add_argument("--local-text-output", type=Path, default=backend / "data/evidence/official_units.local.json")
    args = parser.parse_args()
    protected = {args.registry.resolve()}
    registry = load_registry(args.registry)
    protected.update(_resolve_unicode_path(repo, item["relative_path"]).resolve() for item in registry["sources"])
    outputs = {args.public_output.resolve(), args.local_text_output.resolve()}
    if len(outputs) != 2 or outputs & protected:
        raise ValueError("outputs must differ and must not overwrite the registry or a source PDF")
    public, private = build_indexes(repo, args.registry)
    atomic_write_json(args.local_text_output, private, private=True)
    atomic_write_json(args.public_output, public, private=False)


if __name__ == "__main__":
    main()
