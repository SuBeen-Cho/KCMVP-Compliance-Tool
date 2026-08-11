# KCMVP evidence index

`official_sources.json` is the closed allow-list for the seven local reference
PDF artifacts. The PDFs remain ignored and are never modified. A digest mismatch
stops generation, so replacing a document requires a deliberate registry review.

Generate a non-verbatim audit index and an ignored retrieval index from
`backend/`:

```bash
python -m experiments.evidence_index \
  --public-output /tmp/kcmvp-official-evidence.json
```

The public output contains locators, source/version/authority metadata, text
lengths, and SHA-256 digests but no extracted text. The local retrieval output
defaults to `backend/data/evidence/official_units.local.json`, is ignored by Git,
and is written with mode `0600`. Outputs are atomic and cannot overwrite the
registry or an allow-listed PDF. Absolute paths, traversal, and symlinked PDF
inputs are rejected. Public and local outputs carry the same
`units_manifest_sha256`, which binds the complete locator/hash manifest and
detects a stale or mismatched output pair. The producing PyMuPDF version is
recorded because layout extraction can change across extractor releases.

`authority_tier` is mandatory. In particular, `LEA_DESIGN_PAPER` is a research
reference, not a normative KCMVP requirement. Runtime retrieval must filter by
authority tier and may not promote author-authored files in `backend/guidelines/`
to this collection. Such files belong to the separate `author_commentary`
collection.
