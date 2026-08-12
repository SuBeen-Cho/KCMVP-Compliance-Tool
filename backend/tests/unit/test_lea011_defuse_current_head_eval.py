import hashlib

import pytest

from experiments.lea011_defuse_current_head_eval import _source_index


def source(content="x\n"):
    return {"source_id":"opaque-1", "content":content,
            "sha256":hashlib.sha256(content.encode()).hexdigest(),
            "bytes":len(content.encode()), "lines":len(content.splitlines())}


def test_source_index_accepts_hash_bound_embedded_complete_source():
    assert _source_index({"sources":[source()]}) == {"opaque-1":"x\n"}


@pytest.mark.parametrize("mutation", ["hash", "bytes", "lines"])
def test_source_index_rejects_tampered_metadata(mutation):
    row = source()
    row[{"hash":"sha256", "bytes":"bytes", "lines":"lines"}[mutation]] = "bad"
    with pytest.raises(ValueError):
        _source_index({"sources":[row]})


def test_source_index_rejects_duplicate_opaque_identity():
    with pytest.raises(ValueError, match="duplicate"):
        _source_index({"sources":[source(), source()]})
