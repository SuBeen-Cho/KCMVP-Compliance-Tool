import json
from pathlib import Path

import pytest

from experiments.l3_advisory_checker import extract_pad002_facts, load_specs, run

BACKEND = Path(__file__).resolve().parents[2]
FIXTURES = BACKEND / "tests/fixtures"


def test_closed_spec_and_three_advisories():
    spec = load_specs(BACKEND / "rag/l3_advisory_specs.json")
    assert [row["advisory_id"] for row in spec["advisories"]] == ["GCM-006", "CTR-006", "PAD-002"]
    assert spec["default_enforcement"] == "disabled"
    index = json.loads((BACKEND / "data/evidence/official_units.local.json").read_text())
    known = {unit["unit_id"] for unit in index["units"]}
    assert all(set(row["evidence_unit_ids"]) <= known for row in spec["advisories"])


def test_open_advisory_schema_rejected(tmp_path):
    data = json.loads((BACKEND / "rag/l3_advisory_specs.json").read_text())
    data["advisories"][0]["extra"] = True
    path = tmp_path / "spec.json"
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="open advisory"):
        load_specs(path)


@pytest.mark.parametrize("fixture,outcome", [
    ("pad002_satisfied.c", "satisfied"),
    ("pad002_unsafe.c", "unsafe_observed"),
    ("pad002_unknown.c", "unknown"),
])
def test_pad002_three_way_outcomes(fixture, outcome):
    source = (FIXTURES / fixture).read_text()
    assert extract_pad002_facts(source)["outcome"] == outcome


def test_default_gate_never_emits_finding():
    result = run(FIXTURES / "pad002_unsafe.c", enabled=False)
    assert result == {"schema_version": "1.0", "enabled": False, "findings": [], "gate": "no_fp_default"}


def test_comments_and_strings_do_not_create_events():
    result = extract_pad002_facts('// cbc_decrypt(x); remove_padding(x);\nchar*s="validate_padding(x)";')
    assert result["outcome"] == "unknown"
