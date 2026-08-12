import json
from pathlib import Path
def gate():return json.loads((Path(__file__).resolve().parents[2]/"mapping/lea_mct_applicability_gate.json").read_text())
def test_mct_rule_is_validation_artifact_scoped_not_production_generic():
 g=gate();assert g["normative_scope"]=="LEA validation-system Monte Carlo test artifact";assert "ordinary production CBC encryption" in g["does_not_apply_by_default_to"];assert g["decision"]=="remain_fail_closed"
def test_fallback_names_and_xor_text_cannot_prove_applicability():
 text=" ".join(gate()["does_not_apply_by_default_to"]);assert "name contains mct" in text;assert "fallback regex" in text
def test_current_overlap_is_explicit_and_not_double_counted_as_independent():
 p=gate()["current_population"];assert p=={"CBC-LEA-005":6,"LEA-057":2,"shared_occurrences":2};assert gate()["authenticated_mct_harness_applicability"]==0;assert gate()["production_authorized"] is False
