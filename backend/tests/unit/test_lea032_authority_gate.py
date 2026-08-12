import json
from pathlib import Path
def gate():return json.loads((Path(__file__).resolve().parents[2]/"mapping/lea032_authority_gate.json").read_text())
def test_research_comparison_is_not_promoted_to_normative_fact():
 g=gate();assert g["current_source_authority"]=="research_reference";assert g["normative_support"]["directly_states_aes_comparison"] is False;assert g["mapping_verified"] is False
def test_fallback_and_declarations_do_not_prove_final_round_structure():
 g=gate();assert "declaration" in g["detector_scope_problem"];assert g["current_population"]["occurrences"]==10;assert g["production_authorized"] is False
def test_only_algorithm_iteration_fragment_is_normatively_supported():assert gate()["normative_support"]["supports_fixed_iteration_of_algorithm_2"] is True and gate()["decision"]=="remain_fail_closed"
