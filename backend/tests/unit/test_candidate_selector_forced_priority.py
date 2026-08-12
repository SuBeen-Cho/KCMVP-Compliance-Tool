from app.services.llm.candidate_selector import _select_l3_candidates


def candidate(index, *, snippet, rule="COM-003", pattern="regex", severity="high"):
    return {"rule_id": rule, "snippet": snippet, "pattern_type": pattern,
            "severity": severity, "marker": index}


def test_all_eligible_sensitive_name_candidates_survive_per_rule_cap():
    rows = [candidate(i, snippet=f"uint8_t session_key_{i}[16] = {{0}};") for i in range(12)]
    result = _select_l3_candidates(rows)
    assert {row["marker"] for row in result} == set(range(12))
    assert len({id(row) for row in result}) == 12


def test_forced_priority_never_overrides_fp_exclusion():
    row = candidate(1, snippet="uint8_t test_key[16] = {0};")
    # TP keywords are intentionally checked first today; this regression makes
    # that policy visible. A future semantic exclusion must change this test.
    assert _select_l3_candidates([row]) == [row]
    fp = candidate(2, snippet="uint8_t sbox_table[256] = {0};")
    assert _select_l3_candidates([fp]) == []


def test_ineligible_name_match_is_not_forced_into_l3():
    row = candidate(1, snippet="uint8_t secret_key[16];", pattern="document")
    assert _select_l3_candidates([row]) == []
