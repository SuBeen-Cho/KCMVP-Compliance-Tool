import pytest

from experiments.grounded_v1_v2_compare import ComparisonError, compare


def _rows(v2=False):
    rows=[]
    for i in range(41):
        row={"candidate_id_sha256":f"h{i}","raw_label":"non_violation","input_tokens":10,"output_tokens":2,"latency_ms":3}
        if v2: row.update({"raw_label":"non_violation" if i else "violation","verifier_passed":i==0,
                           "verifier_reason":"ok" if i==0 else "entailment_unconfirmed",
                           "verified_final":"violation" if i==0 else "abstain"})
        rows.append(row)
    return {"rows":rows}


def test_aggregate_comparison_preserves_invalid_v1_verifier_boundary():
    result=compare(_rows(),_rows(True),input_sha256={})
    assert result["raw_label_stability"]["exact_match_count"]==40
    assert result["verifier"]["v2_pass_count"]==1
    assert result["verifier"]["v1_final_comparison_status"].startswith("invalid")
    assert result["v2_final_disposition"]["abstention_count"]==40


def test_order_mismatch_fails_closed():
    v2=_rows(True); v2["rows"].reverse()
    with pytest.raises(ComparisonError,match="ordered"):
        compare(_rows(),v2,input_sha256={})


def test_non_41_and_missing_fields_fail_closed():
    with pytest.raises(ComparisonError, match="41"):
        compare({"rows": _rows()["rows"][:-1]}, _rows(True), input_sha256={})
    broken = _rows(True); del broken["rows"][0]["verified_final"]
    with pytest.raises(ComparisonError, match="missing"):
        compare(_rows(), broken, input_sha256={})
