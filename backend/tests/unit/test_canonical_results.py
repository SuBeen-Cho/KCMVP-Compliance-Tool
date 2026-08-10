from experiments.canonical import audit_legacy_result, metrics


def test_metrics_match_paper_arithmetic():
    result = metrics(128, 37, 0)
    assert round(result["precision"] * 100, 1) == 77.6
    assert round(result["recall"] * 100, 1) == 100.0
    assert round(result["f1"] * 100, 1) == 87.4


def test_blind_rate_and_version_mismatch_are_explicit():
    audited = audit_legacy_result({
        "timestamp": "legacy",
        "aggregate_all": {"GT": 128, "TP": 128, "FN": 0, "FP": 37,
                          "Precision": 128 / 165, "Recall": 1.0, "F1": 256 / 293},
        "blind_kcmvp": {"c_files": 34, "kloc": 12.0, "final_count": 9},
    })
    assert audited["status"] == "legacy_unverified"
    assert audited["blind"]["computed_candidates_per_kloc"] == 0.75
    assert audited["blind"]["incompatible_with_paper_claim"] is True
    assert round(audited["blind"]["paper_claim_7_over_14_5"], 2) == 0.48
