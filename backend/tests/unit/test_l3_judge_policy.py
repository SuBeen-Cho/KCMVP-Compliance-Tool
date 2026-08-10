"""L3 risk-tier decision policy tests."""

from app.services.llm import l3_judge


def test_no_dual_verify_ablation_skips_second_pass(monkeypatch):
    called = False

    def fail_if_called(*_args, **_kwargs):
        nonlocal called
        called = True
        return False

    monkeypatch.setenv("ABLATION_NO_DUAL_VERIFY", "1")
    monkeypatch.setattr(l3_judge, "_verify_fp_removal", fail_if_called)

    assert l3_judge._fp_removal_verified({}, {}, "code", "src/test.c") is True
    assert called is False


def test_dual_verify_default_requires_second_pass(monkeypatch):
    calls = []

    def fake_verify(v, obj, code_block, file_path):
        calls.append((v, obj, code_block, file_path))
        return False

    monkeypatch.delenv("ABLATION_NO_DUAL_VERIFY", raising=False)
    monkeypatch.setattr(l3_judge, "_verify_fp_removal", fake_verify)

    assert l3_judge._fp_removal_verified({"rule_id": "LEA-030"}, {}, "code", "src/lea.c") is False
    assert calls == [({"rule_id": "LEA-030"}, {}, "code", "src/lea.c")]


def test_never_remove_rule_is_kept_even_when_l3_says_false(monkeypatch):
    monkeypatch.setenv("ABLATION_NO_DUAL_VERIFY", "1")
    results = []
    rejected = set()
    violation = {
        "rule_id": "CBC-001",
        "pattern_type": "ast",
        "file": "src/cipher.c",
        "line": 10,
    }
    judgment = {
        "is_real_issue": False,
        "confidence": 95,
        "description": "오탐으로 보임",
        "suggestion": "",
    }

    l3_judge._apply_l3_decision(
        v=violation,
        obj=judgment,
        code_block="code",
        file_path="src/cipher.c",
        results=results,
        rejected_tracker=rejected,
    )

    assert len(results) == 1
    assert rejected == set()
    assert results[0]["l3_risk_tier"] == "D"
    assert results[0]["l3_removal_allowed"] is False
    assert results[0]["l3_removal_blocked_reason"] == "never_remove"


def test_grounded_missing_relax_removes_low_risk_auxiliary(monkeypatch):
    monkeypatch.setenv("L3_GROUNDED_RELAX", "1")
    monkeypatch.setenv("ABLATION_NO_DUAL_VERIFY", "1")
    results = []
    rejected = set()
    violation = {
        "rule_id": "LEA-048",
        "pattern_type": "missing",
        "file": "src/test_lea.c",
        "line": None,
    }
    judgment = {
        "is_real_issue": False,
        "confidence": 20,
        "description": "제출 산출물 증거가 별도 존재함",
        "suggestion": "",
        "evidence_type": "delegated_to_other_file",
        "delegated_target": "rsp/lea_cbc_mmt.rsp",
    }

    l3_judge._apply_l3_decision(
        v=violation,
        obj=judgment,
        code_block="code",
        file_path="src/test_lea.c",
        results=results,
        rejected_tracker=rejected,
    )

    assert results == []
    assert rejected == {("src/test_lea.c", "LEA-048", None)}
    assert "removal_allowed" not in judgment


def test_experimental_grounded_relax_is_opt_in(monkeypatch):
    monkeypatch.delenv("L3_GROUNDED_ARTIFACT_RELAX", raising=False)
    assert l3_judge._grounded_artifact_relax() is False
