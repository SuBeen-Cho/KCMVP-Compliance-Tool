import importlib.util
from pathlib import Path
import subprocess


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "evaluate_cipher_implementations.py"
SPEC = importlib.util.spec_from_file_location("cipher_impl_eval", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_static_coverage_keeps_mixed_unknown_aggregate_unknown(tmp_path, monkeypatch):
    checkout = tmp_path / "candidate"
    checkout.mkdir()
    (checkout / "aes_ok.c").write_text("handled", encoding="utf-8")
    (checkout / "aes_indirect.c").write_text("indirect", encoding="utf-8")

    def fake_check(rule_id, content, filename):
        return [] if content == "handled" else None

    import app.services.ast_checker_service as checker
    monkeypatch.setattr(checker, "check_rule", fake_check)
    report = MODULE.static_coverage(
        {"algorithms": ["AES"]}, checkout
    )["algorithms"][0]
    assert report["rules"][0]["aggregate_status"] == "unknown"
    assert report["rules"][0]["file_status_counts"] == {
        "compliant": 1, "unknown": 1, "violation": 0,
    }


def test_vector_report_requires_attested_build_and_reports_pass(tmp_path, monkeypatch):
    source = {"algorithms": ["AES"]}
    vectors = [{
        "algorithm": "AES-128", "key": "00", "plaintext": "00",
        "ciphertext": "aa", "source": "test vector",
    }]
    runner = tmp_path / "runner"
    runner.write_text("placeholder", encoding="utf-8")
    monkeypatch.setattr(
        MODULE, "_run",
        lambda command, cwd=None, **kwargs: subprocess.CompletedProcess(command, 0, "aa\n", ""),
    )
    attestation = {"status": "built_from_locked_checkout", "checkout_commit": "a" * 40}
    passed = MODULE.executable_vector_report(source, vectors, runner, attestation)
    assert passed["status"] == "passed"
    assert passed["build"] == attestation


def test_cli_has_no_arbitrary_runner_option():
    text = SCRIPT.read_text(encoding="utf-8")
    assert '"--runner"' not in text


def test_library_driver_compile_contracts_are_version_specific():
    botan = MODULE.DRIVERS["botan-3.12.0"]
    mbedtls = MODULE.DRIVERS["mbedtls-3.6.7"]
    assert 'c->set_key(k.data(),k.size())' in botan
    assert 'c->encrypt(p.data())' in botan
    assert 'mbedtls_aria_crypt_ecb(&x,p.data(),o)' in mbedtls
    assert '"-std=c++20"' in SCRIPT.read_text(encoding="utf-8")


def test_checkout_must_be_external_to_repository(tmp_path):
    checkout = MODULE.BACKEND_ROOT / "accidental-vendor"
    try:
        MODULE._assert_external(checkout, MODULE.BACKEND_ROOT.parent)
    except MODULE.EvaluationError as exc:
        assert "outside" in str(exc)
    else:
        raise AssertionError("repository-contained candidate was accepted")
