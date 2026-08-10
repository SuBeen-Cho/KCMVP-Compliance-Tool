import importlib.util
from pathlib import Path
import urllib.request

import pytest


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "check_policy_freshness.py"
SPEC = importlib.util.spec_from_file_location("check_policy_freshness", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


def test_policy_snapshot_tracks_official_expected_values():
    snapshot = MODULE.load_snapshot()
    sources = {item["id"]: item for item in snapshot["sources"]}
    assert sources["kisa-kcmvp-aes-status"]["expected"] == {
        "algorithm": "AES",
        "validation_system": "TBD",
        "test_vectors": "TBD",
    }
    assert sources["nist-fips-140-3-ig-version"]["expected"]["latest_version_date"] == "2026-04-09"


def test_snapshot_rejects_non_official_url(tmp_path):
    path = tmp_path / "snapshot.json"
    path.write_text(
        '{"schema_version":1,"as_of":"2026-08-11","sources":['
        '{"id":"bad","authority":"x","url":"https://example.com/x",'
        '"checked_on":"2026-08-11","expected":{"x":"y"},"claim_limit":"limit"}]}',
        encoding="utf-8",
    )
    with pytest.raises(MODULE.SnapshotError, match="official"):
        MODULE.load_snapshot(path)


def test_kisa_inspector_detects_tbd_and_publication():
    source = next(
        item for item in MODULE.load_snapshot()["sources"]
        if item["id"] == "kisa-kcmvp-aes-status"
    )
    unchanged = MODULE.inspect_source(
        source, "<tr><td>AES</td><td>modes</td><td>TBD</td><td>TBD</td></tr>"
    )
    changed = MODULE.inspect_source(
        source, "<tr><td>AES</td><td>modes</td><td>DOWNLOAD</td><td>DOWNLOAD</td></tr>"
    )
    assert unchanged["status"] == "unchanged"
    assert changed["status"] == "changed"


def test_kisa_inspector_only_counts_tbd_in_aes_row():
    source = next(
        item for item in MODULE.load_snapshot()["sources"]
        if item["id"] == "kisa-kcmvp-aes-status"
    )
    page = (
        "<table><tr><td><span>AES</span></td><td>published</td><td>TBD</td></tr>"
        "<tr><td>ARIA</td><td>TBD</td><td>TBD</td></tr></table>"
    )
    assert MODULE.inspect_source(source, page)["status"] == "changed"


def test_nist_inspector_detects_expected_version():
    source = next(
        item for item in MODULE.load_snapshot()["sources"]
        if item["id"] == "nist-fips-140-3-ig-version"
    )
    assert MODULE.inspect_source(
        source, "FIPS 140-3 IG (April 9, 2026) - Latest version"
    )["status"] == "unchanged"
    assert MODULE.inspect_source(
        source, "FIPS 140-3 IG (July 1, 2026) - Latest version"
    )["status"] == "changed"


def test_nist_inspector_uses_latest_date_not_historical_match():
    source = next(
        item for item in MODULE.load_snapshot()["sources"]
        if item["id"] == "nist-fips-140-3-ig-version"
    )
    page = (
        "FIPS 140-3 IG (April 9, 2026) - archived. "
        "FIPS 140-3 IG (July 1, 2026) - Latest version"
    )
    result = MODULE.inspect_source(source, page)
    assert result["status"] == "changed"
    assert result["observed"]["latest_version_date"] == "2026-07-01"


def test_network_unavailability_is_reported_without_exception(monkeypatch):
    monkeypatch.setattr(MODULE, "fetch_text", lambda *args: (_ for _ in ()).throw(TimeoutError("offline")))
    results = MODULE.check_network(MODULE.load_snapshot())
    assert {item["status"] for item in results} == {"unavailable"}
    assert {item["error_code"] for item in results} == {"unexpected_error"}


@pytest.mark.parametrize(
    "url",
    [
        "https://user@csrc.nist.gov/path",
        "https://csrc.nist.gov:8443/path",
        "https://csrc.nist.gov/path?next=https://example.com",
    ],
)
def test_snapshot_rejects_unsafe_official_url_variants(tmp_path, url):
    path = tmp_path / "snapshot.json"
    path.write_text(
        '{"schema_version":1,"as_of":"2026-08-11","sources":['
        '{"id":"bad","authority":"NIST","url":' + repr(url).replace("'", '"') + ','
        '"checked_on":"2026-08-11","expected":{"x":"y"},"claim_limit":"limit"}]}',
        encoding="utf-8",
    )
    with pytest.raises(MODULE.SnapshotError, match="official"):
        MODULE.load_snapshot(path)


def test_redirect_is_rejected_with_stable_error_code(monkeypatch):
    handler = MODULE._RejectRedirects()
    with pytest.raises(MODULE.NetworkCheckError, match="redirect_rejected"):
        handler.redirect_request(None, None, 302, "Found", {}, "http://127.0.0.1/")


def test_fetch_rejects_oversized_response(monkeypatch):
    class Headers:
        @staticmethod
        def get_content_charset():
            return "utf-8"

    class Response:
        headers = Headers()
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def read(self, amount):
            return b"x" * amount

    class Opener:
        @staticmethod
        def open(*args, **kwargs):
            return Response()

    monkeypatch.setattr(urllib.request, "build_opener", lambda *args: Opener())
    with pytest.raises(MODULE.NetworkCheckError, match="response_too_large"):
        MODULE.fetch_text("https://csrc.nist.gov/", max_bytes=8)


def test_snapshot_rejects_non_string_claim_limit(tmp_path):
    path = tmp_path / "snapshot.json"
    path.write_text(
        '{"schema_version":1,"as_of":"2026-08-11","sources":['
        '{"id":"nist-fips-140-3-ig-version","authority":"NIST",'
        '"url":"https://csrc.nist.gov/path","checked_on":"2026-08-11",'
        '"expected":{"latest_version_date":"2026-04-09",'
        '"displayed_version":"April 9, 2026"},"claim_limit":7}]}',
        encoding="utf-8",
    )
    with pytest.raises(MODULE.SnapshotError, match="claim limit"):
        MODULE.load_snapshot(path)


def test_strict_network_returns_three_for_unavailable(monkeypatch):
    monkeypatch.setattr(
        MODULE,
        "check_network",
        lambda *args: [{"id": "x", "status": "unavailable", "error_code": "timeout"}],
    )
    monkeypatch.setattr(
        MODULE.sys,
        "argv",
        ["check_policy_freshness.py", "--network", "--strict-network"],
    )
    assert MODULE.main() == 3


def test_snapshot_rejects_mismatched_authority_and_expected_schema(tmp_path):
    path = tmp_path / "snapshot.json"
    path.write_text(
        '{"schema_version":1,"as_of":"2026-08-11","sources":['
        '{"id":"nist-fips-140-3-ig-version","authority":"KISA",'
        '"url":"https://csrc.nist.gov/path","checked_on":"2026-08-11",'
        '"expected":{"latest_version_date":"2026-04-09"},"claim_limit":"limit"}]}',
        encoding="utf-8",
    )
    with pytest.raises(MODULE.SnapshotError):
        MODULE.load_snapshot(path)
