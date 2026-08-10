#!/usr/bin/env python3
"""Validate policy metadata and optionally detect changes on official web pages."""

from __future__ import annotations

import argparse
import calendar
from datetime import date
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import sys
import urllib.error
import urllib.request
from urllib.parse import urlparse


BACKEND_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SNAPSHOT = BACKEND_ROOT / "evaluation" / "policy_sources.snapshot.json"
ALLOWED_HOSTS = {"seed.kisa.or.kr", "csrc.nist.gov"}
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
SOURCE_SCHEMAS = {
    "kisa-kcmvp-aes-status": {
        "authority": "KISA",
        "host": "seed.kisa.or.kr",
        "expected": {"algorithm", "validation_system", "test_vectors"},
    },
    "nist-fips-140-3-ig-version": {
        "authority": "NIST",
        "host": "csrc.nist.gov",
        "expected": {"latest_version_date", "displayed_version"},
    },
}


class SnapshotError(RuntimeError):
    """The tracked policy snapshot is malformed or unsafe."""


class NetworkCheckError(RuntimeError):
    """A bounded, stable network-check failure suitable for JSON reporting."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise NetworkCheckError("redirect_rejected")


class _TableRows(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.rows: list[list[str]] = []
        self._row: list[str] | None = None
        self._cell: list[str] | None = None

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag.lower() == "tr":
            self._row = []
        elif tag.lower() in {"td", "th"} and self._row is not None:
            self._cell = []

    def handle_data(self, data: str) -> None:
        if self._cell is not None:
            self._cell.append(data)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in {"td", "th"} and self._row is not None and self._cell is not None:
            self._row.append(" ".join("".join(self._cell).split()))
            self._cell = None
        elif tag == "tr" and self._row is not None:
            self.rows.append(self._row)
            self._row = None
            self._cell = None


class _VisibleText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        self.parts.append(data)

    def text(self) -> str:
        return " ".join(" ".join(self.parts).split())


def load_snapshot(path: Path = DEFAULT_SNAPSHOT) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema_version") != 1 or not data.get("sources"):
        raise SnapshotError("unsupported or empty policy snapshot")
    try:
        snapshot_date = date.fromisoformat(data["as_of"])
    except (KeyError, TypeError, ValueError):
        raise SnapshotError("snapshot as_of must be an ISO date") from None
    ids: set[str] = set()
    for source in data["sources"]:
        required = {"id", "authority", "url", "checked_on", "expected", "claim_limit"}
        missing = sorted(required - source.keys())
        if missing:
            raise SnapshotError(f"{source.get('id', '<unknown>')}: missing {missing}")
        if source["id"] in ids:
            raise SnapshotError(f"duplicate source id: {source['id']}")
        ids.add(source["id"])
        schema = SOURCE_SCHEMAS.get(source["id"])
        if not isinstance(source["url"], str):
            raise SnapshotError(f"{source['id']}: URL must be a string")
        parsed = urlparse(source["url"])
        try:
            port = parsed.port
        except ValueError:
            raise SnapshotError(f"{source['id']}: URL is not an allowed official source") from None
        if (
            parsed.scheme != "https"
            or parsed.hostname not in ALLOWED_HOSTS
            or (schema is not None and parsed.hostname != schema["host"])
            or port not in (None, 443)
            or parsed.username is not None
            or parsed.password is not None
            or bool(parsed.query)
        ):
            raise SnapshotError(f"{source['id']}: URL is not an allowed official source")
        if schema is None:
            raise SnapshotError(f"{source['id']}: unsupported policy source")
        if source["authority"] != schema["authority"]:
            raise SnapshotError(f"{source['id']}: authority does not match official host")
        try:
            checked_on = date.fromisoformat(source["checked_on"])
        except (TypeError, ValueError):
            raise SnapshotError(f"{source['id']}: checked_on must be an ISO date") from None
        if checked_on > snapshot_date:
            raise SnapshotError(f"{source['id']}: checked_on is later than snapshot as_of")
        if not isinstance(source["expected"], dict) or not source["expected"]:
            raise SnapshotError(f"{source['id']}: expected values are required")
        if set(source["expected"]) != schema["expected"] or not all(
            isinstance(value, str) and value.strip() for value in source["expected"].values()
        ):
            raise SnapshotError(f"{source['id']}: expected values do not match source schema")
        if not isinstance(source["claim_limit"], str) or not source["claim_limit"].strip():
            raise SnapshotError(f"{source['id']}: expected values and claim limit are required")
    return data


def fetch_text(
    url: str,
    timeout: float = 20.0,
    max_bytes: int = MAX_RESPONSE_BYTES,
) -> str:
    if timeout <= 0 or max_bytes <= 0:
        raise NetworkCheckError("invalid_network_limit")
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "KCMVP-policy-freshness-check/1.0"},
    )
    opener = urllib.request.build_opener(_RejectRedirects())
    try:
        with opener.open(request, timeout=timeout) as response:
            charset = response.headers.get_content_charset() or "utf-8"
            payload = response.read(max_bytes + 1)
    except NetworkCheckError:
        raise
    except urllib.error.HTTPError as exc:
        raise NetworkCheckError(f"http_{exc.code}") from None
    except (TimeoutError, urllib.error.URLError):
        raise NetworkCheckError("network_unavailable") from None
    if len(payload) > max_bytes:
        raise NetworkCheckError("response_too_large")
    return payload.decode(charset, errors="replace")


def inspect_source(source: dict, page: str) -> dict:
    expected = source["expected"]
    if source["id"] == "kisa-kcmvp-aes-status":
        parser = _TableRows()
        parser.feed(page)
        aes_row = next(
            (row for row in parser.rows if any(cell.strip().upper() == "AES" for cell in row)),
            None,
        )
        has_aes = aes_row is not None
        tbd_count = sum(cell.strip().upper() == "TBD" for cell in (aes_row or []))
        matches = has_aes and tbd_count >= 2
        return {
            "id": source["id"],
            "status": "unchanged" if matches else "changed",
            "observed": {"aes_present": has_aes, "nearby_tbd_count": tbd_count},
            "expected": expected,
        }
    if source["id"] == "nist-fips-140-3-ig-version":
        month_numbers = {name.lower(): number for number, name in enumerate(calendar.month_name) if name}
        parser = _VisibleText()
        parser.feed(page)
        visible = parser.text()
        latest_labels = re.findall(
            r"FIPS\s+140-3\s+IG\s*\(("
            + "|".join(calendar.month_name[1:])
            + r")\s+(\d{1,2}),\s+(\d{4})\)\s*-\s*Latest\s+version",
            visible,
            re.IGNORECASE,
        )
        observed_dates = []
        for month, day, year in latest_labels:
            try:
                observed_dates.append(date(int(year), month_numbers[month.lower()], int(day)))
            except ValueError:
                continue
        latest = max(observed_dates).isoformat() if observed_dates else None
        matches = latest == expected["latest_version_date"]
        return {
            "id": source["id"],
            "status": "unchanged" if matches else "changed",
            "observed": {"latest_version_date": latest},
            "expected": expected,
        }
    raise SnapshotError(f"{source['id']}: no network inspector is defined")


def check_network(snapshot: dict, timeout: float = 20.0) -> list[dict]:
    results = []
    for source in snapshot["sources"]:
        try:
            results.append(inspect_source(source, fetch_text(source["url"], timeout)))
        except Exception as exc:  # Network checks are diagnostic and explicitly requested.
            code = exc.code if isinstance(exc, NetworkCheckError) else "unexpected_error"
            results.append({
                "id": source["id"],
                "status": "unavailable",
                "error_code": code,
            })
    return results


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--snapshot", type=Path, default=DEFAULT_SNAPSHOT)
    parser.add_argument("--network", action="store_true", help="contact official pages")
    parser.add_argument(
        "--strict-network",
        action="store_true",
        help="return a failure when any official page is unavailable",
    )
    parser.add_argument("--timeout", type=float, default=20.0)
    args = parser.parse_args()

    snapshot = load_snapshot(args.snapshot)
    report = {
        "schema_version": 1,
        # Keep reports portable and avoid publishing workstation paths.
        "snapshot": args.snapshot.name,
        "as_of": snapshot["as_of"],
        "mode": "network" if args.network else "offline",
        "results": check_network(snapshot, args.timeout) if args.network else [],
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if not args.network:
        return 0
    # A changed page is actionable; temporary network failure is reported but
    # does not masquerade as a policy change or break ordinary CI.
    if any(item["status"] == "changed" for item in report["results"]):
        return 2
    if args.strict_network and any(item["status"] == "unavailable" for item in report["results"]):
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
