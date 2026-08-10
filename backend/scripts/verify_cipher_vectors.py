#!/usr/bin/env python3
"""Verify authoritative AES, SEED, and ARIA block vectors with OpenSSL.

SEED is exposed by OpenSSL 3.x's legacy provider, whereas ARIA and AES are
available from the default provider.  The vectors themselves are copied from
NIST FIPS 197, RFC 4269 Appendix B, and RFC 5794 Appendix A.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess


DEFAULT_VECTORS = (
    Path(__file__).resolve().parents[1]
    / "evaluation" / "candidates" / "authoritative_vectors.json"
)


def cipher_name(algorithm: str) -> str:
    normalized = algorithm.upper()
    if normalized == "AES-128":
        return "aes-128-ecb"
    if normalized == "SEED":
        return "seed-ecb"
    if normalized in {"ARIA-128", "ARIA-192", "ARIA-256"}:
        return normalized.lower() + "-ecb"
    raise ValueError(f"unsupported algorithm: {algorithm}")


def openssl_metadata(openssl: str = "openssl") -> dict:
    """Record the executable version and provider inventory when available."""
    version = subprocess.run(
        [openssl, "version", "-a"], capture_output=True, text=True, check=False
    )
    providers = subprocess.run(
        [openssl, "list", "-providers"], capture_output=True, text=True, check=False
    )
    # `openssl list -providers` prints the provider identifier at two-space
    # indentation and its human-readable name below it. Preserve the identifier
    # (for example, `default`) because that is what provider CLI flags accept.
    provider_names = re.findall(r"^ {2}([A-Za-z0-9_-]+)\s*$", providers.stdout, re.MULTILINE)
    return {
        "version": version.stdout.splitlines()[0] if version.returncode == 0 and version.stdout else None,
        "version_details": version.stdout.strip() if version.returncode == 0 else None,
        "providers": provider_names,
        "provider_details": providers.stdout.strip() if providers.returncode == 0 else None,
        "provider_query_error": (
            providers.stderr.strip() or None if providers.returncode else None
        ),
    }


def verify_vector(vector: dict, openssl: str = "openssl") -> dict:
    command = [
        openssl, "enc", f"-{cipher_name(vector['algorithm'])}",
        "-K", vector["key"], "-nopad",
    ]
    # OpenSSL 3 keeps SEED in the legacy provider. ARIA and AES use default.
    if vector["algorithm"].upper() == "SEED":
        command.extend(("-provider", "legacy"))
    result = subprocess.run(
        command,
        input=bytes.fromhex(vector["plaintext"]),
        capture_output=True,
        check=False,
    )
    if result.returncode:
        error = result.stderr.decode("utf-8", errors="replace").strip()
        unavailable_markers = (
            "unknown cipher", "unsupported", "unable to load provider",
            "unrecognized flag", "unknown option",
        )
        return {
            "algorithm": vector["algorithm"], "passed": False,
            "status": (
                "unavailable" if any(marker in error.lower() for marker in unavailable_markers)
                else "error"
            ),
            "error": error,
        }
    actual = result.stdout.hex()
    return {
        "algorithm": vector["algorithm"],
        "source": vector["source"],
        "expected": vector["ciphertext"],
        "actual": actual,
        "passed": actual.lower() == vector["ciphertext"].lower(),
        "status": "passed" if actual.lower() == vector["ciphertext"].lower() else "mismatch",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vectors", type=Path, default=DEFAULT_VECTORS)
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    vectors = json.loads(args.vectors.read_text(encoding="utf-8"))["vectors"]
    results = [verify_vector(vector, args.openssl) for vector in vectors]
    report = {
        "schema_version": 1,
        "engine": args.openssl,
        "engine_metadata": openssl_metadata(args.openssl),
        "results": results,
    }
    encoded = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")
    return 0 if all(result["passed"] for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
