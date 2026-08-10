#!/usr/bin/env python3
"""Verify authoritative AES/SEED single-block vectors with an OpenSSL CLI."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
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
    raise ValueError(f"unsupported algorithm: {algorithm}")


def verify_vector(vector: dict, openssl: str = "openssl") -> dict:
    command = [
        openssl, "enc", f"-{cipher_name(vector['algorithm'])}",
        "-K", vector["key"], "-nopad",
    ]
    if vector["algorithm"].upper() == "SEED":
        command.extend(("-provider", "legacy"))
    result = subprocess.run(
        command,
        input=bytes.fromhex(vector["plaintext"]),
        capture_output=True,
        check=False,
    )
    if result.returncode:
        return {
            "algorithm": vector["algorithm"], "passed": False,
            "error": result.stderr.decode("utf-8", errors="replace").strip(),
        }
    actual = result.stdout.hex()
    return {
        "algorithm": vector["algorithm"],
        "source": vector["source"],
        "expected": vector["ciphertext"],
        "actual": actual,
        "passed": actual.lower() == vector["ciphertext"].lower(),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vectors", type=Path, default=DEFAULT_VECTORS)
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    vectors = json.loads(args.vectors.read_text(encoding="utf-8"))["vectors"]
    results = [verify_vector(vector, args.openssl) for vector in vectors]
    report = {"schema_version": 1, "engine": args.openssl, "results": results}
    encoded = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")
    return 0 if all(result["passed"] for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
