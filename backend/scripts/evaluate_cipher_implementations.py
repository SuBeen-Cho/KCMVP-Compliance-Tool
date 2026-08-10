#!/usr/bin/env python3
"""Build and evaluate exact locked cipher checkouts outside the repository."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import os


BACKEND_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOCK = BACKEND_ROOT / "evaluation" / "candidates" / "sources.lock.json"
DEFAULT_VECTORS = BACKEND_ROOT / "evaluation" / "candidates" / "authoritative_vectors.json"
DEFAULT_CACHE = Path(tempfile.gettempdir()) / "kcmvp-cipher-candidates"
DEFAULT_BUILD = Path(tempfile.gettempdir()) / "kcmvp-cipher-build"
RULE_IDS = {"AES": ("AES-001", "AES-002", "AES-003"), "SEED": ("SEED-001",), "ARIA": ("ARIA-001",)}
SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".h", ".hpp"}


class EvaluationError(RuntimeError):
    pass


def _run(command: list[str], cwd: Path | None = None, *, check: bool = False,
         env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    process_env = os.environ.copy()
    if env:
        process_env.update(env)
    result = subprocess.run(command, cwd=cwd, text=True, capture_output=True, check=False, env=process_env)
    if check and result.returncode:
        raise EvaluationError(f"command failed ({' '.join(command)}): {result.stderr.strip() or result.stdout.strip()}")
    return result


def _git_head(checkout: Path) -> str:
    result = _run(["git", "rev-parse", "HEAD"], checkout)
    if result.returncode:
        raise EvaluationError(f"not a Git checkout: {checkout}")
    return result.stdout.strip()


def _assert_external(path: Path, repository: Path) -> None:
    path, repository = path.resolve(), repository.resolve()
    if path == repository or repository in path.parents:
        raise EvaluationError("candidate checkout and build paths must remain outside the repository")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


DRIVER_COMMON = r'''
#include <cctype>
#include <cstdio>
#include <string>
#include <vector>
static std::vector<unsigned char> hex(const char *s) {
  std::vector<unsigned char> out; std::string x(s);
  if(x.size()%2) return out;
  for(size_t i=0;i<x.size();i+=2) { unsigned v; if(std::sscanf(x.substr(i,2).c_str(),"%2x",&v)!=1) return {}; out.push_back((unsigned char)v); }
  return out;
}
static void print16(const unsigned char *p) { for(int i=0;i<16;i++) std::printf("%02x",p[i]); std::printf("\n"); }
'''

DRIVERS = {
    "openssl-3.5.7": DRIVER_COMMON + r'''
#include <openssl/evp.h>
#include <openssl/provider.h>
int main(int n,char **v) { if(n!=4) return 2; auto k=hex(v[2]), p=hex(v[3]); if(p.size()!=16) return 3;
  OSSL_PROVIDER *d=OSSL_PROVIDER_load(nullptr,"default"), *l=OSSL_PROVIDER_load(nullptr,"legacy");
  std::string name=v[1]; if(name=="SEED") name="SEED-ECB"; else name += "-ECB";
  EVP_CIPHER *c=EVP_CIPHER_fetch(nullptr,name.c_str(),nullptr); EVP_CIPHER_CTX *x=EVP_CIPHER_CTX_new(); unsigned char o[32]; int a=0,b=0;
  int ok=c && x && EVP_EncryptInit_ex2(x,c,k.data(),nullptr,nullptr)==1 && EVP_CIPHER_CTX_set_padding(x,0)==1 && EVP_EncryptUpdate(x,o,&a,p.data(),16)==1 && EVP_EncryptFinal_ex(x,o+a,&b)==1;
  if(ok) print16(o); EVP_CIPHER_CTX_free(x); EVP_CIPHER_free(c); OSSL_PROVIDER_unload(l); OSSL_PROVIDER_unload(d); return ok?0:4; }
''',
    "botan-3.12.0": DRIVER_COMMON + r'''
#include <botan/block_cipher.h>
#include <memory>
int main(int n,char **v) { if(n!=4) return 2; auto k=hex(v[2]), p=hex(v[3]); std::string a=v[1]; if(a=="SEED") a="SEED";
  auto c=Botan::BlockCipher::create(a); if(!c || p.size()!=16) return 3; c->set_key(k.data(),k.size()); c->encrypt(p.data()); print16(p.data()); return 0; }
''',
    "cryptopp-8.9.0": DRIVER_COMMON + r'''
#include "aes.h"
#include "seed.h"
#include "aria.h"
#include <memory>
using CryptoPP::BlockCipher;
int main(int n,char **v) { if(n!=4) return 2; auto k=hex(v[2]), p=hex(v[3]); std::unique_ptr<BlockCipher> c; std::string a=v[1];
  if(a=="AES-128") c.reset(new CryptoPP::AES::Encryption); else if(a=="SEED") c.reset(new CryptoPP::SEED::Encryption); else c.reset(new CryptoPP::ARIA::Encryption);
  c->SetKey(k.data(),k.size()); unsigned char o[16]; c->ProcessBlock(p.data(),o); print16(o); return 0; }
''',
    "mbedtls-3.6.7": DRIVER_COMMON + r'''
#include "mbedtls/aes.h"
#include "mbedtls/aria.h"
int main(int n,char **v) { if(n!=4) return 2; auto k=hex(v[2]), p=hex(v[3]); unsigned char o[16]; std::string a=v[1]; int rc;
  if(a.rfind("AES",0)==0) { mbedtls_aes_context x; mbedtls_aes_init(&x); rc=mbedtls_aes_setkey_enc(&x,k.data(),k.size()*8); if(!rc) rc=mbedtls_aes_crypt_ecb(&x,MBEDTLS_AES_ENCRYPT,p.data(),o); mbedtls_aes_free(&x); }
  else { mbedtls_aria_context x; mbedtls_aria_init(&x); rc=mbedtls_aria_setkey_enc(&x,k.data(),k.size()*8); if(!rc) rc=mbedtls_aria_crypt_ecb(&x,p.data(),o); mbedtls_aria_free(&x); }
  if(rc) return 4; print16(o); return 0; }
''',
}


def build_runner(source: dict, checkout: Path, build_root: Path) -> tuple[Path, dict, dict[str, str]]:
    """Build both the locked library and a checkout-linked vector driver."""
    target = build_root / source["id"]
    target.mkdir(parents=True, exist_ok=True)
    driver = target / "driver.cpp"
    driver.write_text(DRIVERS[source["id"]], encoding="utf-8")
    binary = target / "vector-runner"
    commands: list[tuple[list[str], Path]] = []
    sid = source["id"]
    runner_env: dict[str, str] = {}
    if sid.startswith("openssl"):
        openssl_build = target / "openssl"
        openssl_build.mkdir(exist_ok=True)
        commands = [([str(checkout / "Configure"), "no-shared", "no-tests"], openssl_build),
                    (["make", "-j1", "build_generated"], openssl_build),
                    (["make", "-j2", "build_sw"], openssl_build),
                    (["c++", "-std=c++17", str(driver), "-I", str(openssl_build / "include"), "-I", str(checkout / "include"), str(openssl_build / "libcrypto.a"), "-lpthread", "-o", str(binary)], target)]
        runner_env = {"OPENSSL_MODULES": str(openssl_build / "providers")}
    elif sid.startswith("botan"):
        commands = [([sys.executable, "configure.py", f"--prefix={target / 'install'}", "--disable-shared-library", "--minimized-build", "--enable-modules=aes,seed,aria"], checkout), (["make", "-j2"], checkout),
                    (["c++", "-std=c++20", str(driver), "-I", str(checkout / "build" / "include" / "public"), str(checkout / "libbotan-3.a"), "-lpthread", "-o", str(binary)], target)]
    elif sid.startswith("cryptopp"):
        commands = [(["make", "-j2", "libcryptopp.a"], checkout), (["c++", "-std=c++17", str(driver), "-I", str(checkout), str(checkout / "libcryptopp.a"), "-o", str(binary)], target)]
    elif sid.startswith("mbedtls"):
        cmake_build = target / "cmake"
        commands = [(["git", "submodule", "update", "--init", "--depth=1", "framework"], checkout),
                    (["cmake", "-S", str(checkout), "-B", str(cmake_build), "-DENABLE_TESTING=OFF", "-DENABLE_PROGRAMS=OFF"], target), (["cmake", "--build", str(cmake_build), "-j2"], target),
                    (["c++", "-std=c++17", str(driver), "-I", str(checkout / "include"), str(cmake_build / "library" / "libmbedcrypto.a"), "-o", str(binary)], target)]
    else:
        raise EvaluationError(f"no audited build recipe for {sid}")
    records = []
    for command, cwd in commands:
        _run(command, cwd, check=True)
        records.append({"command": command, "cwd": str(cwd)})
    attestation = {"status": "built_from_locked_checkout", "checkout_commit": _git_head(checkout),
                   "driver_sha256": _sha256(driver), "binary_sha256": _sha256(binary), "commands": records}
    if sid.startswith("mbedtls"):
        expected = _run(["git", "ls-tree", "HEAD", "framework"], checkout, check=True).stdout.split()[2]
        actual = _git_head(checkout / "framework")
        if actual != expected:
            raise EvaluationError(f"{sid}: framework submodule differs from locked gitlink")
        attestation["submodules"] = {"framework": actual}
    return binary, attestation, runner_env


def candidate_files(checkout: Path, algorithm: str) -> list[Path]:
    aliases = {"AES": ("aes", "rijndael", "vpaes", "bsaes", "aesni"), "SEED": ("seed",), "ARIA": ("aria",)}[algorithm]
    tracked = _run(["git", "ls-files", "-z"], checkout) if (checkout / ".git").exists() else None
    paths = ((checkout / name) for name in tracked.stdout.split("\0") if name) if tracked and not tracked.returncode else checkout.rglob("*")
    return sorted(path for path in paths if path.is_file() and path.suffix.lower() in SOURCE_SUFFIXES and any(a in str(path.relative_to(checkout)).lower() for a in aliases))


def static_coverage(source: dict, checkout: Path) -> dict:
    sys.path.insert(0, str(BACKEND_ROOT))
    from app.services.ast_checker_service import check_rule
    algorithms = []
    for algorithm in source["algorithms"]:
        files, rules = candidate_files(checkout, algorithm), []
        for rule_id in RULE_IDS[algorithm]:
            rows = []
            for path in files:
                result = check_rule(rule_id, path.read_text(encoding="utf-8", errors="replace"), path.name)
                rows.append({"path": str(path.relative_to(checkout)), "status": "unknown" if result is None else ("violation" if result else "compliant"), "finding_count": len(result or ())})
            counts = Counter(row["status"] for row in rows)
            aggregate = "violation" if counts["violation"] else ("not_applicable" if not rows else ("unknown" if counts["unknown"] else "compliant"))
            rules.append({"rule_id": rule_id, "aggregate_status": aggregate, "file_status_counts": {k: counts[k] for k in ("compliant", "unknown", "violation")}, "files": rows})
        algorithms.append({"algorithm": algorithm, "candidate_file_count": len(files), "rules": rules})
    return {"status_vocabulary": {"compliant": "all selected files handled without explicit contradiction", "violation": "one or more explicit contradiction findings", "unknown": "one or more selected files could not be decided"}, "algorithms": algorithms}


def executable_vector_report(source: dict, vectors: list[dict], runner: Path, build: dict,
                             runner_env: dict[str, str] | None = None) -> dict:
    selected = [v for v in vectors if v["algorithm"].split("-")[0] in source["algorithms"]]
    results = []
    for vector in selected:
        process = _run([str(runner), vector["algorithm"], vector["key"], vector["plaintext"]], env=runner_env)
        actual = process.stdout.strip().lower() if process.returncode == 0 else None
        passed = actual == vector["ciphertext"].lower()
        results.append({"algorithm": vector["algorithm"], "source": vector["source"], "status": "passed" if passed else "failed", "passed": passed, "expected": vector["ciphertext"], "actual": actual, "error": process.stderr.strip() or None})
    return {"status": "passed" if results and all(x["passed"] for x in results) else "failed", "build": build, "vector_count": len(results), "results": results}


def evaluate(lock_path: Path, vectors_path: Path, cache: Path, build_root: Path) -> dict:
    lock = json.loads(lock_path.read_text(encoding="utf-8")); vectors = json.loads(vectors_path.read_text(encoding="utf-8"))["vectors"]
    repository = BACKEND_ROOT.parent; _assert_external(cache, repository); _assert_external(build_root, repository)
    reports = []
    for source in lock["sources"]:
        checkout = (cache / source["id"]).resolve(); _assert_external(checkout, repository)
        if _git_head(checkout) != source["commit"]: raise EvaluationError(f"{source['id']}: checkout commit differs from lock")
        base = {"id": source["id"], "commit": source["commit"], "license": source["license"], "vendor_sources_committed": False, "checkout_location_policy": "external temporary cache only", "declared_algorithm_support": source["algorithms"], "selection_status": "selected_from_source_lock"}
        try:
            runner, build, runner_env = build_runner(source, checkout, build_root)
            base.update({"evaluation_status": "completed", "vector_evaluation": executable_vector_report(source, vectors, runner, build, runner_env), "static_rule_coverage": static_coverage(source, checkout)})
        except EvaluationError as exc:
            base.update({"evaluation_status": "failed", "error": str(exc), "vector_evaluation": {"status": "not_run", "results": []}, "static_rule_coverage": static_coverage(source, checkout)})
        reports.append(base)
    return {"schema_version": 2, "scope": "built locked upstream checkout evaluation", "limitations": ["Known-answer vectors cover selected single-block examples, not KCMVP certification.", "Static compliant is not proof of full conformance.", "C++ templates, assembly, generated code, wrappers, and indirect constants frequently remain unknown."], "sources": reports}


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK); parser.add_argument("--vectors", type=Path, default=DEFAULT_VECTORS); parser.add_argument("--cache", type=Path, default=DEFAULT_CACHE); parser.add_argument("--build-root", type=Path, default=DEFAULT_BUILD); parser.add_argument("--output", type=Path); args = parser.parse_args()
    report = evaluate(args.lock, args.vectors, args.cache, args.build_root); encoded = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        temporary = args.output.with_name(args.output.name + ".tmp")
        temporary.write_text(encoded, encoding="utf-8")
        temporary.replace(args.output)
    else: print(encoded, end="")
    return 0


if __name__ == "__main__": raise SystemExit(main())
