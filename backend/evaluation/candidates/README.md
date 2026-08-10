# Authoritative cipher evaluation assets

`authoritative_vectors.json` contains externally published known-answer
vectors. `ARIA-002` denotes evaluation with all three RFC 5794 Appendix A
vectors (128-, 192-, and 256-bit keys); it is not registered as a static AST
rule. A static source heuristic must not substitute for this execution result.

`verify_cipher_vectors.py` uses OpenSSL's default provider for AES and ARIA and
the legacy provider for SEED. Candidate source trees remain outside the Git
repository according to `sources.lock.json`.

## Locked implementation evaluation

`scripts/evaluate_cipher_implementations.py` verifies each checkout commit,
builds the locked library and its implementation-linked driver itself, and
records build commands, the checkout commit, driver/binary SHA-256 values,
known-answer results, and static AES/SEED/ARIA rule coverage. Arbitrary external
runners are not accepted.
Build directories, generated drivers, libraries, and upstream source trees
must remain outside this repository. The following upstream build mechanisms
were exercised on macOS arm64 on 2026-08-11:

- OpenSSL: `perl Configure darwin64-arm64-cc no-shared no-tests`, then
  `make -j4 build_sw`.
- Botan: `configure.py --minimized-build --enable-modules=aes,aria,seed
  --disable-shared-library --build-targets=static,cli --link-method=copy`, then
  the generated Makefile. `--link-method=copy` avoids cross-volume symlink
  problems when the source checkout and build directory use different mounts.
- Crypto++: `make -j4 static`.
- Mbed TLS: initialize the commit-pinned `framework` submodule, configure with
  CMake using `ENABLE_TESTING=OFF`, `ENABLE_PROGRAMS=OFF`, and
  `BUILD_SHARED_LIBS=OFF`, then build. Mbed TLS does not declare SEED support in
  `sources.lock.json` and therefore receives no SEED vector.

An aggregate static status is `compliant` only if every selected source file
was parsed and handled without a finding. If even one selected file is
undecidable, the aggregate is `unknown`; this prevents optimized, assembly, or
C++ code from being mislabeled as compliant. Neither a vector pass nor a
static `compliant` status is a KCMVP/CMVP validation claim.
