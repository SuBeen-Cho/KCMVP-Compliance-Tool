# Authoritative cipher evaluation assets

`authoritative_vectors.json` contains externally published known-answer
vectors. `ARIA-002` denotes evaluation with all three RFC 5794 Appendix A
vectors (128-, 192-, and 256-bit keys); it is not registered as a static AST
rule. A static source heuristic must not substitute for this execution result.

`verify_cipher_vectors.py` uses OpenSSL's default provider for AES and ARIA and
the legacy provider for SEED. Candidate source trees remain outside the Git
repository according to `sources.lock.json`.
