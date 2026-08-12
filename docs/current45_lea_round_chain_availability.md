# Current45 LEA round chain availability

This API-free audit is limited to the four newly routed occurrences: one each
of `LEA-027` through `LEA-030`. It rechecks the frozen snapshot hash, clean
router freeze, exact 45-member universe hash, and exact four-rule membership
before producing aggregate output.

The frozen snapshot resolves complete source for all four occurrences. It does
not contain the private replay capture and runtime secret required by
`verify_and_bind_preprocessing`. Therefore a payload field named
`trusted_preprocessing_manifest`, or even a candidate-supplied self-hashed
receipt, is not trusted. Operation-graph input availability, callsite
non-overlap proof, and the complete chain consequently remain 0/4.

This is a fail-closed availability result, not a detector failure: the sealed
synthetic chain separately passes its positive fixture and mutation attacks.
Semantic authorization stays zero and the program-fact state stays `unknown`.

The command-line writer applies `experiments.workspace_guard.guarded_output_path`.
It refuses output outside the active Git repository, including sibling Dropbox
folders. Reproduction requires the private frozen snapshot as input and writes
only an aggregate public JSON artifact inside this repository.
