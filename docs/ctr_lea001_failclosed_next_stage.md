# CTR-LEA-001 fail-closed next-stage record

The frozen 265-occurrence cohort contains six `CTR-LEA-001` detections. The
hold-priority report identifies three proxy violations in three clone groups.
This is an aggregate replay result, not candidate-level ground truth.

The official LEA specification exactly supports a 16-byte LEA block. The
located CTR validation units support incrementing-counter behavior and distinct
initial values. Neither source span directly requires that every operative CTR
initial counter be represented by a 16-byte C array. A declaration match also
does not establish symbol role or runtime dataflow. The legacy rule-to-source
mapping therefore remains untrusted and no atomic claim is registered.

The proposed Clang array-extent/symbol-role extractor was deliberately not
implemented because its prerequisite evidence gate failed. Even a future
shadow extractor must require authenticated preprocessing and build-manifest
bindings, a complete translation unit, exact symbol identity, and operative
counter dataflow. Missing inputs mean `unknown` / abstain. Candidate-supplied
booleans or manifest-shaped dictionaries are not authentication. Production
authorization remains zero.

The aggregate evaluator performs no external API calls, persists no candidate
identifier or source text, and uses `workspace_guard` for its output path.
