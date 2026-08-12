"""API-free LEA-011 extractor integration; never authorizes production output."""
from __future__ import annotations

import hashlib
from typing import Any

from app.services.lea011_program_fact_extractor import (
    EXTRACTOR_ID, EXTRACTOR_VERSION, RULE_ID, extract_lea011_program_fact,
    extractor_sha256,
)
from app.services.program_fact_contract import verify_program_fact


def evaluate_candidate(candidate_id: str, candidate: dict[str, Any],
                       runtime_secret: bytes) -> dict[str, Any]:
    if candidate.get("rule_id") != "LEA-011":
        return {"candidate_id": candidate_id, "state": "unknown",
                "reason": "rule_not_supported", "production_authorized": False}
    # A detector snippet is never upgraded to a complete source unit.  Only an
    # explicitly supplied complete_source field may enter this shadow extractor.
    source = candidate.get("complete_source")
    complete = isinstance(source, str) and bool(source)
    source_text = source if complete else str(candidate.get("snippet") or "")
    envelope = extract_lea011_program_fact(
        source_text, candidate_id=candidate_id, claim_id="LEA-011:C1",
        applicability={"algorithm": str(candidate.get("algorithm") or ""),
                       "operation": str(candidate.get("operation") or "")},
        source_complete=complete, runtime_secret=runtime_secret,
    )
    # Derive the expected binding independently. Trusting provenance copied
    # from the envelope would make provenance verification circular.
    expected = {
        "extractor_id": EXTRACTOR_ID,
        "extractor_version": EXTRACTOR_VERSION,
        "extractor_sha256": extractor_sha256(),
        "source_sha256": hashlib.sha256(source_text.encode("utf-8")).hexdigest(),
        "candidate_id": candidate_id,
        "rule_id": RULE_ID,
        "claim_id": "LEA-011:C1",
    }
    result = verify_program_fact(envelope, runtime_secret, expected)
    missing = envelope.get("missing_context")
    extraction_reason = (
        str(missing[0]) if result["verified"] and isinstance(missing, list) and missing
        else str(result["reason"])
    )
    return {"candidate_id": candidate_id, "state": result["state"],
            "reason": result["reason"], "extraction_reason": extraction_reason,
            "fact_content_sha256": envelope["content_sha256"],
            "production_authorized": False}
