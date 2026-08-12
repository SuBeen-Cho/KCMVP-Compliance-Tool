"""Fail-closed shadow chain for one narrow LEA round fixture.

The chain joins, but does not promote, three independently bounded claims:
official normative evidence, an exact round-operation graph, and a unique call
using distinct direct fixed-size arrays.  Algorithm identity, applicability to
the caller, and ground truth remain outside this contract.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from app.services.clang_straightline_reaching_def import VerifiedPreprocessingBinding
from app.services.lea_round_operation_graph import prove_lea_round_operation_graph
from app.services.restrict_callsite_nonoverlap import prove_restrict_callsite_nonoverlap

CHAIN_ID = "lea-round-evidence-operation-callsite-shadow-chain"
CHAIN_VERSION = "1.0.0"


def _digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False, allow_nan=False).encode()
    return hashlib.sha256(encoded).hexdigest()


def evaluate_lea_round_shadow_chain(
    source: str, *, preprocessing_binding: VerifiedPreprocessingBinding | None,
) -> dict[str, Any]:
    """Evaluate the closed chain; deliberately never return an observed fact."""
    graph = prove_lea_round_operation_graph(
        source, preprocessing_binding=preprocessing_binding)
    callsite = prove_restrict_callsite_nonoverlap(
        source, callee="lea_round_graph_fixture", parameter_positions=(0, 1, 2),
        minimum_extents=(4, 4, 6), preprocessing_binding=preprocessing_binding)
    stages = {
        "official_evidence": graph.get("evidence_binding_complete") is True,
        "operation_graph": (graph.get("structural_complete") is True
                            and graph.get("graph_equal") is True),
        "direct_array_callsite": callsite.get("structural_complete") is True,
    }
    binding_sha = (preprocessing_binding.preprocessed_sha256
                   if isinstance(preprocessing_binding, VerifiedPreprocessingBinding) else None)
    identity_join = (
        isinstance(binding_sha, str)
        and graph.get("preprocessing", {}).get("preprocessed_sha256") == binding_sha
        and callsite.get("source_sha256") == binding_sha
    )
    stages["same_preprocessed_occurrence"] = identity_join
    complete = all(stages.values())
    reason = ("caller_algorithm_applicability_and_ground_truth_unproved" if complete
              else "shadow_chain_stage_incomplete")
    return {
        "chain_id": CHAIN_ID, "chain_version": CHAIN_VERSION,
        "state": "unknown", "semantic_authorization": 0,
        "structural_chain_complete": complete, "stages": stages,
        "occurrence_binding_sha256": binding_sha,
        "graph_reason": graph.get("reason"),
        "callsite_reason": callsite.get("reason"),
        "graph_proof_sha256": _digest(graph),
        "callsite_proof_sha256": _digest(callsite),
        "chain_sha256": _digest({"stages": stages, "graph": graph,
                                  "callsite": callsite}),
        "reason": reason,
    }
