from experiments.no_evidence_41_eval import build_prompt


def test_prompt_parity_differs_only_in_evidence_block():
    candidate = {"rule_id": "X-1", "snippet": "int x;", "message": "m"}
    empty = build_prompt(candidate, evidence_block="")
    grounded = build_prompt(candidate, evidence_block='[{"unit_id":"u"}]')
    assert empty.rsplit("official_evidence=", 1)[0] == grounded.rsplit("official_evidence=", 1)[0]
    assert empty.endswith("official_evidence=")


def test_prompt_does_not_serialize_grounding_fields():
    candidate = {"rule_id": "X-1", "snippet": "x", "rag_evidence_bundle": {"secret": "span"},
                 "rag_guideline_text": "official text", "rag_route": {"decision": "retrieve"}}
    prompt = build_prompt(candidate)
    assert "official text" not in prompt and "secret" not in prompt and "retrieve" not in prompt
