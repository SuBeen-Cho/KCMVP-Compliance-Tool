from types import SimpleNamespace
import json

from experiments.grounded_rag_llm_eval import FIXTURES, CONDITIONS, build_prompt, canonicalize_cited_spans, final_disposition, run


def test_fixture_is_balanced_and_paired():
    assert len(FIXTURES) == 9
    for rule in {x[1] for x in FIXTURES}:
        assert {x[2] for x in FIXTURES if x[1] == rule} == {"violation", "non_violation", "not_applicable"}
    assert len({x[0] for x in FIXTURES}) == len(FIXTURES)


def test_prompt_does_not_disclose_gt():
    prompt = build_prompt(FIXTURES[0], "no_rag", [])
    assert "gt=" not in prompt and '"gt"' not in prompt


def test_fail_closed_disposition():
    assert final_disposition("non_violation", "irrelevant_official", False) == "abstain"
    assert final_disposition("violation", "no_rag", True) == "violation"


def test_cited_id_resolves_to_exact_immutable_span():
    decision={"evidence_unit_ids":["u"],"supporting_spans":["paraphrase"]}
    value, changed=canonicalize_cited_spans(decision,[{"unit_id":"u","text":"exact span"}])
    assert changed and value["supporting_spans"] == ["exact span"]
    _, changed=canonicalize_cited_spans({"evidence_unit_ids":["wrong"]},[{"unit_id":"u","text":"x"}])
    assert not changed


def test_runner_writes_no_prompt_response_or_secret(tmp_path, monkeypatch):
    index={"units":[]}; audit={"rules":{}}
    for _,rid,_,_ in FIXTURES:
        if rid in audit["rules"]: continue
        uid=f"{rid}:u"; text="official requirement"
        import hashlib
        index["units"].append({"unit_id":uid,"source_id":rid,"locator":{"page":1},"text":text,"text_sha256":hashlib.sha256(text.encode()).hexdigest(),"role":"requirement","authority":"official","authority_tier":"official","version":"1","effective_date":"2026-01-01","applicability":{}})
        audit["rules"][rid]={"evidence_unit_ids":[uid],"source_sha256":"a"*64,"source_locator":{"source_id":rid}}
    ip=tmp_path/"i.json"; ap=tmp_path/"a.json"; lp=tmp_path/"l.jsonl"; op=tmp_path/"o.json"
    ip.write_text(json.dumps(index)); ap.write_text(json.dumps(audit))
    monkeypatch.setattr("app.services.rag_grounding._verified_rule_binding", lambda rid:{"source_id":rid,"source_sha256":"a"*64,"unit_ids":frozenset({f"{rid}:u"})})
    class Models:
        def generate_content(self, **kwargs):
            fid=kwargs["contents"].split("fixture_id=")[1].split(";")[0]
            gt=next(x[2] for x in FIXTURES if x[0]==fid)
            return SimpleNamespace(text=json.dumps({"label":gt,"evidence_unit_ids":[],"supporting_spans":[],"evidence_entails_verdict":False,"applicability":False,"exceptions_checked":[],"counterevidence":[],"rationale":"x"}),usage_metadata=SimpleNamespace(prompt_token_count=2,candidates_token_count=1))
    run(SimpleNamespace(models=Models()),ip,ap,lp,op)
    public=op.read_text(); assert "official requirement" not in public and "contents" not in public
    assert "GOOGLE_API_KEY" not in public and str(tmp_path) not in public
    document=json.loads(public)
    assert set(document) == {"schema_version","run_id","created_at","model","prompt_version","run_provenance","pricing_assumption","fixture_set_sha256","conditions","rows","metrics","stratified_metrics"}
    assert document["schema_version"] == "1.1" and len(document["run_id"]) == 64
    assert document["run_provenance"]["temperature"] == 0
    assert document["run_provenance"]["provenance_capture"] == "at_execution"
    assert document["run_provenance"]["seed"] is None
    assert document["run_provenance"]["request_count"] == 27
    assert all(len(document["run_provenance"][key]) == 64 for key in
               ("official_evidence_index_sha256","rule_evidence_audit_sha256","runner_source_sha256"))
    assert len(document["fixture_set_sha256"]) == 64
    assert len(document["rows"]) == len(FIXTURES)*len(CONDITIONS)
    assert all("prompt_sha256" not in row and "response_sha256" not in row for row in document["rows"])
    assert sum(value["estimated_cost_usd"] for value in document["metrics"].values()) > 0
    private=lp.read_text(); assert "prompt_sha256" in private and "response_sha256" in private
    assert "GOOGLE_API_KEY" not in private and str(tmp_path) not in private
