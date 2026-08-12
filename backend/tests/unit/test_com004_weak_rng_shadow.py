import app.services.clang_straightline_reaching_def as rd
from app.services.com004_weak_rng_shadow import observe_direct_store


def binding(source):
    return rd.VerifiedPreprocessingBinding(
        original_source_sha256="a" * 64, preprocessed_sha256=rd._sha(source.encode()),
        input_manifest_sha256="b" * 64, compiler_binary_sha256="c" * 64,
        _attestor=rd._BINDING_ATTESTOR)


def observe(source, sinks=frozenset({"iv"})):
    return observe_direct_store(source, preprocessing_binding=binding(source),
                                audited_sink_names=sinks)


def test_direct_shape_is_observed_but_never_semantically_authorized():
    result = observe("void f(unsigned char *iv){ iv[0] = (unsigned char)rand(); }")
    assert result["structural_observation"] is True
    assert result["state"] == "unknown"
    assert result["production_authorized"] is result["semantic_authorized"] is False


def test_binding_and_audited_sink_registry_are_mandatory():
    source = "void f(unsigned char *iv){ iv[0] = rand(); }"
    assert observe_direct_store(source, preprocessing_binding=None,
        audited_sink_names=frozenset({"iv"}))["reason"] == "authenticated_preprocessing_unavailable"
    assert observe(source, frozenset())["reason"] == "audited_sensitive_sink_registry_unavailable"
    assert observe(source, frozenset({"log"}))["reason"] == "sensitive_sink_identity_unproved"


def test_dead_branch_macro_alias_and_indirect_flow_fail_closed():
    attacks = [
        "void f(unsigned char *iv){ if(0) iv[0]=rand(); }",
        "#define R rand\nvoid f(unsigned char *iv){iv[0]=R();}",
        "void f(unsigned char *iv){unsigned char *p=iv; p[0]=rand();}",
        "void f(unsigned char *iv){int x=rand(); iv[0]=x;}",
        "void f(unsigned char *iv){memcpy(iv, &((int){rand()}), 1);}",
    ]
    assert all("structural_observation" not in observe(source) for source in attacks)


def test_noncrypto_unused_seed_and_multiple_calls_do_not_cross_gate():
    sources = [
        "void f(void){ srand(1); }",
        "int f(void){ return rand(); }",
        "void f(unsigned char *iv){iv[0]=rand(); iv[1]=rand();}",
    ]
    assert all("structural_observation" not in observe(source) for source in sources)
